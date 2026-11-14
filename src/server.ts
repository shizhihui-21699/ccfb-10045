// Internal SSH CA service: REST API + admin UI.
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { loadOrCreateCAKeys, parsePublicKey, CAKey } from './keys';
import { buildCertificate, ALLOWED_EXTENSIONS, CERT_TYPE_USER, CERT_TYPE_HOST } from './cert';
import { buildKRL } from './krl';
import { Store, loadOrCreateConfig, TokenEntry, CertRequest, IssuedCertRecord } from './store';
import { renderUI } from './ui';

interface Args {
  dataDir: string;
  port: number;
  host: string;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { dataDir: path.join(process.cwd(), 'data'), port: 8443, host: '127.0.0.1' };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--data') args.dataDir = argv[++i];
    else if (argv[i] === '--port') args.port = Number(argv[++i]);
    else if (argv[i] === '--host') args.host = argv[++i];
  }
  return args;
}

const args = parseArgs(process.argv);
const config = loadOrCreateConfig(args.dataDir);
const caKeys = loadOrCreateCAKeys(path.join(args.dataDir, 'ca'));
const store = new Store(args.dataDir);

// ---------------------------------------------------------------- helpers

type Role = 'admin' | 'requester';
interface Auth {
  name: string;
  role: Role;
}

function authenticate(req: http.IncomingMessage): Auth | null {
  const header = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return null;
  const entry: TokenEntry | undefined = config.tokens[m[1].trim()];
  return entry ? { name: entry.name, role: entry.role } : null;
}

function send(res: http.ServerResponse, code: number, body: unknown, contentType = 'application/json'): void {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body, null, 2);
  res.writeHead(code, { 'content-type': contentType });
  res.end(data);
}

function sendError(res: http.ServerResponse, code: number, message: string): void {
  send(res, code, { error: message });
}

async function readBody(req: http.IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, 'request body is not valid JSON');
  }
}

class HttpError extends Error {
  constructor(public code: number, message: string) {
    super(message);
  }
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function requireAdmin(auth: Auth): void {
  if (auth.role !== 'admin') throw new HttpError(403, 'admin role required');
}

function publicRequestView(r: CertRequest): Record<string, unknown> {
  return { ...r };
}

function publicCertView(c: IssuedCertRecord): Record<string, unknown> {
  const { openssh, ...rest } = c;
  return { ...rest, cert: openssh };
}

// ---------------------------------------------------------------- routes

type Handler = (ctx: {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  auth: Auth;
  params: Record<string, string>;
  query: URLSearchParams;
}) => Promise<void> | void;

const routes: Array<{ method: string; pattern: RegExp; keys: string[]; handler: Handler }> = [];

function route(method: string, pattern: string, handler: Handler): void {
  const keys: string[] = [];
  const regex = new RegExp(
    '^' + pattern.replace(/:[^/]+/g, (m) => {
      keys.push(m.slice(1));
      return '([^/]+)';
    }) + '$'
  );
  routes.push({ method, pattern: regex, keys, handler });
}

route('GET', '/api/health', ({ res }) => send(res, 200, { ok: true }));

route('GET', '/api/ca', ({ res }) => {
  send(res, 200, {
    cas: [...caKeys.values()].map((ca: CAKey) => ({
      id: ca.id,
      algo: ca.algo,
      publicKey: ca.publicLine,
      fingerprint: ca.fingerprint,
    })),
    hints: {
      sshd_config: [
        'TrustedUserCAKeys /etc/ssh/ca_user.pub',
        'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub',
        'RevokedHostKeys /etc/ssh/revoked.krl  # or: RevokedKeys for user certs',
      ],
    },
  });
});

route('POST', '/api/requests', async ({ req, res, auth }) => {
  const body = await readBody(req);
  const kind = body.type;
  if (kind !== 'user' && kind !== 'host') throw new HttpError(400, 'type must be "user" or "host"');

  const parsed = parsePublicKey(String(body.publicKey || '')); // throws on bad key

  const principals: string[] = Array.isArray(body.principals) ? body.principals.map(String) : [];
  if (principals.length === 0) throw new HttpError(400, 'at least one principal is required');
  if (principals.some((p) => !/^[\w.@+-]+$/.test(p))) {
    throw new HttpError(400, 'principals may only contain [a-zA-Z0-9_.@+-]');
  }

  const caId = body.ca === 'nistp256' || body.ca === 'ecdsa' ? 'nistp256' : 'ed25519';
  if (!caKeys.has(caId)) throw new HttpError(400, `unknown CA "${body.ca}"`);

  const now = nowSec();
  const defaultTTL = kind === 'user' ? config.defaultUserCertTTLSec : config.defaultHostCertTTLSec;
  const maxTTL = kind === 'user' ? config.maxUserCertTTLSec : config.maxHostCertTTLSec;
  const validAfter = body.validAfter !== undefined ? Number(body.validAfter) : now - 300;
  const validBefore = body.validBefore !== undefined ? Number(body.validBefore) : now + defaultTTL;
  if (!Number.isFinite(validAfter) || !Number.isFinite(validBefore) || validBefore <= validAfter) {
    throw new HttpError(400, 'invalid validity window');
  }
  if (validBefore - validAfter > maxTTL + 300) {
    throw new HttpError(400, `validity window exceeds max TTL for ${kind} certs (${maxTTL}s)`);
  }

  const criticalOptions = {
    forceCommand: body.criticalOptions?.forceCommand ? String(body.criticalOptions.forceCommand) : undefined,
    sourceAddress: Array.isArray(body.criticalOptions?.sourceAddress)
      ? body.criticalOptions.sourceAddress.map(String)
      : undefined,
  };
  if (kind === 'host' && (criticalOptions.forceCommand || criticalOptions.sourceAddress)) {
    throw new HttpError(400, 'critical options are only meaningful for user certs');
  }

  const extensions: string[] = Array.isArray(body.extensions) ? body.extensions.map(String) : [];
  for (const ext of extensions) {
    if (!ALLOWED_EXTENSIONS.has(ext)) throw new HttpError(400, `extension "${ext}" is not allowed`);
  }

  const record: CertRequest = {
    id: crypto.randomUUID(),
    status: 'pending',
    kind,
    ca: caId,
    keyId: body.keyId ? String(body.keyId) : '',
    principals,
    publicKey: `${parsed.algo} ${parsed.blob.toString('base64')}`,
    fingerprint: parsed.fingerprint,
    validAfter,
    validBefore,
    criticalOptions,
    extensions,
    comment: body.comment ? String(body.comment) : '',
    requestedBy: auth.name,
    requestedAt: now,
  };
  store.addRequest(record);
  store.audit(auth.name, 'request.create', {
    requestId: record.id,
    kind,
    principals,
    fingerprint: record.fingerprint,
    validAfter,
    validBefore,
    criticalOptions,
    extensions,
  });
  send(res, 201, publicRequestView(record));
});

route('GET', '/api/requests', ({ res, query }) => {
  const status = query.get('status') || undefined;
  const list = store.listRequests(status as any).map(publicRequestView);
  send(res, 200, { requests: list });
});

route('POST', '/api/requests/:id/approve', ({ res, auth, params }) => {
  requireAdmin(auth);
  const r = store.getRequest(params.id);
  if (!r) throw new HttpError(404, 'request not found');
  if (r.status !== 'pending') throw new HttpError(409, `request already ${r.status}`);

  const ca = caKeys.get(r.ca)!;
  const parsed = parsePublicKey(r.publicKey);
  const serial = store.allocSerial();
  const keyId = r.keyId || `${r.kind}:${r.requestedBy}:${serial}`;
  const cert = buildCertificate({
    ca,
    subjectKey: parsed,
    serial,
    type: r.kind === 'user' ? CERT_TYPE_USER : CERT_TYPE_HOST,
    keyId,
    principals: r.principals,
    validAfter: BigInt(r.validAfter),
    validBefore: BigInt(r.validBefore),
    criticalOptions: r.criticalOptions,
    extensions: r.extensions,
  });

  r.status = 'approved';
  r.decidedBy = auth.name;
  r.decidedAt = nowSec();
  r.serial = cert.serial;
  r.keyId = keyId;
  store.updateRequest(r);

  const record: IssuedCertRecord = {
    serial: cert.serial,
    requestId: r.id,
    kind: r.kind,
    ca: r.ca,
    keyId,
    principals: r.principals,
    fingerprint: r.fingerprint,
    openssh: cert.openssh,
    validAfter: r.validAfter,
    validBefore: r.validBefore,
    issuedBy: auth.name,
    issuedAt: nowSec(),
    revoked: false,
  };
  store.addCert(record);
  store.audit(auth.name, 'request.approve', {
    requestId: r.id,
    serial: cert.serial,
    kind: r.kind,
    keyId,
    principals: r.principals,
    fingerprint: r.fingerprint,
    ca: r.ca,
    validAfter: r.validAfter,
    validBefore: r.validBefore,
  });
  send(res, 200, { ...publicCertView(record) });
});

route('POST', '/api/requests/:id/reject', async ({ req, res, auth, params }) => {
  requireAdmin(auth);
  const r = store.getRequest(params.id);
  if (!r) throw new HttpError(404, 'request not found');
  if (r.status !== 'pending') throw new HttpError(409, `request already ${r.status}`);
  const body = await readBody(req);
  r.status = 'rejected';
  r.decidedBy = auth.name;
  r.decidedAt = nowSec();
  r.rejectReason = body.reason ? String(body.reason) : '';
  store.updateRequest(r);
  store.audit(auth.name, 'request.reject', { requestId: r.id, reason: r.rejectReason });
  send(res, 200, publicRequestView(r));
});

route('GET', '/api/certs', ({ res }) => {
  send(res, 200, { certs: store.listCerts().map(publicCertView) });
});

route('GET', '/api/certs/:serial/cert.pub', ({ res, params, auth }) => {
  const c = store.getCert(params.serial);
  if (!c) throw new HttpError(404, 'cert not found');
  store.audit(auth.name, 'cert.download', { serial: c.serial, keyId: c.keyId, kind: c.kind });
  send(res, 200, c.openssh + '\n', 'text/plain; charset=utf-8');
});

route('POST', '/api/certs/:serial/revoke', async ({ req, res, auth, params }) => {
  requireAdmin(auth);
  const c = store.getCert(params.serial);
  if (!c) throw new HttpError(404, 'cert not found');
  if (c.revoked) throw new HttpError(409, 'cert already revoked');
  const body = await readBody(req);
  c.revoked = true;
  c.revokedBy = auth.name;
  c.revokedAt = nowSec();
  c.revokeReason = body.reason ? String(body.reason) : '';
  store.updateCert(c);
  store.bumpKrlVersion();
  store.audit(auth.name, 'cert.revoke', {
    serial: c.serial,
    keyId: c.keyId,
    kind: c.kind,
    principals: c.principals,
    reason: c.revokeReason,
  });
  send(res, 200, publicCertView(c));
});

route('GET', '/api/krl', ({ res, auth }) => {
  const serials = store.revokedSerials();
  const ca = caKeys.get('ed25519')!; // KRL is signed by the primary CA
  const krl = buildKRL({
    ca,
    serials,
    krlVersion: BigInt(store.krlVersion),
    generatedDate: BigInt(nowSec()),
  });
  store.audit(auth.name, 'krl.download', { revokedCount: serials.length, krlVersion: store.krlVersion });
  send(res, 200, krl, 'application/octet-stream');
});

route('GET', '/api/audit', ({ res, auth, query }) => {
  requireAdmin(auth);
  const limit = Math.min(Number(query.get('limit') || 500), 5000);
  send(res, 200, { audit: store.listAudit(limit) });
});

route('GET', '/', ({ res }) => {
  send(res, 200, renderUI(), 'text/html; charset=utf-8');
});

// ---------------------------------------------------------------- server

const PUBLIC_PATHS = new Set(['/', '/api/health']);

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    const pathname = url.pathname;

    let auth: Auth = { name: 'anonymous', role: 'requester' };
    if (!PUBLIC_PATHS.has(pathname)) {
      const a = authenticate(req);
      if (!a) return sendError(res, 401, 'missing or invalid bearer token');
      auth = a;
    }

    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = r.pattern.exec(pathname);
      if (!m) continue;
      const params: Record<string, string> = {};
      r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      return await r.handler({ req, res, auth, params, query: url.searchParams });
    }
    sendError(res, 404, 'not found');
  } catch (err) {
    if (err instanceof HttpError) return sendError(res, err.code, err.message);
    sendError(res, 400, err instanceof Error ? err.message : String(err));
  }
});

server.listen(args.port, args.host, () => {
  const tokenSummary = Object.entries(config.tokens)
    .map(([t, v]) => `  ${v.role.padEnd(10)} ${v.name.padEnd(12)} token=${t}`)
    .join('\n');
  console.log(`ssh-ca listening on http://${args.host}:${args.port}`);
  console.log(`data dir: ${args.dataDir}`);
  console.log(`CA fingerprints:`);
  for (const ca of caKeys.values()) console.log(`  ${ca.id.padEnd(10)} ${ca.fingerprint}`);
  console.log(`tokens:\n${tokenSummary}`);
});
