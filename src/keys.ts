// Public-key parsing, CA key management, and SSH-format signing.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Reader, Writer } from './wire';

export type KeyType = 'ed25519' | 'ecdsa' | 'rsa';

export interface ParsedPublicKey {
  algo: string; // ssh-ed25519 | ecdsa-sha2-nistp256/384/521 | ssh-rsa
  comment: string;
  blob: Buffer; // full SSH public key blob
  fields: Buffer; // key fields only (everything after the algo string), for cert embedding
  fingerprint: string; // SHA256 base64
}

const SUPPORTED_ALGOS = new Set([
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'ssh-rsa',
]);

export function fingerprintOf(blob: Buffer): string {
  const digest = crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  return `SHA256:${digest}`;
}

/** Parse one authorized_keys-format public key line. */
export function parsePublicKey(line: string): ParsedPublicKey {
  const trimmed = line.trim();
  if (!trimmed) throw new Error('empty public key');
  const parts = trimmed.split(/\s+/);
  if (parts.length < 2) throw new Error('not an authorized_keys line (need "<algo> <base64> [comment]")');
  const [algo, b64] = parts;
  const comment = parts.slice(2).join(' ');
  if (!SUPPORTED_ALGOS.has(algo)) {
    throw new Error(`unsupported key type "${algo}" (supported: ${[...SUPPORTED_ALGOS].join(', ')})`);
  }
  const blob = Buffer.from(b64, 'base64');
  const r = new Reader(blob);
  const blobAlgo = r.string().toString('utf8');
  if (blobAlgo !== algo) throw new Error(`key blob algorithm "${blobAlgo}" does not match "${algo}"`);

  // Validate structure and capture the raw field bytes (offset after algo string).
  const fieldsStart = 4 + blobAlgo.length;
  if (algo === 'ssh-ed25519') {
    const pk = r.string();
    if (pk.length !== 32) throw new Error('bad ed25519 public key length');
  } else if (algo.startsWith('ecdsa-sha2-')) {
    const curve = r.string().toString('utf8');
    if (`ecdsa-sha2-${curve}` !== algo) throw new Error('ecdsa curve name mismatch');
    const q = r.string();
    if (q.length === 0 || q[0] !== 0x04) throw new Error('ecdsa public key is not an uncompressed point');
  } else if (algo === 'ssh-rsa') {
    r.string(); // e
    r.string(); // n
  }
  if (!r.done) throw new Error('trailing garbage in public key blob');

  return {
    algo,
    comment,
    blob,
    fields: blob.subarray(fieldsStart),
    fingerprint: fingerprintOf(blob),
  };
}

// ---------------------------------------------------------------- CA keys

export interface CAKey {
  id: string; // 'ed25519' | 'ecdsa'
  algo: string; // SSH algorithm name used in signatures
  privateKey: crypto.KeyObject;
  publicBlob: Buffer;
  publicLine: string;
  fingerprint: string;
}

interface EcSpec {
  nodeCurve: string;
  sshCurve: string;
  hash: string;
  pointLen: number;
}

const EC_SPECS: Record<string, EcSpec> = {
  nistp256: { nodeCurve: 'prime256v1', sshCurve: 'nistp256', hash: 'sha256', pointLen: 65 },
  nistp384: { nodeCurve: 'secp384r1', sshCurve: 'nistp384', hash: 'sha384', pointLen: 97 },
  nistp521: { nodeCurve: 'secp521r1', sshCurve: 'nistp521', hash: 'sha512', pointLen: 133 },
};

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function ed25519RawFromSpki(der: Buffer): Buffer {
  if (!der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error('unexpected ed25519 SPKI layout');
  }
  return der.subarray(ED25519_SPKI_PREFIX.length);
}

function ecPointFromSpki(der: Buffer, spec: EcSpec): Buffer {
  const q = der.subarray(der.length - spec.pointLen);
  if (q[0] !== 0x04) throw new Error('unexpected EC SPKI layout (not an uncompressed point)');
  return q;
}

function makeCA(id: string, privateKey: crypto.KeyObject): CAKey {
  const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const w = new Writer();
  let algo: string;
  if (id === 'ed25519') {
    algo = 'ssh-ed25519';
    w.string(algo).string(ed25519RawFromSpki(spki));
  } else {
    const spec = EC_SPECS[id]; // id like 'nistp256'
    if (!spec) throw new Error(`unknown CA key id: ${id}`);
    algo = `ecdsa-sha2-${spec.sshCurve}`;
    w.string(algo).string(spec.sshCurve).string(ecPointFromSpki(spki, spec));
  }
  const publicBlob = w.buffer();
  return {
    id,
    algo,
    privateKey,
    publicBlob,
    publicLine: `${algo} ${publicBlob.toString('base64')} ssh-ca-${id}`,
    fingerprint: fingerprintOf(publicBlob),
  };
}

export function generateCAKey(id: string): { pem: string; ca: CAKey } {
  let pair: crypto.KeyPairSyncResult<string, string>;
  if (id === 'ed25519') {
    pair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { format: 'pem', type: 'spki' },
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
    });
  } else {
    const spec = EC_SPECS[id];
    if (!spec) throw new Error(`unknown CA key id: ${id}`);
    pair = crypto.generateKeyPairSync('ec', {
      namedCurve: spec.nodeCurve,
      publicKeyEncoding: { format: 'pem', type: 'spki' },
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
    });
  }
  return { pem: pair.privateKey, ca: makeCA(id, crypto.createPrivateKey(pair.privateKey)) };
}

export const CA_KEY_IDS = ['ed25519', 'nistp256'] as const;

/** Load CA keys from dir, generating any that are missing. */
export function loadOrCreateCAKeys(dir: string): Map<string, CAKey> {
  fs.mkdirSync(dir, { recursive: true });
  const keys = new Map<string, CAKey>();
  for (const id of CA_KEY_IDS) {
    const pemPath = path.join(dir, `${id}.pem`);
    if (!fs.existsSync(pemPath)) {
      const { pem } = generateCAKey(id);
      fs.writeFileSync(pemPath, pem, { mode: 0o600 });
    }
    const pem = fs.readFileSync(pemPath, 'utf8');
    const ca = makeCA(id, crypto.createPrivateKey(pem));
    keys.set(id, ca);
    fs.writeFileSync(path.join(dir, `${id}.pub`), ca.publicLine + '\n');
  }
  return keys;
}

// ---------------------------------------------------------------- signing

/** Parse a DER ECDSA signature into (r, s) as SSH-mpint-ready byte strings. */
function derToRS(der: Buffer): { r: Buffer; s: Buffer } {
  let off = 0;
  const readLen = (): number => {
    let len = der[off++];
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | der[off++];
    }
    return len;
  };
  if (der[off++] !== 0x30) throw new Error('bad DER signature');
  readLen(); // sequence length
  if (der[off++] !== 0x02) throw new Error('bad DER signature (r)');
  const rlen = readLen();
  const r = der.subarray(off, off + rlen);
  off += rlen;
  if (der[off++] !== 0x02) throw new Error('bad DER signature (s)');
  const slen = readLen();
  const s = der.subarray(off, off + slen);
  return { r: Buffer.from(r), s: Buffer.from(s) };
}

/**
 * Sign data with a CA key and return the SSH "signature" field value:
 * string(algorithm) + string(signature blob).
 */
export function sshSign(ca: CAKey, data: Buffer): Buffer {
  const w = new Writer();
  if (ca.id === 'ed25519') {
    const sig = crypto.sign(null, data, ca.privateKey);
    w.string('ssh-ed25519').string(sig);
  } else {
    const spec = EC_SPECS[ca.id];
    const der = crypto.sign(spec.hash, data, ca.privateKey);
    const { r, s } = derToRS(der);
    const inner = new Writer().mpint(r).mpint(s).buffer();
    w.string(ca.algo).string(inner);
  }
  return w.buffer();
}
