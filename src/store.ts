// JSON-file persistence: requests, certs, revocations, audit log.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { CriticalOptions } from './cert';

export type CertKind = 'user' | 'host';
export type RequestStatus = 'pending' | 'approved' | 'rejected';

export interface CertRequest {
  id: string;
  status: RequestStatus;
  kind: CertKind;
  ca: string; // CA key id
  keyId: string;
  principals: string[];
  publicKey: string; // authorized_keys line
  fingerprint: string;
  validAfter: number; // unix seconds
  validBefore: number;
  criticalOptions: CriticalOptions;
  extensions: string[];
  comment: string;
  requestedBy: string;
  requestedAt: number;
  decidedBy?: string;
  decidedAt?: number;
  rejectReason?: string;
  serial?: string; // set on approval
}

export interface IssuedCertRecord {
  serial: string;
  requestId: string;
  kind: CertKind;
  ca: string;
  keyId: string;
  principals: string[];
  fingerprint: string;
  openssh: string; // cert line
  validAfter: number;
  validBefore: number;
  issuedBy: string;
  issuedAt: number;
  revoked: boolean;
  revokedBy?: string;
  revokedAt?: number;
  revokeReason?: string;
}

export interface AuditEntry {
  ts: number;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
}

interface StoreData {
  nextSerial: string; // bigint as decimal string
  krlVersion: number;
  requests: CertRequest[];
  certs: IssuedCertRecord[];
  audit: AuditEntry[];
}

const EMPTY: StoreData = { nextSerial: '1', krlVersion: 1, requests: [], certs: [], audit: [] };

export class Store {
  private file: string;
  private data: StoreData;

  constructor(dir: string) {
    fs.mkdirSync(dir, { recursive: true });
    this.file = path.join(dir, 'store.json');
    if (fs.existsSync(this.file)) {
      this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } else {
      this.data = structuredClone(EMPTY);
      this.save();
    }
  }

  private save(): void {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    fs.renameSync(tmp, this.file);
  }

  allocSerial(): bigint {
    const s = BigInt(this.data.nextSerial);
    this.data.nextSerial = (s + 1n).toString();
    return s; // caller must save() via another mutating call
  }

  bumpKrlVersion(): number {
    this.data.krlVersion += 1;
    return this.data.krlVersion;
  }

  get krlVersion(): number {
    return this.data.krlVersion;
  }

  addRequest(r: CertRequest): void {
    this.data.requests.push(r);
    this.save();
  }

  updateRequest(r: CertRequest): void {
    this.save();
  }

  getRequest(id: string): CertRequest | undefined {
    return this.data.requests.find((r) => r.id === id);
  }

  listRequests(status?: RequestStatus): CertRequest[] {
    return this.data.requests.filter((r) => !status || r.status === status);
  }

  addCert(c: IssuedCertRecord): void {
    this.data.certs.push(c);
    this.save();
  }

  getCert(serial: string): IssuedCertRecord | undefined {
    return this.data.certs.find((c) => c.serial === serial);
  }

  updateCert(_c: IssuedCertRecord): void {
    this.save();
  }

  listCerts(): IssuedCertRecord[] {
    return this.data.certs;
  }

  revokedSerials(): bigint[] {
    return this.data.certs.filter((c) => c.revoked).map((c) => BigInt(c.serial));
  }

  audit(actor: string, action: string, detail: Record<string, unknown>): void {
    this.data.audit.push({ ts: Math.floor(Date.now() / 1000), actor, action, detail });
    this.save();
  }

  listAudit(limit = 500): AuditEntry[] {
    return this.data.audit.slice(-limit).reverse();
  }
}

// ------------------------------------------------------------------ config

export interface TokenEntry {
  name: string;
  role: 'admin' | 'requester';
}

export interface Config {
  tokens: Record<string, TokenEntry>;
  defaultUserCertTTLSec: number;
  maxUserCertTTLSec: number;
  defaultHostCertTTLSec: number;
  maxHostCertTTLSec: number;
}

export function loadOrCreateConfig(dir: string): Config {
  const file = path.join(dir, 'config.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  const cfg: Config = {
    tokens: {
      [crypto.randomBytes(24).toString('hex')]: { name: 'admin', role: 'admin' },
      [crypto.randomBytes(24).toString('hex')]: { name: 'ops-bot', role: 'requester' },
    },
    defaultUserCertTTLSec: 8 * 3600,
    maxUserCertTTLSec: 7 * 24 * 3600,
    defaultHostCertTTLSec: 30 * 24 * 3600,
    maxHostCertTTLSec: 365 * 24 * 3600,
  };
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  return cfg;
}
