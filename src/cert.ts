// OpenSSH certificate construction (PROTOCOL.certkeys).
import crypto from 'node:crypto';
import { Writer } from './wire';
import { CAKey, ParsedPublicKey, sshSign } from './keys';

export const CERT_TYPE_USER = 1;
export const CERT_TYPE_HOST = 2;

export interface CriticalOptions {
  forceCommand?: string;
  sourceAddress?: string[]; // CIDR list
}

export const ALLOWED_EXTENSIONS = new Set([
  'permit-X11-forwarding',
  'permit-agent-forwarding',
  'permit-port-forwarding',
  'permit-pty',
  'permit-user-rc',
]);

export interface CertParams {
  ca: CAKey;
  subjectKey: ParsedPublicKey;
  serial: bigint;
  type: 1 | 2;
  keyId: string;
  principals: string[];
  validAfter: bigint; // unix seconds
  validBefore: bigint; // unix seconds
  criticalOptions: CriticalOptions;
  extensions: string[]; // names from ALLOWED_EXTENSIONS, empty-string data
}

export interface IssuedCert {
  serial: string; // decimal string (bigint-safe)
  openssh: string; // "<algo> <base64>" line
  certAlgo: string;
}

function encodeNameData(pairs: Array<[string, Buffer]>): Buffer {
  // PROTOCOL.certkeys: options must be lexicographically ordered by name.
  const sorted = [...pairs].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const w = new Writer();
  for (const [name, data] of sorted) w.string(name).string(data);
  return w.buffer();
}

export function buildCertificate(p: CertParams): IssuedCert {
  const certAlgo = `${p.subjectKey.algo}-cert-v01@openssh.com`;

  const critical: Array<[string, Buffer]> = [];
  if (p.criticalOptions.forceCommand) {
    critical.push(['force-command', new Writer().string(p.criticalOptions.forceCommand).buffer()]);
  }
  if (p.criticalOptions.sourceAddress && p.criticalOptions.sourceAddress.length > 0) {
    critical.push(['source-address', new Writer().string(p.criticalOptions.sourceAddress.join(',')).buffer()]);
  }
  const extensions: Array<[string, Buffer]> = p.extensions.map((name) => [name, Buffer.alloc(0)]);

  const principals = new Writer();
  for (const name of p.principals) principals.string(name);

  // The cert blob starts with the cert key-type string; everything up to (but
  // not including) the signature field is signed.
  const blob = new Writer();
  blob.string(certAlgo);
  blob.string(crypto.randomBytes(32)); // nonce
  blob.raw(p.subjectKey.fields); // public key fields
  blob.uint64(p.serial);
  blob.uint32(p.type);
  blob.string(p.keyId);
  blob.string(principals.buffer());
  blob.uint64(p.validAfter);
  blob.uint64(p.validBefore);
  blob.string(encodeNameData(critical));
  blob.string(encodeNameData(extensions));
  blob.string(Buffer.alloc(0)); // reserved
  blob.string(p.ca.publicBlob); // signature key
  // signature over everything so far
  const signed = blob.buffer();
  const sig = sshSign(p.ca, signed);
  const full = new Writer().raw(signed).string(sig).buffer();

  return {
    serial: p.serial.toString(),
    certAlgo,
    openssh: `${certAlgo} ${full.toString('base64')}`,
  };
}
