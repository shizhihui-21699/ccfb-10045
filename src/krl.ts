// OpenSSH Key Revocation List generation (matches krl.c in openssh-portable).
import { Writer } from './wire';
import { CAKey, sshSign } from './keys';

const KRL_MAGIC = 0x5353484b524c0a00n; // "SSHKRL\n\0"
const KRL_FORMAT_VERSION = 1;

const KRL_SECTION_CERTIFICATES = 1;
const KRL_SECTION_CERT_SERIAL_LIST = 0x20;
const KRL_SECTION_CERT_KEY_ID = 0x23;
const KRL_SECTION_SIGNATURE = 4;

export interface KrlParams {
  ca: CAKey;
  serials: bigint[]; // revoked certificate serials
  keyIds?: string[]; // revoked key IDs (wildcard revocation)
  krlVersion: bigint;
  generatedDate: bigint; // unix seconds
  comment?: string;
}

export function buildKRL(p: KrlParams): Buffer {
  const out = new Writer();
  out.uint64(KRL_MAGIC);
  out.uint32(KRL_FORMAT_VERSION);
  out.uint64(p.krlVersion);
  out.uint64(p.generatedDate);
  out.uint64(0n); // flags
  out.string(Buffer.alloc(0)); // reserved
  out.string(p.comment ?? `ssh-ca krl v${p.krlVersion}`); // comment

  // Certificates section: string(ca scope key, empty = all CAs) +
  // string(reserved) + subsections. Serial list subsection is a bare
  // sequence of uint64 serials (no reserved field).
  const certs = new Writer();
  certs.string(Buffer.alloc(0)); // CA scope: wildcard (serials are globally unique)
  certs.string(Buffer.alloc(0)); // reserved
  if (p.serials.length > 0) {
    const serialList = new Writer();
    for (const s of [...p.serials].sort((a, b) => (a < b ? -1 : 1))) serialList.uint64(s);
    certs.byte(KRL_SECTION_CERT_SERIAL_LIST).string(serialList.buffer());
  }
  if (p.keyIds && p.keyIds.length > 0) {
    const ids = new Writer();
    for (const id of p.keyIds) ids.string(id);
    certs.byte(KRL_SECTION_CERT_KEY_ID).string(ids.buffer());
  }
  if (p.serials.length > 0 || (p.keyIds && p.keyIds.length > 0)) {
    out.byte(KRL_SECTION_CERTIFICATES).string(certs.buffer());
  }

  // Signature section: byte type, then string(signature_key) and
  // string(signature) directly (NOT wrapped in a section string).
  // The signature covers everything preceding the section.
  const signedData = out.buffer();
  const sig = sshSign(p.ca, signedData);
  out.byte(KRL_SECTION_SIGNATURE);
  out.string(p.ca.publicBlob);
  out.string(sig);

  return out.buffer();
}
