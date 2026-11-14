// SSH wire-format primitives (RFC 4251 §5 + PROTOCOL.certkeys).

export class Writer {
  private parts: Buffer[] = [];

  byte(v: number): this {
    this.parts.push(Buffer.from([v & 0xff]));
    return this;
  }

  uint32(v: number): this {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(v >>> 0);
    this.parts.push(b);
    return this;
  }

  uint64(v: bigint | number): this {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(typeof v === 'bigint' ? v : BigInt(v));
    this.parts.push(b);
    return this;
  }

  raw(data: Buffer): this {
    this.parts.push(data);
    return this;
  }

  string(data: Buffer | string): this {
    const d = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    this.uint32(d.length);
    this.parts.push(d);
    return this;
  }

  /** mpint from a big-endian magnitude buffer (positive values only). */
  mpint(magnitude: Buffer): this {
    let d = magnitude;
    while (d.length > 0 && d[0] === 0x00 && !(d.length > 1 && d[1] & 0x80)) {
      d = d.subarray(1);
    }
    if (d.length === 0) return this.string(Buffer.alloc(0));
    if (d[0] & 0x80) d = Buffer.concat([Buffer.from([0]), d]);
    return this.string(d);
  }

  buffer(): Buffer {
    return Buffer.concat(this.parts);
  }
}

export class Reader {
  private off = 0;
  constructor(private buf: Buffer) {}

  byte(): number {
    this.need(1);
    return this.buf[this.off++];
  }

  uint32(): number {
    this.need(4);
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }

  uint64(): bigint {
    this.need(8);
    const v = this.buf.readBigUInt64BE(this.off);
    this.off += 8;
    return v;
  }

  string(): Buffer {
    const len = this.uint32();
    this.need(len);
    const v = this.buf.subarray(this.off, this.off + len);
    this.off += len;
    return v;
  }

  get done(): boolean {
    return this.off >= this.buf.length;
  }

  private need(n: number): void {
    if (this.off + n > this.buf.length) throw new Error('SSH blob: unexpected end of data');
  }
}
