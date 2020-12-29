import * as cc from 'commons-crypto';

export function hkdf(hash: cc.Hash, length: number, ikm: Buffer, salt?: Buffer | undefined | null, info?: Buffer | undefined | null): Buffer {
  const hashOutputSize = hash.outputSize / 8;
  const _salt: Buffer = salt && salt || Buffer.alloc(hashOutputSize);
  const okm: Buffer[] = [];
  const prk = cc.createHmacByHash('', hash)
    .init(_salt)
    .update(ikm)
    .digest();
  let t: Buffer | null = null;
  for (let i=0; i < Math.ceil(length / hashOutputSize); i++) {
    const bufs: Buffer[] = [];
    if (t) bufs.push(t);
    if (info) bufs.push(info);
    bufs.push(Buffer.from([1 + i]));
    t = cc.createHmacByHash('', hash)
      .init(prk)
      .update(Buffer.concat(bufs))
      .digest();
    okm.push(t);
  }
  return Buffer.concat(okm).slice(0, length);
}

