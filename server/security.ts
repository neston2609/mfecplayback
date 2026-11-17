import crypto from 'node:crypto';

const key = () => {
  const encoded = process.env.MASTER_ENCRYPTION_KEY;
  if (!encoded) throw new Error('MASTER_ENCRYPTION_KEY is required to store Genesys credentials.');
  const value = Buffer.from(encoded, 'base64');
  if (value.length !== 32) throw new Error('MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes.');
  return value;
};
export function encrypt(plain: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${data.toString('base64')}`;
}
export function decrypt(value: string) {
  const [iv, tag, data] = value.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8');
}
export function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
