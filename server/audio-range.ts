import { PassThrough, type Readable } from 'node:stream';

export type ByteRange = { start: number; end: number };

export function parseByteRange(value: string | undefined, size: number): ByteRange | 'unsatisfiable' | 'invalid' | undefined {
  if (!value) return undefined;
  const match = /^bytes=(\d*)-(\d*)$/i.exec(value.trim());
  if (!match || value.includes(',')) return 'invalid';
  if (!Number.isSafeInteger(size) || size <= 0) return 'unsatisfiable';

  const [, rawStart, rawEnd] = match;
  if (!rawStart && !rawEnd) return undefined;
  if (!rawStart) {
    const suffixLength = Number(rawEnd);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return 'unsatisfiable';
    return { start: Math.max(0, size - suffixLength), end: size - 1 };
  }

  const start = Number(rawStart);
  const requestedEnd = rawEnd ? Number(rawEnd) : size - 1;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(requestedEnd) || start >= size || requestedEnd < start) return 'unsatisfiable';
  return { start, end: Math.min(requestedEnd, size - 1) };
}

export function byteRangeStream(source: Readable, range: ByteRange, bytesToSkip = 0): Readable {
  const output = new PassThrough();
  let position = bytesToSkip;
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    source.unpipe();
    source.destroy();
    output.end();
  };

  source.on('data', (chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const chunkStart = position;
    const chunkEnd = chunkStart + bytes.length - 1;
    position += bytes.length;
    const from = Math.max(0, range.start - chunkStart);
    const to = Math.min(bytes.length, range.end + 1 - chunkStart);
    if (to > from && !output.write(bytes.subarray(from, to))) source.pause();
    if (chunkEnd >= range.end) finish();
  });
  output.on('drain', () => source.resume());
  source.once('end', () => output.end());
  source.once('error', error => output.destroy(error));
  output.once('close', () => {
    if (!finished) {
      finished = true;
      source.destroy();
    }
  });
  return output;
}
