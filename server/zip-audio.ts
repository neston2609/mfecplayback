import { inflateRawSync } from 'node:zlib';

const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_AUDIO_BYTES = 256 * 1024 * 1024;
const MAX_ENTRIES = 100;

const audioTypes: Record<string, { mimeType: string; matches: (data: Buffer) => boolean }> = {
  '.aac': { mimeType: 'audio/aac', matches: data => data.length > 2 && data[0] === 0xff && (data[1] & 0xf6) === 0xf0 },
  '.m4a': { mimeType: 'audio/mp4', matches: isMp4 },
  '.mp3': { mimeType: 'audio/mpeg', matches: isMp3 },
  '.mp4': { mimeType: 'audio/mp4', matches: isMp4 },
  '.ogg': { mimeType: 'audio/ogg', matches: data => data.subarray(0, 4).toString('ascii') === 'OggS' },
  '.wav': { mimeType: 'audio/wav', matches: data => data.length >= 12 && data.subarray(0, 4).toString('ascii') === 'RIFF' && data.subarray(8, 12).toString('ascii') === 'WAVE' },
  '.webm': { mimeType: 'audio/webm', matches: data => data.length >= 4 && data.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])) },
};

/** Validate a ZIP in memory and return its only supported audio file. No archive paths are written to disk. */
export function extractSingleAudioFromZip(archive: Buffer): { audio: Buffer; mimeType: string; filename: string } {
  if (archive.length < 22 || archive.length > MAX_ARCHIVE_BYTES) throw new Error('Recording ZIP archive is empty, malformed, or too large to play.');
  const eocd = findEndOfCentralDirectory(archive);
  const disk = archive.readUInt16LE(eocd + 4);
  const centralDisk = archive.readUInt16LE(eocd + 6);
  const entriesOnDisk = archive.readUInt16LE(eocd + 8);
  const entryCount = archive.readUInt16LE(eocd + 10);
  const centralSize = archive.readUInt32LE(eocd + 12);
  const centralOffset = archive.readUInt32LE(eocd + 16);
  const commentLength = archive.readUInt16LE(eocd + 20);
  if (disk !== 0 || centralDisk !== 0 || entriesOnDisk !== entryCount || entryCount === 0 || entryCount > MAX_ENTRIES ||
      eocd + 22 + commentLength !== archive.length || centralOffset + centralSize > eocd) {
    throw new Error('Recording ZIP archive has an unsupported or malformed directory.');
  }

  let cursor = centralOffset;
  let selected: { name: string; nameBytes: Buffer; method: number; flags: number; crc: number; compressedSize: number; size: number; localOffset: number } | undefined;
  for (let index = 0; index < entryCount; index++) {
    if (cursor + 46 > archive.length || archive.readUInt32LE(cursor) !== 0x02014b50) throw new Error('Recording ZIP archive has a malformed file entry.');
    const madeBy = archive.readUInt16LE(cursor + 4) >>> 8;
    const flags = archive.readUInt16LE(cursor + 8);
    const method = archive.readUInt16LE(cursor + 10);
    const crc = archive.readUInt32LE(cursor + 16);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const size = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const entryCommentLength = archive.readUInt16LE(cursor + 32);
    const diskStart = archive.readUInt16LE(cursor + 34);
    const externalAttributes = archive.readUInt32LE(cursor + 38);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const entryEnd = cursor + 46 + nameLength + extraLength + entryCommentLength;
    if (entryEnd > archive.length || diskStart !== 0 || compressedSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff) {
      throw new Error('Recording ZIP archive uses unsupported ZIP64 or split-file features.');
    }
    const nameBytes = archive.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = nameBytes.toString(flags & 0x800 ? 'utf8' : 'latin1');
    const isDirectory = name.endsWith('/');
    if (!name || name.includes('\0') || name.includes('\\') || name.startsWith('/') || name.split('/').some(part => part === '.' || part === '..')) {
      throw new Error('Recording ZIP archive contains an unsafe file name.');
    }
    if ((flags & 0x2041) !== 0 || (method !== 0 && method !== 8)) throw new Error('Recording ZIP archive uses encryption or an unsupported compression method.');
    const unixMode = externalAttributes >>> 16;
    const fileType = madeBy === 3 ? unixMode & 0xf000 : 0;
    if (fileType && fileType !== 0x8000 && fileType !== 0x4000) throw new Error('Recording ZIP archive contains a non-regular file.');
    if (!isDirectory) {
      if (selected) throw new Error('Recording ZIP archive must contain exactly one audio file.');
      selected = { name, nameBytes: Buffer.from(nameBytes), method, flags, crc, compressedSize, size, localOffset };
    }
    cursor = entryEnd;
  }
  if (cursor !== centralOffset + centralSize || !selected) throw new Error('Recording ZIP archive does not contain exactly one playable audio file.');

  const extension = selected.name.slice(selected.name.lastIndexOf('/') + 1).toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || '';
  const audioType = audioTypes[extension];
  if (!audioType || selected.size === 0 || selected.size > MAX_AUDIO_BYTES || selected.compressedSize > MAX_ARCHIVE_BYTES ||
      selected.size > Math.max(selected.compressedSize * 1000, 1024 * 1024)) {
    throw new Error('Recording ZIP archive does not contain a supported audio file or exceeds playback limits.');
  }

  const local = selected.localOffset;
  if (local + 30 > archive.length || archive.readUInt32LE(local) !== 0x04034b50) throw new Error('Recording ZIP archive has a malformed local file header.');
  const localFlags = archive.readUInt16LE(local + 6);
  const localMethod = archive.readUInt16LE(local + 8);
  const localNameLength = archive.readUInt16LE(local + 26);
  const localExtraLength = archive.readUInt16LE(local + 28);
  const dataOffset = local + 30 + localNameLength + localExtraLength;
  if (localFlags !== selected.flags || localMethod !== selected.method || dataOffset + selected.compressedSize > centralOffset ||
      !archive.subarray(local + 30, local + 30 + localNameLength).equals(selected.nameBytes)) {
    throw new Error('Recording ZIP archive local and central headers do not match.');
  }
  if (!(selected.flags & 0x08) && (archive.readUInt32LE(local + 14) !== selected.crc || archive.readUInt32LE(local + 18) !== selected.compressedSize || archive.readUInt32LE(local + 22) !== selected.size)) {
    throw new Error('Recording ZIP archive local and central sizes do not match.');
  }

  let audio: Buffer;
  try {
    const compressed = archive.subarray(dataOffset, dataOffset + selected.compressedSize);
    audio = selected.method === 0 ? Buffer.from(compressed) : inflateRawSync(compressed, { maxOutputLength: MAX_AUDIO_BYTES });
  } catch {
    throw new Error('Recording ZIP audio could not be decompressed safely.');
  }
  if (audio.length !== selected.size || crc32(audio) !== selected.crc || !audioType.matches(audio)) {
    throw new Error('Recording ZIP contents failed audio format or integrity checks.');
  }
  return { audio, mimeType: audioType.mimeType, filename: selected.name.split('/').pop() || 'recording-audio' };
}

function findEndOfCentralDirectory(archive: Buffer): number {
  const minimum = Math.max(0, archive.length - 22 - 0xffff);
  for (let offset = archive.length - 22; offset >= minimum; offset--) {
    if (archive.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  throw new Error('Recording response is not a valid ZIP archive.');
}

function isMp3(data: Buffer): boolean {
  if (data.subarray(0, 3).toString('ascii') === 'ID3') return true;
  return data.length > 1 && data[0] === 0xff && (data[1] & 0xe0) === 0xe0;
}

function isMp4(data: Buffer): boolean {
  return data.length >= 12 && data.subarray(4, 8).toString('ascii') === 'ftyp';
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let value = n;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    table[n] = value >>> 0;
  }
  return table;
})();

function crc32(data: Buffer): number {
  let value = 0xffffffff;
  for (const byte of data) value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}
