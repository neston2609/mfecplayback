import { spawn } from 'node:child_process';
import { finished } from 'node:stream/promises';

export const RECORDING_OUTPUT_FORMATS = ['m4a', 'mp4', 'mp3', 'wav', 'webm', 'ogg_opus', 'ogg_vorbis', 'wav_ulaw'] as const;
export type RecordingOutputFormat = typeof RECORDING_OUTPUT_FORMATS[number];

export const DEFAULT_RECORDING_OUTPUT_FORMAT: RecordingOutputFormat = 'm4a';
export const MAX_TRANSCODED_AUDIO_BYTES = 256 * 1024 * 1024;
const MAX_INPUT_AUDIO_BYTES = 256 * 1024 * 1024;
const TRANSCODE_TIMEOUT_MS = 120_000;
const MAX_CONCURRENT_TRANSCODES = 2;
const MAX_QUEUED_TRANSCODES = 4;
let activeTranscodes = 0;
const transcodeQueue: Array<() => void> = [];

const OUTPUT_INFO: Record<RecordingOutputFormat, { extension: string; mimeType: string }> = {
  m4a: { extension: 'm4a', mimeType: 'audio/mp4' },
  mp4: { extension: 'mp4', mimeType: 'audio/mp4' },
  mp3: { extension: 'mp3', mimeType: 'audio/mpeg' },
  wav: { extension: 'wav', mimeType: 'audio/wav' },
  webm: { extension: 'webm', mimeType: 'audio/webm' },
  ogg_opus: { extension: 'ogg', mimeType: 'audio/ogg; codecs=opus' },
  ogg_vorbis: { extension: 'ogg', mimeType: 'audio/ogg; codecs=vorbis' },
  wav_ulaw: { extension: 'wav', mimeType: 'audio/wav' },
};

export function parseRecordingOutputFormat(value: unknown): RecordingOutputFormat {
  if (typeof value === 'string' && (RECORDING_OUTPUT_FORMATS as readonly string[]).includes(value)) return value as RecordingOutputFormat;
  throw new Error('Choose a supported recording output format.');
}

export function recordingOutputInfo(format: RecordingOutputFormat) {
  return OUTPUT_INFO[format];
}

export function preferredGenesysInputFormat(format: RecordingOutputFormat): string {
  if (format === 'wav_ulaw') return 'WAV_ULAW';
  if (format === 'ogg_opus') return 'OGG_OPUS';
  if (format === 'ogg_vorbis') return 'OGG_VORBIS';
  if (format === 'mp4' || format === 'm4a') return 'WEBM';
  return format.toUpperCase();
}

export function genesysMediaFormatKey(format: string): string {
  return format.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
}

export function ffmpegArguments(format: RecordingOutputFormat): string[] {
  const args = ['-hide_banner', '-loglevel', 'error', '-nostdin', '-protocol_whitelist', 'pipe', '-i', 'pipe:0', '-map', '0:a:0', '-vn', '-sn', '-dn'];
  switch (format) {
    case 'm4a': return [...args, '-c:a', 'aac', '-b:a', '128k', '-movflags', '+frag_keyframe+empty_moov+default_base_moof', '-f', 'mp4', 'pipe:1'];
    case 'mp4': return [...args, '-c:a', 'aac', '-b:a', '128k', '-movflags', '+frag_keyframe+empty_moov+default_base_moof', '-f', 'mp4', 'pipe:1'];
    case 'mp3': return [...args, '-c:a', 'libmp3lame', '-b:a', '192k', '-f', 'mp3', 'pipe:1'];
    case 'wav': return [...args, '-c:a', 'pcm_s16le', '-f', 'wav', 'pipe:1'];
    case 'webm': return [...args, '-c:a', 'libopus', '-b:a', '96k', '-f', 'webm', 'pipe:1'];
    case 'ogg_opus': return [...args, '-c:a', 'libopus', '-b:a', '96k', '-f', 'ogg', 'pipe:1'];
    case 'ogg_vorbis': return [...args, '-c:a', 'libvorbis', '-q:a', '5', '-f', 'ogg', 'pipe:1'];
    case 'wav_ulaw': return [...args, '-c:a', 'pcm_mulaw', '-ar', '8000', '-f', 'wav', 'pipe:1'];
  }
}

type FfmpegRunner = (input: Buffer, args: string[]) => Promise<Buffer>;

export async function transcodeRecordingAudio(input: Buffer, requestedFormat: unknown, runner: FfmpegRunner = runFfmpeg): Promise<{ bytes: Buffer; format: RecordingOutputFormat; extension: string; mimeType: string }> {
  const format = parseRecordingOutputFormat(requestedFormat);
  if (!input.length || input.length > MAX_INPUT_AUDIO_BYTES) throw new Error('Recording audio is empty or exceeds the 256 MB conversion limit.');
  await acquireTranscodeSlot();
  try {
    const bytes = await runner(input, ffmpegArguments(format));
    if (!bytes.length || bytes.length > MAX_TRANSCODED_AUDIO_BYTES) throw new Error('Converted recording is empty or exceeds the 256 MB output limit.');
    return { bytes, format, ...recordingOutputInfo(format) };
  } finally {
    activeTranscodes--;
    transcodeQueue.shift()?.();
  }
}

function acquireTranscodeSlot(): Promise<void> {
  if (activeTranscodes < MAX_CONCURRENT_TRANSCODES) { activeTranscodes++; return Promise.resolve(); }
  if (transcodeQueue.length >= MAX_QUEUED_TRANSCODES) return Promise.reject(new Error('Audio conversion is busy. Retry the download in a moment.'));
  return new Promise(resolve => transcodeQueue.push(() => { activeTranscodes++; resolve(); }));
}

export function checkAudioConverter(): Promise<boolean> {
  return new Promise(resolve => {
    let child: ReturnType<typeof spawn>;
    try { child = spawn(process.env.FFMPEG_PATH || 'ffmpeg', ['-version'], { stdio: 'ignore', windowsHide: true }); }
    catch { resolve(false); return; }
    let settled = false;
    const finish = (available: boolean) => { if (settled) return; settled = true; clearTimeout(timeout); resolve(available); };
    const timeout = setTimeout(() => { child.kill(); finish(false); }, 3000);
    timeout.unref();
    child.once('error', () => finish(false));
    child.once('close', code => finish(code === 0));
  });
}

function runFfmpeg(input: Buffer, args: string[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const executable = process.env.FFMPEG_PATH || 'ffmpeg';
    let child: ReturnType<typeof spawn>;
    try { child = spawn(executable, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }); }
    catch { reject(new Error('Audio conversion could not start. Install FFmpeg and ensure it is available to the application service.')); return; }

    const chunks: Buffer[] = [];
    const errors: Buffer[] = [];
    let outputBytes = 0, stderrBytes = 0, settled = false;
    const finish = (error?: Error, output?: Buffer) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) reject(error); else resolve(output!);
    };
    const timeout = setTimeout(() => {
      child.kill();
      finish(new Error('Audio conversion exceeded the two-minute processing limit.'));
    }, TRANSCODE_TIMEOUT_MS);
    timeout.unref();

    child.once('error', error => {
      finish(error.message.includes('ENOENT')
        ? new Error('Audio conversion is unavailable. Install FFmpeg and ensure it is available to the application service.')
        : new Error('Audio conversion could not start.'));
    });
    child.stdout!.on('data', (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_TRANSCODED_AUDIO_BYTES) {
        child.kill();
        finish(new Error('Converted recording exceeds the 256 MB output limit.'));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    child.stderr!.on('data', (chunk: Buffer) => {
      if (stderrBytes >= 16 * 1024) return;
      const part = Buffer.from(chunk).subarray(0, 16 * 1024 - stderrBytes);
      stderrBytes += part.length;
      errors.push(part);
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      if (code !== 0) {
        const detail = Buffer.concat(errors).toString('utf8').replace(/\s+/g, ' ').trim().slice(-300);
        finish(new Error(detail ? `Audio conversion failed: ${detail}` : `Audio conversion failed (${signal || `exit ${code}`}).`));
      } else finish(undefined, Buffer.concat(chunks, outputBytes));
    });
    child.stdin!.end(input);
    void finished(child.stdin!).catch(error => {
      if (!settled) finish(error instanceof Error ? error : new Error('Audio conversion input stream failed.'));
    });
  });
}
