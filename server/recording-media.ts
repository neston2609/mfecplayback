import type { Connection } from './genesys.js';

type RecordingMetadataClient = { get<T>(path: string): Promise<T> };

export function recordingMediaRequestPath(conversationId: string, recordingId: string): string {
  const query = new URLSearchParams({ formatId: 'WEBM', download: 'true' });
  return `/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings/${encodeURIComponent(recordingId)}?${query}`;
}

export function recordingMediaUri(metadata: any): string | undefined {
  const mediaUris = metadata?.mediaUris;
  if (Array.isArray(mediaUris)) {
    for (const entry of mediaUris) if (typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
  }
  if (mediaUris && typeof mediaUris === 'object') {
    for (const entry of Object.values(mediaUris) as any[]) if (typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
  }
  return typeof metadata?.mediaUri === 'string' && metadata.mediaUri ? metadata.mediaUri : undefined;
}

export function isZipMediaContentType(contentType: string | null | undefined): boolean {
  return /^application\/(?:zip|x-zip-compressed)(?:\s*;|$)/i.test(contentType?.trim() || '');
}

export function isMessageRecording(metadata: any): boolean {
  return metadata?.media === 'message' || metadata?.media === 'chat' || metadata?.media === 'email';
}

export async function getRecordingMedia(
  client: RecordingMetadataClient,
  conversationId: string,
  recordingId: string,
  wait: (milliseconds: number) => Promise<void> = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
) {
  const path = recordingMediaRequestPath(conversationId, recordingId);
  for (let attempt = 0; attempt < 8; attempt++) {
    const metadata = await client.get<any>(path);
    const mediaUri = recordingMediaUri(metadata);
    if (mediaUri) return { metadata, mediaUri };
    if (attempt < 7) await wait(750 * (attempt + 1));
  }
  return undefined;
}

function hasSignedMediaQuery(url: URL): boolean {
  const query = url.searchParams;
  return Boolean(
    ((query.has('Policy') || query.has('Expires')) && query.has('Signature') && query.has('Key-Pair-Id')) ||
    (query.has('X-Amz-Signature') && query.has('X-Amz-Credential') && query.has('X-Amz-Date') && query.has('X-Amz-Expires')) ||
    (query.has('AWSAccessKeyId') && query.has('Signature') && query.has('Expires')),
  );
}

export function validateRecordingMediaUrl(value: string, connection: Connection): URL {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error('Genesys returned an invalid recording media URL.'); }

  const apiHost = new URL(connection.api_base_url).hostname.toLowerCase();
  const oauthHost = new URL(connection.oauth_base_url).hostname.toLowerCase();
  const roots = new Set([apiHost.replace(/^api\./, ''), oauthHost.replace(/^login\./, '')]);
  const allowed = new Set([apiHost, oauthHost]);
  for (const root of roots) {
    for (const prefix of ['apps', 'media', 'downloads', 'api-downloads']) allowed.add(`${prefix}.${root}`);
  }

  const host = url.hostname.toLowerCase();
  const trustedGenesysHost = allowed.has(host);
  const signedCloudFront = host === 'dhqbrvplips7x.cloudfront.net' && hasSignedMediaQuery(url);
  const signedS3 = /^prod-recording-playback\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/.test(host) && hasSignedMediaQuery(url);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !(trustedGenesysHost || signedCloudFront || signedS3)) {
    throw new Error('Genesys returned a recording media URL on an untrusted host.');
  }
  return url;
}
