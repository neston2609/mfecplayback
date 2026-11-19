import type { Connection } from './genesys.js';
import { genesysMediaFormatKey } from './audio-transcode.js';

type RecordingMetadataClient = { get<T>(path: string): Promise<T> };

export function recordingMediaRequestPath(conversationId: string, recordingId: string, formatId = 'WEBM'): string {
  const query = new URLSearchParams({ formatId, download: 'true' });
  return `/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings/${encodeURIComponent(recordingId)}?${query}`;
}

export function recordingMetadataRequestPath(conversationId: string): string {
  return `/api/v2/conversations/${encodeURIComponent(conversationId)}/recordingmetadata`;
}

export function isVoiceInteraction(conversation: any): boolean {
  if (typeof conversation?.mediaStats?.voice === 'number' || typeof conversation?.mediaStats?.callback === 'number') return true;
  return conversationHasVoiceSession(conversation);
}

export async function listVoiceRecordings(client: RecordingMetadataClient, conversationId: string, conversation?: any) {
  let items: any[] = [];
  try {
    const response = await client.get<any>(recordingMetadataRequestPath(conversationId));
    items = Array.isArray(response) ? response
      : Array.isArray(response?.recordings) ? response.recordings
      : Array.isArray(response?.recordingMetadata) ? response.recordingMetadata
      : Array.isArray(response?.entities) ? response.entities : [];
  } catch (error) {
    // Older org permissions may deny recordingmetadata while permitting the
    // recordings collection endpoint. Fall back only for endpoint availability.
    const status = (error as { status?: number })?.status;
    if (status !== 403 && status !== 404 && status !== 405) throw error;
    const response = await client.get<any>(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings`);
    items = Array.isArray(response) ? response
      : Array.isArray(response?.recordings) ? response.recordings
      : Array.isArray(response?.recordingMetadata) ? response.recordingMetadata
      : Array.isArray(response?.entities) ? response.entities : [];
  }
  const ids = new Set<string>();
  return items.filter((recording: any) => {
    const id = String(recording?.id || recording?.recordingId || '');
    const hasUnspecifiedMediaType=!recording?.mediaType&&!recording?.media;
    const verifiedVoice=isVoiceRecording(recording,conversation)||(hasUnspecifiedMediaType&&isVoiceInteraction(conversation));
    if (!id || ids.has(id) || isMessageRecording(recording) || !verifiedVoice) return false;
    ids.add(id);
    return true;
  });
}

export function recordingMediaUri(metadata: any, formatId?: string, strict = false, assumeRequestedFormat = false): string | undefined {
  const mediaUris = metadata?.mediaUris;
  if (formatId && mediaUris && typeof mediaUris === 'object' && !Array.isArray(mediaUris)) {
    const desired = genesysMediaFormatKey(formatId);
    for (const [key, entry] of Object.entries(mediaUris) as [string, any][]) {
      if (genesysMediaFormatKey(key) === desired && typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
    }
    if (strict && assumeRequestedFormat) {
      const entries = Object.values(mediaUris) as any[];
      const available = entries.filter(entry => typeof entry?.mediaUri === 'string' && entry.mediaUri);
      if (available.length === 1) return available[0].mediaUri;
    }
    if (strict && Object.keys(mediaUris).length && Object.values(mediaUris).some((entry: any) => typeof entry?.mediaUri === 'string' && entry.mediaUri)) return undefined;
  }
  if (Array.isArray(mediaUris)) {
    if (formatId) {
      const desired = genesysMediaFormatKey(formatId);
      for (const entry of mediaUris) {
        const entryFormat = entry?.formatId || entry?.mediaFormat || entry?.format;
        if (typeof entryFormat === 'string' && genesysMediaFormatKey(entryFormat) === desired && typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
      }
      if (strict && assumeRequestedFormat) {
        const available = mediaUris.filter((entry: any) => typeof entry?.mediaUri === 'string' && entry.mediaUri);
        if (available.length === 1) return available[0].mediaUri;
      }
      if (strict) return undefined;
    }
    for (const entry of mediaUris) if (typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
  }
  if (mediaUris && typeof mediaUris === 'object') {
    for (const [key, entry] of Object.entries(mediaUris) as [string, any][]) {
      if (strict && genesysMediaFormatKey(key) !== genesysMediaFormatKey(formatId || '')) continue;
      if (typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
    }
  }
  if (strict && formatId && metadata?.mediaUri) {
    const mediaFormat = metadata?.mediaFormat || metadata?.formatId;
    if (mediaFormat ? genesysMediaFormatKey(mediaFormat) !== genesysMediaFormatKey(formatId) : !assumeRequestedFormat) return undefined;
  }
  return typeof metadata?.mediaUri === 'string' && metadata.mediaUri ? metadata.mediaUri : undefined;
}

export function recordingMediaUriForFormats(metadata: any, formats: readonly string[]): string | undefined {
  const mediaUris = metadata?.mediaUris;
  const accepted = new Set(formats.map(genesysMediaFormatKey));
  if (Array.isArray(mediaUris)) {
    for (const entry of mediaUris) {
      const format = entry?.formatId || entry?.mediaFormat || entry?.format;
      if (typeof format === 'string' && accepted.has(genesysMediaFormatKey(format)) && typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
    }
  } else if (mediaUris && typeof mediaUris === 'object') {
    for (const [format, entry] of Object.entries(mediaUris) as [string, any][]) {
      if (accepted.has(genesysMediaFormatKey(format)) && typeof entry?.mediaUri === 'string' && entry.mediaUri) return entry.mediaUri;
    }
  }
  const format = metadata?.mediaFormat || metadata?.formatId;
  if (typeof format === 'string' && accepted.has(genesysMediaFormatKey(format)) && typeof metadata?.mediaUri === 'string' && metadata.mediaUri) return metadata.mediaUri;
  return undefined;
}

export function isZipMediaContentType(contentType: string | null | undefined): boolean {
  return /^application\/(?:zip|x-zip-compressed)(?:\s*;|$)/i.test(contentType?.trim() || '');
}

export function isMessageRecording(metadata: any): boolean {
  const media = typeof metadata?.media === 'string' ? metadata.media.trim().toLowerCase() : '';
  const mediaType = typeof metadata?.mediaType === 'string' ? metadata.mediaType.trim().toLowerCase() : '';
  return ['message', 'chat', 'email'].includes(media) || ['message', 'chat', 'email'].includes(mediaType);
}

export function conversationHasVoiceSession(conversation: any): boolean {
  return Array.isArray(conversation?.participants) && conversation.participants.some((participant: any) =>
    Array.isArray(participant?.sessions) && participant.sessions.some((session: any) =>
      typeof session?.mediaType === 'string' && ['voice', 'callback'].includes(session.mediaType.trim().toLowerCase()),
    ),
  );
}

export function isVoiceRecording(recording: any, conversation?: any): boolean {
  if (isMessageRecording(recording)) return false;
  const mediaType = typeof recording?.mediaType === 'string' ? recording.mediaType.trim().toLowerCase() : '';
  const media = typeof recording?.media === 'string' ? recording.media.trim().toLowerCase() : '';
  if (mediaType === 'voice') return true;
  // Genesys may report callback recordings as `mediaType: callback`, while the
  // recording itself is still audio. Callback sessions are voice interactions.
  if (mediaType === 'callback' && (media === 'audio' || conversationHasVoiceSession(conversation))) return true;
  if (['voice','audio'].includes(mediaType) && conversationHasVoiceSession(conversation)) return true;
  if (media === 'voice' && conversationHasVoiceSession(conversation)) return true;
  // Legacy recording metadata omits mediaType; use its audio media class and
  // conversation context (voice or callback) rather than dropping the item.
  return media === 'audio' && conversationHasVoiceSession(conversation);
}

export async function getRecordingMedia(
  client: RecordingMetadataClient,
  conversationId: string,
  recordingId: string,
  wait: ((milliseconds: number) => Promise<void>) | undefined = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
  formatId = 'WEBM',
  fallbackFormats: readonly string[] = [],
  assumeRequestedFormat = true,
) {
  const path = recordingMediaRequestPath(conversationId, recordingId, formatId);
  const listPath = `/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings`;
  const delays = [0, 750, 1500, 3000, 6000, 12000];
  for (let attempt = 0; attempt < delays.length; attempt++) {
    if (attempt > 0) await (wait || (milliseconds => new Promise<void>(resolve => setTimeout(resolve, milliseconds))))(delays[attempt]);
    const metadata = await client.get<any>(path);
    const mediaUri = recordingMediaUri(metadata, formatId, true, assumeRequestedFormat)
      || recordingMediaUriForFormats(metadata, fallbackFormats);
    if (mediaUri) return { metadata, mediaUri };
    // Genesys may return a media URI on the conversation recording list while
    // the individual recording download metadata omits it. Match the recording
    // ID exactly and never borrow another recording's media URI.
    if (attempt === 0 || attempt === 3) {
      const recordings = await client.get<any>(listPath);
      const listed = Array.isArray(recordings)
        ? recordings.find((recording: any) => (recording?.id || recording?.recordingId) === recordingId)
        : undefined;
      const listedMediaUri = recordingMediaUri(listed, formatId, true, false)
        || recordingMediaUriForFormats(listed, fallbackFormats);
      if (listed && listedMediaUri) return { metadata: listed, mediaUri: listedMediaUri };
    }
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
