import { GenesysError } from './genesys-client.js';

export function transcriptionRequestPath(conversationId: string, communicationId: string): string {
  return `/api/v2/speechandtextanalytics/conversations/${encodeURIComponent(conversationId)}/communications/${encodeURIComponent(communicationId)}/transcripturl`;
}

export function validateTranscriptUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); }
  catch { throw Object.assign(new Error('Genesys returned an invalid transcript URL.'), { status: 502 }); }
  const host = url.hostname.toLowerCase();
  const trustedS3Host = /^(?:[a-z0-9][a-z0-9.-]*\.)?s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/.test(host);
  const query = url.searchParams;
  const signed = Boolean(
    (query.has('X-Amz-Signature') && query.has('X-Amz-Credential') && query.has('X-Amz-Date') && query.has('X-Amz-Expires')) ||
    (query.has('AWSAccessKeyId') && query.has('Signature') && query.has('Expires')),
  );
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !trustedS3Host || !signed) {
    throw Object.assign(new Error('Genesys returned a transcript URL on an untrusted host.'), { status: 502 });
  }
  return url;
}

export function normalizeTranscriptionError(error: unknown): unknown {
  if (error instanceof GenesysError && error.status >= 500 && error.status !== 501) {
    return Object.assign(
      new Error(`Genesys transcription service returned an error (HTTP ${error.status}). Check Speech and Text Analytics access and Genesys service availability.`),
      { status: 502 },
    );
  }
  const status = (error as { status?: unknown } | null)?.status;
  if (typeof status !== 'number' && error instanceof Error) {
    return Object.assign(
      new Error('Could not retrieve this transcription. Check that Speech and Text Analytics is enabled for the conversation and that the Genesys service account can access transcripts.'),
      { status: 502 },
    );
  }
  return error;
}

export function conversationCommunicationIds(conversation: any): string[] {
  const ids = new Set<string>();
  for (const participant of Array.isArray(conversation?.participants) ? conversation.participants : []) {
    for (const session of Array.isArray(participant?.sessions) ? participant.sessions : []) {
      if (session?.mediaType && session.mediaType !== 'voice') continue;
      for (const id of [session?.sessionId, session?.communicationId]) {
        if (typeof id === 'string' && id.trim() && id.length <= 128) ids.add(id);
      }
    }
  }
  return [...ids];
}
