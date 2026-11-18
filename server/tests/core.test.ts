import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deflateRawSync } from 'node:zlib';
import { DEFAULT_REGIONS, trustedBaseUrl, validateRegionEndpoints } from '../regions.js';
import { encrypt, decrypt } from '../security.js';
import { MOCK_CONVERSATIONS, MOCK_RECORDINGS } from '../mock.js';
import { GenesysClient, verifyGenesysApiAccess } from '../genesys-client.js';
import { getRecordingMedia, isMessageRecording, isZipMediaContentType, recordingMediaRequestPath, validateRecordingMediaUrl } from '../recording-media.js';
import { extractSingleAudioFromZip } from '../zip-audio.js';
import { conversationCommunicationIds, transcriptionRequestPath, validateTranscriptUrl } from '../transcription.js';
import { collectAfterCallNotes, collectWrapUpCodeIds, withWrapUpCodeNames } from '../wrapup.js';

describe('MFEC Recording Explorer security and synthetic fixtures', () => {
  beforeAll(() => { process.env.MASTER_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64'); });
  afterAll(() => { delete process.env.MASTER_ENCRYPTION_KEY; });

  it('provides official common Genesys regions including Singapore and Tokyo', () => {
    expect(DEFAULT_REGIONS.find(region => region.id === 'ap-southeast-1')).toMatchObject({ api: 'https://api.apse1.pure.cloud', oauth: 'https://login.apse1.pure.cloud' });
    expect(DEFAULT_REGIONS.find(region => region.id === 'ap-northeast-1')?.oauth).toBe('https://login.mypurecloud.jp');
    expect(DEFAULT_REGIONS.some(region => region.id === 'us-east-1')).toBe(true);
    expect(DEFAULT_REGIONS.some(region => region.id === 'us-west-2')).toBe(true);
    expect(DEFAULT_REGIONS.some(region => region.id === 'eu-west-1')).toBe(true);
  });

  it('rejects endpoint URLs outside exact allowlisted host origins', () => {
    expect(trustedBaseUrl('https://api.apse1.pure.cloud', 'api')).toBe('https://api.apse1.pure.cloud');
    expect(() => trustedBaseUrl('https://api.apse1.pure.cloud.attacker.test', 'api')).toThrow();
    expect(() => trustedBaseUrl('http://127.0.0.1', 'api')).toThrow();
    expect(() => trustedBaseUrl('https://api.apse1.pure.cloud/path', 'api')).toThrow();
  });

  it('allows administrators to define only matching HTTPS Genesys Cloud regional endpoints', () => {
    expect(validateRegionEndpoints('https://api.cac1.pure.cloud', 'https://login.cac1.pure.cloud')).toEqual({
      api: 'https://api.cac1.pure.cloud', oauth: 'https://login.cac1.pure.cloud',
    });
    expect(() => validateRegionEndpoints('https://api.cac1.pure.cloud', 'https://login.apse1.pure.cloud')).toThrow(/matching official/i);
    expect(() => validateRegionEndpoints('https://api.cac1.pure.cloud.attacker.test', 'https://login.cac1.pure.cloud.attacker.test')).toThrow(/matching official/i);
    expect(() => validateRegionEndpoints('http://api.cac1.pure.cloud', 'https://login.cac1.pure.cloud')).toThrow(/HTTPS/i);
  });

  it('encrypts secrets with authenticated encryption and decrypts them', () => {
    const stored = encrypt('synthetic-client-secret');
    expect(stored).not.toContain('synthetic-client-secret');
    expect(decrypt(stored)).toBe('synthetic-client-secret');
    expect(() => decrypt(stored.replace(/.$/, 'A'))).toThrow();
  });

  it('includes synthetic bot-only, bot-to-agent, multi-agent and multi-recording cases', () => {
    const byId = new Map(MOCK_CONVERSATIONS.map(item => [item.conversationId, item]));
    expect(byId.get('demo-bot-only-002')?.participants.some((p:any) => p.purpose === 'ivr')).toBe(true);
    const transferred = byId.get('demo-ava-agent-001')!;
    expect(transferred.participants.some((p:any) => p.purpose === 'agent')).toBe(true);
    const multiAgent = byId.get('demo-transfer-003')!;
    expect(multiAgent.participants.filter((p:any) => p.purpose === 'agent')).toHaveLength(2);
    expect(Object.values(MOCK_RECORDINGS).some(records => records.length > 0)).toBe(true);
  });

  it('uses valid ISO timestamps in synthetic calls for timezone-safe UTC queries', () => {
    for (const conversation of MOCK_CONVERSATIONS) {
      expect(Number.isFinite(Date.parse(conversation.conversationStart))).toBe(true);
      expect(Number.isFinite(Date.parse(conversation.conversationEnd))).toBe(true);
      expect(Date.parse(conversation.conversationEnd)).toBeGreaterThan(Date.parse(conversation.conversationStart));
    }
  });

  it('authenticates with OAuth and verifies organization API access', async () => {
    const originalFetch = globalThis.fetch;
    const originalMode = process.env.MOCK_MODE;
    process.env.MOCK_MODE = 'false';
    const requests: { url: string; authorization: string | null }[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, authorization: new Headers(init?.headers).get('authorization') });
      if (url.endsWith('/oauth/token')) return new Response(JSON.stringify({ access_token: 'test-token', expires_in: 300 }), { status: 200, headers: { 'content-type': 'application/json' } });
      if (url.endsWith('/recordings')) return new Response(null, { status: 200 });
      return new Response(JSON.stringify({ id: 'org-123', name: 'Test organization' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    const client = new GenesysClient({
      id: `genesys-test-${crypto.randomUUID()}`, name: 'Test', organization_label: 'Test', region_id: 'us-east-1',
      api_base_url: 'https://api.mypurecloud.com', oauth_base_url: 'https://login.mypurecloud.com',
      client_id: 'test-client', client_secret_enc: encrypt('test-secret'), enabled: 1, is_default: 0,
    });

    try {
      await client.accessToken();
      const organization = await verifyGenesysApiAccess(client);
      expect(organization).toEqual({ id: 'org-123', name: 'Test organization' });
      await expect(client.get('/api/v2/conversations/test-conversation/recordings')).resolves.toBeUndefined();
      expect(requests.map(request => request.url)).toEqual([
        'https://login.mypurecloud.com/oauth/token',
        'https://api.mypurecloud.com/api/v2/organizations/me',
        'https://api.mypurecloud.com/api/v2/conversations/test-conversation/recordings',
      ]);
      expect(requests[1].authorization).toBe('Bearer test-token');
    } finally {
      client.clearCachedToken();
      globalThis.fetch = originalFetch;
      if (originalMode === undefined) delete process.env.MOCK_MODE;
      else process.env.MOCK_MODE = originalMode;
    }
  });

  it('requests downloadable Genesys recording media and waits for asynchronous readiness', async () => {
    const path = recordingMediaRequestPath('conversation id', 'recording/id');
    expect(path).toBe('/api/v2/conversations/conversation%20id/recordings/recording%2Fid?formatId=WEBM&download=true');
    const requested: string[] = [];
    const client = { async get<T>(endpoint: string): Promise<T> {
      requested.push(endpoint);
      return (requested.length < 3 ? undefined : { mediaUris: { S: { mediaUri: 'https://prod-recording-playback.s3.amazonaws.com/audio?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig' } } }) as T;
    } };
    const result = await getRecordingMedia(client, 'conversation', 'recording', async () => undefined);
    expect(requested).toHaveLength(3);
    expect(requested.every(endpoint => endpoint.includes('download=true'))).toBe(true);
    expect(result?.mediaUri).toContain('X-Amz-Signature=sig');
    let attempts = 0;
    const unavailableClient = { async get<T>(): Promise<T> { attempts++; return undefined as T; } };
    expect(await getRecordingMedia(unavailableClient, 'conversation', 'pending', async () => undefined)).toBeUndefined();
    expect(attempts).toBe(8);
  });

  it('allows only signed Genesys recording storage URLs and known regional media hosts', () => {
    const connection = {
      id: 'media-url-test', name: 'Test', organization_label: 'Test', region_id: 'ap-southeast-1',
      api_base_url: 'https://api.apse1.pure.cloud', oauth_base_url: 'https://login.apse1.pure.cloud',
      client_id: 'client', client_secret_enc: 'encrypted', enabled: 1, is_default: 0,
    };
    expect(validateRecordingMediaUrl('https://api-downloads.apse1.pure.cloud/audio', connection).hostname).toBe('api-downloads.apse1.pure.cloud');
    expect(validateRecordingMediaUrl('https://dhqbrvplips7x.cloudfront.net/audio?Policy=p&Signature=s&Key-Pair-Id=k', connection).hostname).toBe('dhqbrvplips7x.cloudfront.net');
    expect(() => validateRecordingMediaUrl('https://d123abc.cloudfront.net/audio?Policy=p&Signature=s&Key-Pair-Id=k', connection)).toThrow(/untrusted/i);
    expect(() => validateRecordingMediaUrl('https://d123abc.cloudfront.net/audio?Expires=123&Signature=s&Key-Pair-Id=k', connection)).toThrow(/untrusted/i);
    expect(validateRecordingMediaUrl('https://prod-recording-playback.s3.amazonaws.com/audio?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig', connection).hostname).toBe('prod-recording-playback.s3.amazonaws.com');
    expect(() => validateRecordingMediaUrl('https://attacker.example/audio?X-Amz-Signature=sig', connection)).toThrow(/untrusted/i);
    expect(() => validateRecordingMediaUrl('https://attacker-bucket.s3.amazonaws.com/audio?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig', connection)).toThrow(/untrusted/i);
    expect(() => validateRecordingMediaUrl('https://d123abc.cloudfront.net/audio?X-Amz-Signature=sig', connection)).toThrow(/untrusted/i);
    expect(() => validateRecordingMediaUrl('https://prod-recording-playback.s3.amazonaws.com/audio', connection)).toThrow(/untrusted/i);
    expect(() => validateRecordingMediaUrl('http://api-downloads.apse1.pure.cloud/audio', connection)).toThrow(/untrusted/i);
  });

  it('distinguishes message recording archives from playable media', () => {
    expect(isZipMediaContentType('application/zip')).toBe(true);
    expect(isZipMediaContentType('application/x-zip-compressed; charset=binary')).toBe(true);
    expect(isZipMediaContentType('audio/webm')).toBe(false);
    expect(isZipMediaContentType('application/octet-stream')).toBe(false);
    expect(isMessageRecording({ media: 'message' })).toBe(true);
    expect(isMessageRecording({ media: 'voice' })).toBe(false);
  });

  it('extracts one supported and verified audio file from ZIP without writing archive paths', () => {
    const mp3 = Buffer.from('ID3synthetic-test-audio');
    const extracted = extractSingleAudioFromZip(makeZip([{ name: 'folder/recording.mp3', data: mp3 }]));
    expect(extracted.audio).toEqual(mp3);
    expect(extracted.mimeType).toBe('audio/mpeg');
    expect(extracted.filename).toBe('recording.mp3');
  });

  it('rejects malformed, non-audio, and ambiguous ZIP recording archives', () => {
    expect(() => extractSingleAudioFromZip(Buffer.from('not a zip'))).toThrow(/zip/i);
    expect(() => extractSingleAudioFromZip(makeZip([{ name: 'message.json', data: Buffer.from('{"message":"hello"}') }]))).toThrow(/supported audio/i);
    expect(() => extractSingleAudioFromZip(makeZip([
      { name: 'first.mp3', data: Buffer.from('ID3first') },
      { name: 'second.mp3', data: Buffer.from('ID3second') },
    ]))).toThrow(/exactly one audio/i);
    expect(() => extractSingleAudioFromZip(makeZip([{ name: 'recording.mp3', data: Buffer.from('<html>not audio</html>') }]))).toThrow(/format or integrity/i);
    expect(() => extractSingleAudioFromZip(makeZip([{ name: '../recording.mp3', data: Buffer.from('ID3test') }]))).toThrow(/unsafe file name/i);
  });

  it('builds a safe transcript endpoint path and selects only voice communication IDs', () => {
    expect(transcriptionRequestPath('conversation/id', 'communication id')).toBe('/api/v2/speechandtextanalytics/conversations/conversation%2Fid/communications/communication%20id/transcripturl');
    expect(conversationCommunicationIds({participants:[
      {sessions:[{mediaType:'voice',sessionId:'voice-1'},{mediaType:'voice',communicationId:'voice-2'}]},
      {sessions:[{mediaType:'chat',communicationId:'chat-1'},{communicationId:'voice-1'}]},
      {sessions:[{mediaType:'voice',communicationId:'x'.repeat(129)}]},
    ]})).toEqual(['voice-1','voice-2']);
  });

  it('validates signed Genesys transcript URLs before fetching them server-side', () => {
    const good='https://genesys-transcripts.s3.amazonaws.com/file.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600';
    expect(validateTranscriptUrl(good).hostname).toBe('genesys-transcripts.s3.amazonaws.com');
    expect(()=>validateTranscriptUrl('https://attacker.example/file.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600')).toThrow(/untrusted/i);
    expect(()=>validateTranscriptUrl('http://genesys-transcripts.s3.amazonaws.com/file.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600')).toThrow(/untrusted/i);
  });

  it('extracts the true after-call summary note and maps wrap-up UUIDs to names', () => {
    const id='2816e6e2-0c0b-4a90-a147-61e20f80435d';
    const conversation={participants:[{participantName:'Agent A',sessions:[{segments:[{wrapUpCode:id,wrapUpNote:'Customer confirmed resolution.'}]}]}]};
    expect(collectWrapUpCodeIds(conversation)).toEqual([id]);
    expect(collectAfterCallNotes(conversation)).toEqual([{agent:'Agent A',note:'Customer confirmed resolution.'}]);
    const mapped=withWrapUpCodeNames(conversation,{[id]:'Issue Resolved'});
    expect(mapped.participants[0].sessions[0].segments[0]).toMatchObject({wrapUpCodeName:'Issue Resolved',wrapUpNote:'Customer confirmed resolution.'});
    expect(collectAfterCallNotes({participants:[{sessions:[{segments:[{wrapUpCodeNote:'not the agent note'}]}]}]})).toEqual([]);
  });

});

function makeZip(files: { name: string; data: Buffer }[]): Buffer {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let localOffset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name, 'utf8');
    const compressed = deflateRawSync(file.data);
    const checksum = testCrc32(file.data);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0x800, 6);
    header.writeUInt16LE(8, 8);
    header.writeUInt32LE(checksum, 14);
    header.writeUInt32LE(compressed.length, 18);
    header.writeUInt32LE(file.data.length, 22);
    header.writeUInt16LE(name.length, 26);
    local.push(header, name, compressed);

    const directory = Buffer.alloc(46);
    directory.writeUInt32LE(0x02014b50, 0);
    directory.writeUInt16LE(0x0314, 4);
    directory.writeUInt16LE(20, 6);
    directory.writeUInt16LE(0x800, 8);
    directory.writeUInt16LE(8, 10);
    directory.writeUInt32LE(checksum, 16);
    directory.writeUInt32LE(compressed.length, 20);
    directory.writeUInt32LE(file.data.length, 24);
    directory.writeUInt16LE(name.length, 28);
    directory.writeUInt32LE(0x81a40000, 38);
    directory.writeUInt32LE(localOffset, 42);
    central.push(directory, name);
    localOffset += header.length + name.length + compressed.length;
  }
  const centralBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...local, centralBytes, end]);
}

function testCrc32(data: Buffer): number {
  let value = 0xffffffff;
  for (const byte of data) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return (value ^ 0xffffffff) >>> 0;
}
