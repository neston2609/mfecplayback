import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deflateRawSync } from 'node:zlib';
import { DEFAULT_REGIONS, trustedBaseUrl, validateRegionEndpoints } from '../regions.js';
import { encrypt, decrypt } from '../security.js';
import { MOCK_CONVERSATIONS, MOCK_RECORDINGS } from '../mock.js';
import { GenesysClient, verifyGenesysApiAccess } from '../genesys-client.js';
import { queryAllConversations, VOICE_RECORDING_FILTERS } from '../conversation-query.js';
import { participantLines, summarizeConversation } from '../conversation-summary.js';
import { conversationHasVoiceSession, getRecordingMedia, isMessageRecording, isVoiceInteraction, isVoiceRecording, isZipMediaContentType, listVoiceRecordings, recordingMediaRequestPath, recordingMetadataRequestPath, validateRecordingMediaUrl } from '../recording-media.js';
import { extractSingleAudioFromZip } from '../zip-audio.js';
import { conversationCommunicationIds, transcriptionRequestPath, validateTranscriptUrl } from '../transcription.js';
import { collectAfterCallNotes, collectWrapUpCodeIds, withWrapUpCodeNames } from '../wrapup.js';
import { checkPasswordPolicy, isPasswordPolicySatisfied } from '../password-policy.js';
import { parseSmtpSettings, publicSmtpSettings } from '../mailer.js';

describe('MFEC Recording Explorer security and synthetic fixtures', () => {
  beforeAll(() => { process.env.MASTER_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64'); });
  afterAll(() => { delete process.env.MASTER_ENCRYPTION_KEY; });

  it('loads all Analytics conversation pages and deduplicates repeated conversations', async () => {
    const requests: { interval: string; pageNumber: number; pageSize: number }[] = [];
    const firstPage = Array.from({ length: 100 }, (_, index) => ({ conversationId: `conversation-${index + 1}` }));
    const pages = [
      { conversations: firstPage, totalHits: 101 },
      { conversations: [{ conversationId: 'conversation-100' }, { conversationId: 'conversation-101' }], totalHits: 101 },
    ];
    const client = { async post<T>(_path: string, body: any): Promise<T> {
      requests.push({ interval: body.interval, pageNumber: body.paging.pageNumber, pageSize: body.paging.pageSize });
      return pages[body.paging.pageNumber - 1] as T;
    } };

    const result = await queryAllConversations(client, '2026-11-17T00:00:00.000Z/2026-11-18T00:00:00.000Z', {
      conversationFilters: [{ type: 'and', predicates: [] }],
    });

    expect(requests).toEqual([
      { interval: '2026-11-17T00:00:00.000Z/2026-11-18T00:00:00.000Z', pageNumber: 1, pageSize: 100 },
      { interval: '2026-11-17T00:00:00.000Z/2026-11-18T00:00:00.000Z', pageNumber: 2, pageSize: 100 },
    ]);
    expect(result.conversations).toHaveLength(101);
    expect(result.conversations.at(-1)?.conversationId).toBe('conversation-101');
    expect(result).toMatchObject({ totalHits: 101, partial: false });
  });

  it('always adds the native Genesys voice-and-recording Analytics predicates', async () => {
    let query:any;
    await queryAllConversations({async post<T>(_path:string,body:any){query=body;return {conversations:[]} as T;}},'2026-11-18T00:00:00.000Z/2026-11-19T00:00:00.000Z',VOICE_RECORDING_FILTERS);
    expect(query.segmentFilters).toEqual([{type:'and',predicates:[
      {type:'dimension',dimension:'mediaType',operator:'matches',value:'voice'},
      {type:'dimension',dimension:'recording',operator:'matches',value:'true'},
    ]}]);
  });

  it('uses recordingmetadata first and exposes only verified voice recording IDs', async () => {
    const conversation={participants:[{purpose:'customer',sessions:[{mediaType:'voice'}]}]};
    const requested:string[]=[];
    const client={async get<T>(endpoint:string):Promise<T>{requested.push(endpoint);return [
      {recordingId:'voice-1',media:'audio',mediaType:'voice'},
      {recordingId:'message-1',media:'message',mediaType:'message'},
      {recordingId:'duplicate-1',media:'audio',mediaType:'voice'},
      {recordingId:'duplicate-1',media:'audio',mediaType:'voice'},
      {recordingId:'legacy-voice',startTime:'2026-11-18T00:00:00.000Z'},
    ] as T;}};
    expect(recordingMetadataRequestPath('id/with slash')).toBe('/api/v2/conversations/id%2Fwith%20slash/recordingmetadata');
    await expect(listVoiceRecordings(client,'conversation',conversation)).resolves.toEqual([
      {recordingId:'voice-1',media:'audio',mediaType:'voice'},
      {recordingId:'duplicate-1',media:'audio',mediaType:'voice'},
      {recordingId:'legacy-voice',startTime:'2026-11-18T00:00:00.000Z'},
    ]);
    expect(requested).toEqual(['/api/v2/conversations/conversation/recordingmetadata']);
    expect(isVoiceInteraction(conversation)).toBe(true);
    expect(isVoiceInteraction({participants:[{sessions:[{mediaType:'chat'}]}]})).toBe(false);
  });

  it('falls back to the conversation recordings endpoint only when recordingmetadata is unavailable', async () => {
    const requested:string[]=[];
    const client={async get<T>(endpoint:string):Promise<T>{requested.push(endpoint);if(endpoint.endsWith('/recordingmetadata'))throw Object.assign(new Error('Not found'),{status:404});return [{id:'fallback-voice',media:'audio',mediaType:'voice'}] as T;}};
    await expect(listVoiceRecordings(client,'conversation',{participants:[{sessions:[{mediaType:'voice'}]}]})).resolves.toMatchObject([{id:'fallback-voice'}]);
    expect(requested).toEqual(['/api/v2/conversations/conversation/recordingmetadata','/api/v2/conversations/conversation/recordings']);
  });

  it('summarizes UUID participants using names and hides SIP route strings from phone fields', () => {
    const result=summarizeConversation({
      conversationId:'conversation',conversationStart:'2026-11-19T00:00:00.000Z',conversationEnd:'2026-11-19T00:01:00.000Z',originatingDirection:'outbound',
      participants:[
        {purpose:'customer',sessions:[{ani:'sip:6aad58139624088f1a49d141+mfecpubliccompanylimited.orgspan.com@localhost',dnis:'tel:+6621234567',mediaType:'callback'}]},
        {purpose:'agent',participantName:'eb13c121-2f73-4f10-b8da-3a550b0b4d29',userId:'eb13c121-2f73-4f10-b8da-3a550b0b4d29',sessions:[{mediaType:'callback',ani:'sip:route@localhost'}]},
      ],
    },{'eb13c121-2f73-4f10-b8da-3a550b0b4d29':'Nicha Agent'});

    expect(result).toMatchObject({agents:['Nicha Agent'],flows:[],ani:'',dnis:'+6621234567',direction:'outbound',interactionType:'Human Agent'});
  });

  it('formats participant labels in Genesys order using customer numbers, flow names, and resolved agent names', () => {
    const participants=[
      {purpose:'customer',participantName:'Mobile Number, Thailand',sessions:[{ani:'tel:+66652936493',dnis:'tel:+6625440862'}]},
      {purpose:'ivr',participantName:'[MAIN] - Bank of MFEC',sessions:[{flow:{flowName:'[MAIN] - Bank of MFEC'}}]},
      {purpose:'ivr',participantName:'MFEC Insurance Call Flow',sessions:[{flow:{flowName:'MFEC Insurance Call Flow'}}]},
      {purpose:'botflow',sessions:[{flow:{flowName:'MFEC_Insure_AVA'}}]},
      {purpose:'acd',participantName:'MFEC_Insure_CSR'},
      {purpose:'agent',userId:'agent-1',participantName:'agent-1'},
    ];
    expect(participantLines(participants,{'agent-1':'Suwajchai Rasikawan'}).map(item=>item.displayText)).toEqual([
      'Customer : +66652936493 -> +6625440862',
      'IVR : [MAIN] - Bank of MFEC',
      'IVR : MFEC Insurance Call Flow',
      'Botflow : MFEC_Insure_AVA',
      'ACD : MFEC_Insure_CSR',
      'Agent : Suwajchai Rasikawan',
    ]);
  });

  it('recognizes Genesys audio recordings when their mediaType is missing or callback', () => {
    const conversation={participants:[{purpose:'customer',sessions:[{mediaType:'callback'}]}]};
    expect(isVoiceRecording({media:'audio'},conversation)).toBe(true);
    expect(isVoiceRecording({media:'audio',mediaType:'callback'},conversation)).toBe(true);
    expect(isVoiceRecording({media:'message'},conversation)).toBe(false);
    expect(isVoiceRecording({media:'audio',mediaType:'callback'},{participants:[]})).toBe(true);
  });

  it('enforces the requested eight-character password rules without requiring both cases', () => {
    expect(checkPasswordPolicy('abcdefgh','abcdefgh')).toEqual({minLength:true,hasLetter:true,hasNumberOrSpecial:false,matchesConfirmation:true});
    expect(isPasswordPolicySatisfied('abcdefgh1')).toBe(true);
    expect(isPasswordPolicySatisfied('ABCDEFGH!')).toBe(true);
    expect(isPasswordPolicySatisfied('éééééééé!')).toBe(true);
    expect(isPasswordPolicySatisfied('กขคงจฉช้')).toBe(false);
    expect(isPasswordPolicySatisfied('short1')).toBe(false);
    expect(isPasswordPolicySatisfied('12345678')).toBe(false);
    expect(checkPasswordPolicy('abcdefgh1','abcdefgh2').matchesConfirmation).toBe(false);
  });

  it('validates Gmail SMTP settings and never returns configured passwords', () => {
    const settings=parseSmtpSettings({host:'smtp.gmail.com',port:587,secure:false,username:'sender@gmail.com',password:'gmail-app-password',fromName:'MFEC',fromEmail:'sender@gmail.com',rejectUnauthorized:true});
    expect(settings).toMatchObject({host:'smtp.gmail.com',port:587,secure:false});
    expect(publicSmtpSettings(settings,true)).toMatchObject({passwordConfigured:true,username:'sender@gmail.com'});
    expect(publicSmtpSettings(settings,true)).not.toHaveProperty('password');
    expect(()=>parseSmtpSettings({...settings,port:70000})).toThrow(/port/i);
    expect(()=>parseSmtpSettings({...settings,host:'smtp.gmail.com',rejectUnauthorized:false})).toThrow(/certificate/i);
  });

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

  it('honors Genesys 429 Retry-After and suppresses follow-up requests during the cooldown', async () => {
    const originalFetch=globalThis.fetch,originalMode=process.env.MOCK_MODE;process.env.MOCK_MODE='false';
    const apiCalls:string[]=[];
    globalThis.fetch=(async(input:RequestInfo|URL)=>{const url=String(input);if(url.endsWith('/oauth/token'))return new Response(JSON.stringify({access_token:'limited-token',expires_in:300}),{status:200,headers:{'content-type':'application/json'}});apiCalls.push(url);return new Response('rate limited',{status:429,headers:{'retry-after':'30'}});}) as typeof fetch;
    const client=new GenesysClient({id:`rate-limit-${crypto.randomUUID()}`,name:'Rate limit',organization_label:'test',region_id:'us-east-1',api_base_url:'https://api.mypurecloud.com',oauth_base_url:'https://login.mypurecloud.com',client_id:'client',client_secret_enc:encrypt('secret'),enabled:1,is_default:0});
    try{
      await expect(client.get('/api/v2/organizations/me')).rejects.toMatchObject({status:429,retryAfterMs:30000});
      await expect(client.get('/api/v2/conversations/next/recordings')).rejects.toMatchObject({status:429});
      expect(apiCalls).toHaveLength(1);
    }finally{client.clearCachedToken();globalThis.fetch=originalFetch;if(originalMode===undefined)delete process.env.MOCK_MODE;else process.env.MOCK_MODE=originalMode;}
  });

  it('applies the same cooldown when Genesys OAuth itself returns 429', async () => {
    const originalFetch=globalThis.fetch,originalMode=process.env.MOCK_MODE;process.env.MOCK_MODE='false';
    let oauthCalls=0;
    globalThis.fetch=(async()=>{oauthCalls++;return new Response('rate limited',{status:429,headers:{'retry-after':'20'}});}) as typeof fetch;
    const client=new GenesysClient({id:`oauth-rate-limit-${crypto.randomUUID()}`,name:'OAuth rate limit',organization_label:'test',region_id:'us-east-1',api_base_url:'https://api.mypurecloud.com',oauth_base_url:'https://login.mypurecloud.com',client_id:'client',client_secret_enc:encrypt('secret'),enabled:1,is_default:0});
    try{
      await expect(client.get('/api/v2/organizations/me')).rejects.toMatchObject({status:429,retryAfterMs:20000});
      await expect(client.get('/api/v2/organizations/me')).rejects.toMatchObject({status:429});
      expect(oauthCalls).toBe(1);
    }finally{client.clearCachedToken();globalThis.fetch=originalFetch;if(originalMode===undefined)delete process.env.MOCK_MODE;else process.env.MOCK_MODE=originalMode;}
  });

  it('requests downloadable Genesys recording media and waits for asynchronous readiness', async () => {
    const path = recordingMediaRequestPath('conversation id', 'recording/id');
    expect(path).toBe('/api/v2/conversations/conversation%20id/recordings/recording%2Fid?formatId=WEBM&download=true');
    const requested: string[] = [];
    const client = { async get<T>(endpoint: string): Promise<T> {
      requested.push(endpoint);
      if (endpoint.endsWith('/recordings')) return [] as T;
      return (requested.filter(item => item.includes('/recordings/recording?')).length < 3 ? undefined : { mediaUris: { S: { mediaUri: 'https://prod-recording-playback.s3.amazonaws.com/audio?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig' } } }) as T;
    } };
    const result = await getRecordingMedia(client, 'conversation', 'recording', async () => undefined);
    expect(requested).toHaveLength(4);
    expect(requested[1]).toBe('/api/v2/conversations/conversation/recordings');
    expect(requested.filter(endpoint => endpoint.includes('/recordings/recording?')).every(endpoint => endpoint.includes('formatId=WEBM'))).toBe(true);
    expect(result?.mediaUri).toContain('X-Amz-Signature=sig');
    let attempts = 0;
    const unavailableClient = { async get<T>(): Promise<T> { attempts++; return undefined as T; } };
    expect(await getRecordingMedia(unavailableClient, 'conversation', 'pending', async () => undefined)).toBeUndefined();
    expect(attempts).toBe(8);
  });

  it('uses the media URI from the matching recording list item when detail metadata has none', async () => {
    const requested: string[] = [];
    const client = { async get<T>(endpoint: string): Promise<T> {
      requested.push(endpoint);
      if (endpoint.endsWith('/recordings')) return [{ id: 'other-recording', mediaUris: { WEBM: { mediaUri: 'https://wrong.example/audio' } } }, { id: 'wanted-recording', mediaUris: { WEBM: { mediaUri: 'https://prod-recording-playback.s3.amazonaws.com/audio?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig' } } }] as T;
      return { id: 'wanted-recording', mediaUris: {} } as T;
    } };

    const result = await getRecordingMedia(client, 'conversation', 'wanted-recording', async () => undefined);
    expect(requested).toEqual([
      '/api/v2/conversations/conversation/recordings/wanted-recording?formatId=WEBM&download=true',
      '/api/v2/conversations/conversation/recordings',
    ]);
    expect(result?.metadata.id).toBe('wanted-recording');
    expect(result?.mediaUri).toContain('X-Amz-Signature=sig');
  });

  it('does not attempt archive restoration for an AVAILABLE recording with no media URI', async () => {
    const requested: string[] = [];
    const recording = { id: 'available-recording', media: 'audio', fileState: 'AVAILABLE', mediaUris: {} };
    const client = { async get<T>(endpoint: string): Promise<T> {
      requested.push(endpoint);
      return (endpoint.endsWith('/recordings') ? [recording] : recording) as T;
    } };

    await expect(getRecordingMedia(client, 'conversation', recording.id, async () => undefined)).resolves.toBeUndefined();
    expect(requested.some(endpoint => endpoint.endsWith('/restore'))).toBe(false);
    expect(requested).toHaveLength(8);
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
    expect(isVoiceRecording({ mediaType: 'voice' })).toBe(true);
    expect(isVoiceRecording({ mediaType: 'VOICE' })).toBe(true);
    expect(isVoiceRecording({ mediaType: 'message' })).toBe(false);
    expect(isVoiceRecording({ media: 'voice' })).toBe(false);
    const voiceConversation={participants:[{sessions:[{mediaType:'voice'}]}]};
    const messageConversation={participants:[{sessions:[{mediaType:'message'}]}]};
    expect(conversationHasVoiceSession(voiceConversation)).toBe(true);
    expect(conversationHasVoiceSession(messageConversation)).toBe(false);
    expect(isVoiceRecording({media:'audio'},voiceConversation)).toBe(true);
    expect(isVoiceRecording({mediaType:'voice',media:'message'},voiceConversation)).toBe(false);
    expect(isVoiceRecording({media:'message'},voiceConversation)).toBe(false);
    expect(isVoiceRecording({media:'audio'},messageConversation)).toBe(false);
    expect(isVoiceRecording({media:'audio'})).toBe(false);
  });

  it('keeps only voice media in the synthetic recording fixtures', () => {
    const mediaTypes = Object.values(MOCK_RECORDINGS).flatMap(items => (items as {mediaType:string}[]).filter(isVoiceRecording).map(item => item.mediaType));
    expect(mediaTypes.length).toBeGreaterThan(0);
    expect(mediaTypes.every(mediaType => mediaType === 'voice')).toBe(true);
    expect(Object.values(MOCK_RECORDINGS).some(items => (items as {mediaType:string}[]).some(item => item.mediaType === 'message'))).toBe(true);
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
