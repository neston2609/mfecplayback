import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deflateRawSync } from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_REGIONS, trustedBaseUrl, validateRegionEndpoints } from '../regions.js';
import { encrypt, decrypt } from '../security.js';
import { MOCK_CONVERSATIONS, MOCK_RECORDINGS } from '../mock.js';
import { GenesysClient, GenesysError, verifyGenesysApiAccess } from '../genesys-client.js';
import { queryAllConversations, VOICE_RECORDING_FILTERS } from '../conversation-query.js';
import { archivedConversationDisplay, collectQueueIds, conversationQueueNames, conversationWrapUpCodeNames, participantLines, summarizeConversation, withParticipantLines } from '../conversation-summary.js';
import { conversationHasVoiceSession, getRecordingMedia, isMessageRecording, isVoiceInteraction, isVoiceRecording, isZipMediaContentType, listVoiceRecordings, recordingMediaRequestPath, recordingMetadataRequestPath, recordingMediaUriForFormats, validateRecordingMediaUrl } from '../recording-media.js';
import { extractSingleAudioFromZip } from '../zip-audio.js';
import { conversationCommunicationIds, normalizeTranscriptionError, transcriptionRequestPath, validateTranscriptUrl } from '../transcription.js';
import { collectAfterCallNotes, collectWrapUpCodeIds, withWrapUpCodeNames } from '../wrapup.js';
import { aiConversationSummaryPath, analyticsConversationDetailsPath, avaConversationSummaryPath, fetchConversationSummaryArtifacts, transcriptSearchCommunicationIds, transcriptSearchPath, transcriptSearchRequest } from '../conversation-artifacts.js';
import { checkPasswordPolicy, isPasswordPolicySatisfied } from '../password-policy.js';
import { parseSmtpSettings, publicSmtpSettings } from '../mailer.js';
import { DEFAULT_RECORDING_OUTPUT_FORMAT, ffmpegArguments, minimumExpectedAudioDurationMs, parseRecordingOutputFormat, preferredGenesysInputFormat, recordingOutputInfo, transcodeRecordingAudio, RECORDING_OUTPUT_FORMATS } from '../audio-transcode.js';
import { groupMemberUserIds, searchDirectory } from '../genesys-directory.js';
import { conversationHasPhoneMatch, normalizePhoneSearch, phoneSearchMatches } from '../phone-search.js';
import { execFileSync } from 'node:child_process';
import { libraryTabFromPath, pathForLibraryTab } from '../../src/library-navigation.js';
import { mapParticipantUserNames, participantUserLookupId } from '../participant-users.js';
import { byteRangeStream, parseByteRange } from '../audio-range.js';
import { Readable } from 'node:stream';
import { initialArchiveCursor } from '../library-schedule.js';
import { fetchConversationTranscriptions } from '../conversation-transcription.js';
import { decryptS3Source, getS3RecordingAudio, normalizeExportMetadata, publicS3Source, s3SourceConfigJson, s3SourceSchema, searchS3Recordings } from '../s3-source.js';
import { isScreenRecording, listConversationRecordings, listPlayableRecordings, safeRecordingMetadata } from '../recording-media.js';
import { extractScreenTracksFromZip, screenTrackFromWebm } from '../screen-recording.js';
import { cacheScreenTracks, getCachedScreenTrack } from '../screen-cache.js';
import { tracksFromBytes } from '../screen-media.js';

describe('MFEC Recording Explorer security and synthetic fixtures', () => {
  beforeAll(() => { process.env.MASTER_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64'); });
  afterAll(() => { delete process.env.MASTER_ENCRYPTION_KEY; });

  it('encrypts AWS credentials at rest and excludes credential material from public source data',()=>{
    const parsed=s3SourceSchema.parse({name:'Cloud CX exports',bucket:'mfec-recordings-prod',region:'ap-southeast-1',prefix:'',organizationId:'org-123',accessKeyId:'AKIA_TEST',secretAccessKey:'secret-test-value',sessionToken:'token-test-value'});
    const config={...parsed,accessKeyId:parsed.accessKeyId!,secretAccessKey:parsed.secretAccessKey!};
    const encrypted=s3SourceConfigJson(config);
    expect(encrypted.accessKeyId).not.toContain(config.accessKeyId);
    expect(encrypted.secretAccessKey).not.toContain(config.secretAccessKey);
    expect(encrypted.sessionToken).not.toContain(config.sessionToken);
    const row={id:'source-1',name:config.name,bucket:config.bucket,region:config.region,prefix:config.prefix,organization_id:config.organizationId,genesys_connection_id:null,access_key_id_enc:encrypted.accessKeyId,secret_access_key_enc:encrypted.secretAccessKey,session_token_enc:encrypted.sessionToken,enabled:1,created_at:'now',updated_at:'now'};
    expect(decryptS3Source(row)).toMatchObject({accessKeyId:config.accessKeyId,secretAccessKey:config.secretAccessKey,sessionToken:config.sessionToken});
    const visible=publicS3Source(row);
    expect(visible).toMatchObject({id:'source-1',credentialsConfigured:true,hasSessionToken:true});
    expect(JSON.stringify(visible)).not.toContain('secret-test-value');
    expect(JSON.stringify(visible)).not.toContain('token-test-value');
  });

  it('validates the configured AWS source fields and rejects unsafe bucket prefixes',()=>{
    expect(s3SourceSchema.safeParse({name:'S3',bucket:'valid-bucket-1',region:'ap-southeast-1',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'}).success).toBe(true);
    expect(s3SourceSchema.safeParse({name:'S3',bucket:'Bad_Bucket',region:'ap-southeast-1',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'}).success).toBe(false);
    expect(s3SourceSchema.safeParse({name:'S3',bucket:'valid-bucket-1',region:'ap-southeast-1',organizationId:'org-123',prefix:'recordings/../private',accessKeyId:'key',secretAccessKey:'secret'}).success).toBe(false);
  });

  it('normalizes Genesys export metadata and verifies voice fields and the storage path date',()=>{
    const parsed=s3SourceSchema.parse({name:'Archive',bucket:'mfec-genesys-exports',region:'ap-southeast-1',prefix:'exports',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'});
    const config={...parsed,accessKeyId:parsed.accessKeyId!,secretAccessKey:parsed.secretAccessKey!};
    const key='exports/org-123/year=2026/month=11/day=23/hour=10/conversation_id=conv-1/recording-1_metadata.json';
    const normalized=normalizeExportMetadata({organizationId:'org-123',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z',durationMs:8250,initialDirection:'inbound',ani:'+6620000000',dnis:'020000000',userIds:['agent-1'],queueIds:['queue-1'],wrapUpCodeIds:['wrap-1'],mediaType:'voice'},key,config);
    expect(normalized).toMatchObject({conversationId:'conv-1',conversationStart:'2026-11-23T10:14:00.000Z',direction:'inbound',ani:'+6620000000',dnis:'020000000',agents:['agent-1'],queues:['queue-1'],wrapUp:'wrap-1',recordingCount:1,recordings:[{id:'recording-1',durationMs:8250,metadataKey:key,hasMedia:true}]});
    const numericMetadata=normalizeExportMetadata({organizationId:'org-123',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z',durationMs:0,mediaType:'voice'},key,config);
    expect(numericMetadata?.durationSeconds).toBe(0);
    expect(normalizeExportMetadata({conversationId:'conv-1',recordingId:'recording-1',mediaType:'chat',startTime:'2026-11-23T10:14:00.000Z'},key,config)).toBeUndefined();
    expect(normalizeExportMetadata({conversationId:'conv-1',recordingId:'recording-1',mediaType:'recording',startTime:'2026-11-23T10:14:00.000Z'},key,config)).toMatchObject({recordingCount:1});
    expect(normalizeExportMetadata({conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z'},'outside/recording-1_metadata.json',config)).toBeUndefined();
    expect(normalizeExportMetadata({organizationId:'other-org',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z'},key,config)).toBeUndefined();
    expect(normalizeExportMetadata({organizationId:'org-123',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z'},'exports/org-123/year=2026/month=11/day=22/hour=10/conversation_id=conv-1/recording-1_metadata.json',config)).toBeUndefined();
    expect(normalizeExportMetadata({organizationId:'org-123',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z'},'exports/org-123/year=2026/month=11/day=32/hour=10/conversation_id=conv-1/recording-1_metadata.json',config)).toBeUndefined();
    expect(normalizeExportMetadata({organizationId:'org-123',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z'},'exports/org-123/year=2026/month=11/day=23/hour=10/conversation_id=another-conversation/recording-1_metadata.json',config)).toBeUndefined();
  });

  it('discovers screen recordings without weakening voice verification or leaking media URIs',async()=>{
    const signed='https://media.usw2.pure.cloud/secure?token=never-expose',conversation={participants:[{sessions:[{mediaType:'voice'}]}]},client={async get<T>(){return [{id:'voice-1',media:'audio',mediaType:'voice',mediaUris:{WEBM:{mediaUri:signed}}},{id:'screen-1',mediaType:'screenRecording',mediaUris:{WEBM:{mediaUri:signed}}},{id:'chat-1',mediaType:'chat',mediaUris:{WEBM:{mediaUri:signed}}}] as T;}};
    const items=await listConversationRecordings(client,'conversation'),playable=listPlayableRecordings(items,conversation);
    expect(playable.map(item=>item.id)).toEqual(['voice-1','screen-1']);
    expect(isScreenRecording(items[1])).toBe(true);
    const publicRows=playable.map(item=>safeRecordingMetadata(item,conversation));
    expect(JSON.stringify(publicRows)).not.toContain('mediaUri');
    expect(JSON.stringify(publicRows)).not.toContain('never-expose');
  });

  it('extracts several validated WebM monitor tracks and rejects unsafe or tampered ZIPs',()=>{
    const first=Buffer.from([0x1a,0x45,0xdf,0xa3,1,2]),second=Buffer.from([0x1a,0x45,0xdf,0xa3,3,4]);
    const tracks=extractScreenTracksFromZip(makeZip([{name:'screenRecordingId/Monitor 1.webm',data:first},{name:'screenRecordingId/Monitor 2.webm',data:second},{name:'readme.txt',data:Buffer.from('ignored')} ]));
    expect(tracks.map(track=>track.name)).toEqual(['Monitor 1.webm','Monitor 2.webm']);expect(tracks.map(track=>track.bytes)).toEqual([first,second]);
    expect(tracksFromBytes(makeZip([{name:'Monitor.webm',data:first}]))).toHaveLength(1);
    expect(screenTrackFromWebm(first).mimeType).toBe('video/webm');
    expect(()=>extractScreenTracksFromZip(makeZip([{name:'../secret.webm',data:first}]))).toThrow(/unsafe file name/);
    const corrupt=makeZip([{name:'Monitor.webm',data:first}]);corrupt[31]^=1;expect(()=>extractScreenTracksFromZip(corrupt)).toThrow();
    expect(()=>screenTrackFromWebm(Buffer.from('not WebM'))).toThrow(/not a supported WebM/);
  });

  it('scopes temporary screen playback cache entries to the authenticated owner',()=>{
    const track=screenTrackFromWebm(Buffer.from([0x1a,0x45,0xdf,0xa3,1]),'monitor.webm'),id=cacheScreenTracks('user-a',[track]);
    expect(id).toBeTruthy();expect(getCachedScreenTrack(id!,'user-a','0')?.name).toBe('monitor.webm');expect(getCachedScreenTrack(id!,'user-b','0')).toBeUndefined();
  });

  it('supports region-valid AWS S3 buckets that contain adjacent dots',()=>{
    expect(s3SourceSchema.safeParse({name:'S3',bucket:'a.b-recordings',region:'ap-southeast-1',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'}).success).toBe(true);
    expect(s3SourceSchema.safeParse({name:'S3',bucket:'ab..cd',region:'ap-southeast-1',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'}).success).toBe(false);
    expect(s3SourceSchema.safeParse({name:'S3',bucket:'999.1.1.1',region:'ap-southeast-1',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'}).success).toBe(false);
  });

  it('searches only configured organization metadata and applies exported metadata filters',async()=>{
    const parsed=s3SourceSchema.parse({name:'Archive',bucket:'mfec-genesys-exports',region:'ap-southeast-1',prefix:'exports',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'});
    const config={...parsed,accessKeyId:parsed.accessKeyId!,secretAccessKey:parsed.secretAccessKey!};
    const key='exports/org-123/year=2026/month=11/day=23/hour=10/conversation_id=conv-1/recording-1_metadata.json';
    const metadata={organizationId:'org-123',conversationId:'conv-1',recordingId:'recording-1',startTime:'2026-11-23T10:14:00.000Z',mediaType:'voice',agents:['Nicha S.'],queueNames:['Customer Care'],ani:'+6620000000'};
    const requests:any[]=[];
    const client={send:async(command:any)=>{requests.push(command.input);if(command.constructor.name==='ListObjectsV2Command')return {Contents:[{Key:key,Size:JSON.stringify(metadata).length}]};if(command.constructor.name==='GetObjectCommand')return {Body:Readable.from([Buffer.from(JSON.stringify(metadata))])};throw new Error('Unexpected S3 command.');},destroy(){}};
    const result=await searchS3Recordings(config,{start:'2026-11-23T00:00:00.000Z',end:'2026-11-24T00:00:00.000Z',agentName:'nicha',queueName:'care',phone:'+6620000000',pageNumber:1,pageSize:25},()=>client as any);
    expect(result.results).toHaveLength(1);
    expect(result.results[0]).toMatchObject({conversationId:'conv-1',agents:['Nicha S.'],queues:['Customer Care']});
    expect(requests[0].Prefix).toBe('exports/org-123/year=2026/month=11/day=23/');
  });

  it('retrieves only a requested AWS S3 audio byte range and reports range headers',async()=>{
    const parsed=s3SourceSchema.parse({name:'Archive',bucket:'mfec-genesys-exports',region:'ap-southeast-1',organizationId:'org-123',accessKeyId:'key',secretAccessKey:'secret'});
    const config={...parsed,accessKeyId:parsed.accessKeyId!,secretAccessKey:parsed.secretAccessKey!},requests:any[]=[];
    const client={send:async(command:any)=>{requests.push(command.input);if(command.constructor.name==='HeadObjectCommand')return {ContentLength:10,ContentType:'audio/ogg'};return {Body:Readable.from([Buffer.from('234')]),ContentLength:3,ContentRange:'bytes 2-4/10'};},destroy(){}};
    const result=await getS3RecordingAudio(config,'org-123/year=2026/month=11/day=23/hour=10/conversation_id=conv-1/recording-1.opus','bytes=2-4',()=>client as any);
    expect('invalidRange' in result).toBe(false);
    if(!('invalidRange' in result)){
      expect(result.status).toBe(206);
      expect(result.range).toBe('bytes 2-4/10');
      expect(result.contentType).toBe('audio/ogg');
      expect(requests[1].Range).toBe('bytes=2-4');
      const chunks:Buffer[]=[];for await(const chunk of result.body as AsyncIterable<Uint8Array>)chunks.push(Buffer.from(chunk));
      expect(Buffer.concat(chunks)).toEqual(Buffer.from('234'));
      result.close();
    }
  });

  it('loads a bounded transcript via validated Genesys transcript storage URLs',async()=>{
    const connection={api_base_url:'https://api.usw2.pure.cloud'},conversation={conversationId:'conversation-1',participants:[{sessions:[{mediaType:'voice',sessionId:'communication-1'}]}]},client={post:async()=>({}),get:async(path:string)=>path.includes('transcripturl')?{url:'https://transcripts.s3.amazonaws.com/transcript.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600'}:{}};
    const transcript=await fetchConversationTranscriptions(client as any,connection,'conversation-1',conversation,async()=>new Response(JSON.stringify({utterances:[{text:'hello'}]}),{status:200,headers:{'content-type':'application/json'}}));
    expect(transcript).toEqual([{communicationId:'communication-1',transcript:{utterances:[{text:'hello'}]}}]);
  });

  it('parses valid, suffix, clamped and unsatisfiable audio byte ranges', () => {
    expect(parseByteRange(undefined, 10)).toBeUndefined();
    expect(parseByteRange('bytes=2-5', 10)).toEqual({ start: 2, end: 5 });
    expect(parseByteRange('bytes=7-', 10)).toEqual({ start: 7, end: 9 });
    expect(parseByteRange('bytes=-4', 10)).toEqual({ start: 6, end: 9 });
    expect(parseByteRange('bytes=8-99', 10)).toEqual({ start: 8, end: 9 });
    expect(parseByteRange('bytes=10-', 10)).toBe('unsatisfiable');
    expect(parseByteRange('bytes=4-2', 10)).toBe('unsatisfiable');
    expect(parseByteRange('bytes=1-2,4-5', 10)).toBe('invalid');
  });

  it('limits first archive backfill cursor to the configured lookback days',()=>{
    const now=new Date('2026-11-20T15:00:00.000Z');
    expect(initialArchiveCursor(now,30)).toBe('2026-10-21T00:00:00.000Z');
    expect(initialArchiveCursor(now,900)).toBe(initialArchiveCursor(now,550));
  });

  it('streams only the requested byte interval from destinations without native range reads', async () => {
    const chunks: Buffer[] = [];
    for await (const chunk of byteRangeStream(Readable.from([Buffer.from('abc'), Buffer.from('defg')]), { start: 2, end: 5 })) {
      chunks.push(Buffer.from(chunk));
    }
    expect(Buffer.concat(chunks).toString()).toBe('cdef');
  });

  it('maps Sound Library routes and tabs in both directions',()=>{
    expect(libraryTabFromPath('/library')).toBe('library');
    expect(libraryTabFromPath('/library/schedules')).toBe('schedules');
    expect(libraryTabFromPath('/library/worker')).toBe('worker');
    expect(libraryTabFromPath('/library/settings')).toBe('settings');
    expect(pathForLibraryTab('library')).toBe('/library');
    expect(pathForLibraryTab('schedules')).toBe('/library/schedules');
    expect(pathForLibraryTab('worker')).toBe('/library/worker');
    expect(pathForLibraryTab('settings')).toBe('/library/settings');
  });

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

  it('uses DNIS as the visible direction number for inbound calls',()=>{
    const conversation={conversationId:'inbound-number',originatingDirection:'inbound',participants:[
      {purpose:'customer',sessions:[{ani:'tel:+66812345678',dnis:'tel:+6621112222'}]},
      {purpose:'agent',sessions:[{ani:'tel:+66999999999',dnis:'tel:+6621112222'}]},
    ]};
    const result=summarizeConversation(conversation);
    expect(result).toMatchObject({direction:'inbound',ani:'+66812345678',dnis:'+6621112222'});
    expect(archivedConversationDisplay({conversation:result})).toMatchObject({direction:'inbound',ani:'+66812345678'});
  });

  it('does not treat generic agent labels as real names and resolves the session user ID',()=>{
    const conversation={conversationId:'session-agent',conversationStart:'2026-11-19T00:00:00.000Z',conversationEnd:'2026-11-19T00:01:00.000Z',participants:[{purpose:'agent',participantName:'Agent',sessions:[{userId:'session-user-id'}]}]};
    expect(summarizeConversation(conversation).agents).toEqual([]);
    expect(summarizeConversation(conversation,{'session-user-id':'Real Agent Name'}).agents).toEqual(['Real Agent Name']);
    expect(participantUserLookupId(conversation.participants[0])).toBe('session-user-id');
  });

  it('prepares archived conversation display values from resolved metadata without showing raw IDs',()=>{
    expect(archivedConversationDisplay({conversation:{agents:['Agent Name'],flows:['Flow Name'],queues:['Queue Name'],interactionType:'Bot to Agent',durationSeconds:null},participants:[{purpose:'agent',participantName:'10000000-0000-4000-8000-000000000001'}]},95000))
      .toEqual({agents:['Agent Name'],flows:['Flow Name'],queues:['Queue Name'],interactionType:'Bot to Agent',direction:'',callbackNumber:'',ani:'',dnis:'',durationSeconds:95});
  });

  it('provides the outbound callback number for display in the Direction column',()=>{
    const result=summarizeConversation({conversationId:'outbound-callback',originatingDirection:'outbound',participants:[
      {purpose:'customer',sessions:[{ani:'sip:route@localhost',callbackNumbers:['tel:+66812345678']}]},
      {purpose:'agent',sessions:[{callbackNumbers:['+66999999999']}]},
    ]});
    expect(result).toMatchObject({direction:'outbound',callbackNumber:'+66812345678',ani:''});
    expect(archivedConversationDisplay({conversation:result})).toMatchObject({direction:'outbound',callbackNumber:'+66812345678'});
    const inbound=summarizeConversation({conversationId:'inbound-callback',originatingDirection:'inbound',participants:[{purpose:'customer',sessions:[{ani:'tel:+66887654321',dnis:'tel:+6621112222'}]}]});
    expect(archivedConversationDisplay({conversation:inbound}).ani).toBe('+66887654321');
  });

  it('includes transferred ACD queues and only readable wrap-up code names in the overview',()=>{
    const wrapUpId='2816e6e2-0c0b-4a90-a147-61e20f80435d';
    const conversation={participants:[
      {purpose:'acd',participantName:'Customer Care',sessions:[{segments:[]}]},
      {purpose:'agent',participantName:'Agent A',sessions:[{segments:[{wrapUpCode:wrapUpId,wrapUpCodeName:'Issue Resolved'}]}]},
      {purpose:'agent',sessions:[{segments:[{wrapUpCode:'748a0ed1-839f-48e7-b328-fd769f10d54d'}]}]},
    ]};
    expect(conversationQueueNames(conversation)).toEqual(['Customer Care']);
    expect(conversationWrapUpCodeNames(conversation)).toEqual(['Issue Resolved']);
    expect(summarizeConversation(conversation).wrapUp).toBe('Issue Resolved');
    const queueId='eb13c121-2f73-4f10-b8da-3a550b0b4d29';
    const transfer={participants:[{purpose:'acd',sessions:[{queueId}]}]};
    expect(collectQueueIds(transfer)).toEqual([queueId]);
    expect(conversationQueueNames(transfer,{[queueId]:'Customer Care'})).toEqual(['Customer Care']);
    expect(conversationQueueNames(transfer)).toEqual([]);
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

  it('resolves user-purpose participants by participantId like Genesys agents',async()=>{
    const queried:string[]=[];
    const conversation={participants:[
      {purpose:'user',participantId:'genesys-user-id',participantName:'genesys-user-id'},
      {purpose:'agent',participantId:'agent-participant-id',userId:'genesys-agent-id',participantName:'genesys-agent-id'},
      {purpose:'customer',participantId:'customer-id',participantName:'Customer'},
    ]};
    const named=await mapParticipantUserNames({async get<T>(url:string):Promise<T>{queried.push(url);const id=decodeURIComponent(url.split('/').pop()||'');return ({name:id==='genesys-user-id'?'User Name':'Agent Name'} as T);}},conversation);
    expect(queried.sort()).toEqual(['/api/v2/users/genesys-agent-id','/api/v2/users/genesys-user-id'].sort());
    expect(named.participants.map((participant:any)=>participant.participantName)).toEqual(['User Name','Agent Name','Customer']);
    expect(withParticipantLines(named).participants.map((participant:any)=>participant.displayText)).toEqual(['User : User Name','Agent : Agent Name','Customer : — -> —']);
    expect(participantUserLookupId({purpose:'user',participantId:'user-p-1'})).toBe('user-p-1');
    expect(participantUserLookupId({purpose:'customer',participantId:'customer-p-1'})).toBe('');
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
      return (requested.filter(item => item.includes('/recordings/recording?')).length < 3 ? undefined : { mediaUris: { WEBM: { mediaUri: 'https://prod-recording-playback.s3.amazonaws.com/audio?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig' } } }) as T;
    } };
    const result = await getRecordingMedia(client, 'conversation', 'recording', async () => undefined);
    expect(requested).toHaveLength(4);
    expect(requested[1]).toBe('/api/v2/conversations/conversation/recordings');
    expect(requested.filter(endpoint => endpoint.includes('/recordings/recording?')).every(endpoint => endpoint.includes('formatId=WEBM'))).toBe(true);
    expect(result?.mediaUri).toContain('X-Amz-Signature=sig');
    const explicitFormat = await getRecordingMedia({ async get<T>(endpoint:string):Promise<T>{return ({mediaUris:{WEBM:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/webm?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'},MP3:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/mp3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'}}} as T);}},'conversation','recording',undefined,'MP3');
    expect(explicitFormat?.mediaUri).toContain('/mp3?');
    const strict = await getRecordingMedia({ async get<T>(endpoint:string):Promise<T>{return (endpoint.endsWith('/recordings') ? [{id:'strict-recording',mediaUris:{WEBM:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/webm?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'},MP3:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/mp3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'}}}] : {mediaUris:{}}) as T;}},'conversation','strict-recording',async()=>undefined,'MP3');
    expect(strict?.mediaUri).toContain('/mp3?');
    const mismatch = await getRecordingMedia({ async get<T>(endpoint:string):Promise<T>{return (endpoint.endsWith('/recordings') ? [{id:'strict-recording',mediaUris:{WEBM:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/webm?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'}}}] : {mediaUris:{}}) as T;}},'conversation','strict-recording',async()=>undefined,'MP3');
    expect(mismatch).toBeUndefined();
    const alternateFormat = await getRecordingMedia({ async get<T>():Promise<T>{return {mediaUris:{FLAC:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/flac?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'},MP3:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/mp3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'}}} as T;}},'conversation','alternate-recording',async()=>undefined,'WEBM',['WEBM','MP3','WAV'],false);
    expect(alternateFormat?.mediaUri).toContain('/mp3?');
    expect(recordingMediaUriForFormats({mediaUris:{FLAC:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/flac'},WAV:{mediaUri:'https://prod-recording-playback.s3.amazonaws.com/wav'}}},['WEBM','MP3','WAV'])).toContain('/wav');
    expect(recordingMediaUriForFormats({mediaUri:'https://prod-recording-playback.s3.amazonaws.com/unknown'},['WEBM','MP3','WAV'])).toBeUndefined();
    const formatless = await getRecordingMedia({ async get<T>(endpoint:string):Promise<T>{return (endpoint.endsWith('/recordings') ? [{id:'strict-recording',mediaUri:'https://prod-recording-playback.s3.amazonaws.com/unknown?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600&X-Amz-Signature=sig'}] : {mediaUris:{}}) as T;}},'conversation','strict-recording',async()=>undefined,'MP3');
    expect(formatless).toBeUndefined();
    let attempts = 0;
    const unavailableClient = { async get<T>(): Promise<T> { attempts++; return undefined as T; } };
    expect(await getRecordingMedia(unavailableClient, 'conversation', 'pending', async () => undefined)).toBeUndefined();
    expect(attempts).toBe(8);
  });

  it('accepts Genesys signed media returned under an opaque single format key when a format was requested', async () => {
    const requested:string[]=[];
    const signedMediaUri='https://api-downloads.apse1.pure.cloud/download?expires=123&signature=opaque&token=media';
    const client={async get<T>(endpoint:string):Promise<T>{requested.push(endpoint);return {id:'recording',fileState:'AVAILABLE',mediaUris:{S:{mediaUri:signedMediaUri}}} as T;}};
    await expect(getRecordingMedia(client,'conversation','recording',async()=>undefined,'WEBM',[],false)).resolves.toBeUndefined();
    requested.length=0;
    const playable=await getRecordingMedia(client,'conversation','recording',async()=>undefined,'WEBM',[],true);
    expect(playable).toMatchObject({mediaUri:signedMediaUri,metadata:{id:'recording',fileState:'AVAILABLE'}});
    expect(requested).toEqual(['/api/v2/conversations/conversation/recordings/recording?formatId=WEBM&download=true']);
  });

  it('converts recordings to the configured audio-only format with bounded input and output', async () => {
    expect(DEFAULT_RECORDING_OUTPUT_FORMAT).toBe('m4a');
    expect(preferredGenesysInputFormat('m4a')).toBe('WEBM');
    expect(preferredGenesysInputFormat('mp3')).toBe('MP3');
    expect(recordingOutputInfo('m4a')).toEqual({extension:'m4a',mimeType:'audio/mp4'});
    expect(ffmpegArguments('mp4')).toContain('pipe:0');
    expect(ffmpegArguments('mp4')).toContain('-vn');
    expect(ffmpegArguments('m4a')).toContain('-xerror');
    expect(ffmpegArguments('m4a')).toContain('aac');
    expect(ffmpegArguments('mp3')).toContain('libmp3lame');
    for(const format of RECORDING_OUTPUT_FORMATS)expect(ffmpegArguments(format)).toContain('-vn');
    const input=Buffer.from('synthetic audio bytes');let invoked=false;
    let runnerCalls=0;
    const output=await transcodeRecordingAudio(input,'m4a',async(bytes,args)=>{runnerCalls++;invoked=true;expect(args).toContain('-vn');if(runnerCalls===1){expect(bytes).toEqual(input);return Buffer.from('converted m4a');}expect(bytes).toEqual(Buffer.from('converted m4a'));expect(args).toContain('-xerror');expect(args).toContain('-f');return Buffer.alloc(0);});
    expect(invoked).toBe(true);
    expect(output).toMatchObject({bytes:Buffer.from('converted m4a'),format:'m4a',extension:'m4a',mimeType:'audio/mp4'});
    await expect(transcodeRecordingAudio(input,'flac',async()=>Buffer.from('x'))).rejects.toThrow(/supported recording output format/i);
    let invalidOutputCalls=0;
    await expect(transcodeRecordingAudio(input,'mp3',async()=>++invalidOutputCalls===1?Buffer.from('not actually audio'):Promise.reject(new Error('decoder rejected output')))).rejects.toThrow(/integrity validation/i);
    await expect(transcodeRecordingAudio(input,'mp3',async()=>Buffer.alloc(0))).rejects.toThrow(/empty/i);
  });

  it('sets a conservative minimum expected audio duration threshold',()=>{
    expect(minimumExpectedAudioDurationMs(0)).toBe(0);
    expect(minimumExpectedAudioDurationMs(400)).toBe(250);
    expect(minimumExpectedAudioDurationMs(30_000)).toBe(3000);
  });

  it('searches directory names and reads members for a selected Genesys group',async()=>{
    const calls:string[]=[];
    const client={
      async post<T>(endpoint:string,body:any):Promise<T>{calls.push(endpoint);expect(body.query[0]).toMatchObject({type:'CONTAINS',fields:['name'],value:'Nicha'});return {results:[{id:'agent-1',name:'Nicha S.'}]} as T;},
      async get<T>(endpoint:string):Promise<T>{calls.push(endpoint);if(endpoint.startsWith('/api/v2/routing/queues?'))return {entities:[{id:'queue-1',name:'Customer Care'}]} as T;return {entities:[{id:'agent-1'}],total:1} as T;},
    };
    await expect(searchDirectory(client as any,'agent','Nicha')).resolves.toEqual([{id:'agent-1',name:'Nicha S.'}]);
    await expect(searchDirectory(client as any,'queue','Customer')).resolves.toEqual([{id:'queue-1',name:'Customer Care'}]);
    await expect(groupMemberUserIds(client as any,'group-1')).resolves.toEqual(new Set(['agent-1']));
    expect(calls).toEqual(['/api/v2/users/search','/api/v2/routing/queues?name=*Customer*&pageSize=100&pageNumber=1','/api/v2/groups/group-1/members?pageSize=100&pageNumber=1']);
  });

  it('matches Thai phone numbers across local and international formats',()=>{
    const formats=['0652936493','66652936493','+66652936493','0066652936493','065-293-6493'];
    expect(formats.map(normalizePhoneSearch)).toEqual(Array(formats.length).fill('0652936493'));
    for(const query of formats)for(const stored of formats)expect(phoneSearchMatches(stored,query)).toBe(true);
    const conversation={participants:[{sessions:[{ani:'+66652936493',dnis:'+6621000101'}]}]};
    expect(conversationHasPhoneMatch(conversation,'0652936493','phone')).toBe(true);
    expect(conversationHasPhoneMatch(conversation,'021000101','dnis')).toBe(true);
    expect(conversationHasPhoneMatch(conversation,'0652936493','dnis')).toBe(false);
    expect(phoneSearchMatches('+6621000101','021000101')).toBe(true);
    expect(phoneSearchMatches('sip:0652936493@genesys.example','0652936493')).toBe(false);
    expect(phoneSearchMatches('+14155552671','0652936493')).toBe(false);
  });

  it.skipIf(!process.env.FFMPEG_PATH)('transcodes real audio into every supported audio-only container', async () => {
    const ffmpeg=process.env.FFMPEG_PATH!,ffprobe=ffmpeg.replace(/ffmpeg(?:\.exe)?$/i,match=>match.toLowerCase().endsWith('.exe')?'ffprobe.exe':'ffprobe');
    const fixture=path.join(os.tmpdir(),`mfec-transcode-${process.pid}.wav`);
    try{
      execFileSync(ffmpeg,['-hide_banner','-loglevel','error','-f','lavfi','-i','sine=frequency=1000:duration=0.2','-c:a','pcm_s16le','-ar','8000','-ac','1','-y',fixture]);
      const input=fs.readFileSync(fixture);
      for(const format of RECORDING_OUTPUT_FORMATS){
        const converted=await transcodeRecordingAudio(input,format);
        const convertedPath=path.join(os.tmpdir(),`mfec-converted-${process.pid}-${format}.${format.startsWith('ogg_')?'ogg':format==='wav_ulaw'?'wav':format}`);
        try{
          fs.writeFileSync(convertedPath,converted.bytes);
          const probe=JSON.parse(execFileSync(ffprobe,['-v','error','-show_entries','stream=codec_type,codec_name:format=format_name','-of','json',convertedPath],{encoding:'utf8'}));
          expect(probe.streams).toHaveLength(1);
          expect(probe.streams[0].codec_type).toBe('audio');
          expect(probe.streams[0].codec_name).toBe(format==='m4a'||format==='mp4'?'aac':format==='mp3'?'mp3':format==='webm'?'opus':format==='ogg_opus'?'opus':format==='ogg_vorbis'?'vorbis':format==='wav_ulaw'?'pcm_mulaw':'pcm_s16le');
          expect(converted.bytes.length).toBeGreaterThan(0);
        }finally{fs.rmSync(convertedPath,{force:true});}
      }
    }finally{fs.rmSync(fixture,{force:true});}
  },60_000);

  it.skipIf(!process.env.FFMPEG_PATH)('rejects converted audio that is much shorter than the Genesys recording metadata', async () => {
    const ffmpeg=process.env.FFMPEG_PATH!;
    const fixture=path.join(os.tmpdir(),`mfec-short-audio-${process.pid}.wav`);
    try{
      execFileSync(ffmpeg,['-hide_banner','-loglevel','error','-f','lavfi','-i','sine=frequency=1000:duration=0.25','-c:a','pcm_s16le','-ar','8000','-ac','1','-y',fixture]);
      await expect(transcodeRecordingAudio(fs.readFileSync(fixture),'m4a',undefined,30_000)).rejects.toThrow(/unexpectedly short recording/i);
    }finally{fs.rmSync(fixture,{force:true});}
  },30_000);

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
    const connection={api_base_url:'https://api.apse1.pure.cloud'};
    const good='https://genesys-transcripts.s3.amazonaws.com/file.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600';
    const regional='https://api-downloads.apse1.pure.cloud/transcriptsCache/example.json?Expires=1790000000&Signature=signature&Key-Pair-Id=key';
    const regionalCustomPolicy='https://api-downloads.apse1.pure.cloud/transcriptsCache/example.json?Policy=policy&Signature=signature&Key-Pair-Id=key';
    expect(validateTranscriptUrl(good,connection).hostname).toBe('genesys-transcripts.s3.amazonaws.com');
    expect(validateTranscriptUrl(regional,connection).hostname).toBe('api-downloads.apse1.pure.cloud');
    expect(validateTranscriptUrl(regionalCustomPolicy,connection).hostname).toBe('api-downloads.apse1.pure.cloud');
    expect(()=>validateTranscriptUrl('https://attacker.example/file.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600',connection)).toThrow(/untrusted/i);
    expect(()=>validateTranscriptUrl('https://api-downloads.mypurecloud.com/transcriptsCache/example.json?Policy=policy&Signature=signature&Key-Pair-Id=key',connection)).toThrow(/untrusted/i);
    expect(()=>validateTranscriptUrl('https://api-downloads.apse1.pure.cloud/other/example.json?Policy=policy&Signature=signature&Key-Pair-Id=key',connection)).toThrow(/untrusted/i);
    expect(()=>validateTranscriptUrl('https://api-downloads.apse1.pure.cloud/transcriptsCache/example.json',connection)).toThrow(/untrusted/i);
    expect(()=>validateTranscriptUrl('http://genesys-transcripts.s3.amazonaws.com/file.json?X-Amz-Signature=sig&X-Amz-Credential=credential&X-Amz-Date=20261118T000000Z&X-Amz-Expires=600',connection)).toThrow(/untrusted/i);
    expect(()=>validateTranscriptUrl('invalid-url',connection)).toThrow(/invalid transcript URL/i);
    try{validateTranscriptUrl('invalid-url',connection);}catch(error){expect(error).toMatchObject({status:502});}
  });

  it('returns a safe actionable gateway error for transcription service failures',()=>{
    expect(normalizeTranscriptionError(new GenesysError(503,'Genesys API could not be reached.'))).toMatchObject({status:502,message:expect.stringContaining('Speech and Text Analytics')});
    const failedGenesysRequest=Object.assign(new Error('Genesys API request failed (HTTP 500).'),{status:500});
    expect(normalizeTranscriptionError(failedGenesysRequest)).toBe(failedGenesysRequest);
    const unavailable=Object.assign(new Error('Transcription is not available.'),{status:404});
    expect(normalizeTranscriptionError(unavailable)).toBe(unavailable);
  });

  it('builds the explicit Genesys summary, details, and transcript search API requests', () => {
    expect(analyticsConversationDetailsPath('conversation/id')).toBe('/api/v2/analytics/conversations/conversation%2Fid/details');
    expect(avaConversationSummaryPath('conversation/id')).toBe('/api/v2/conversations/conversation%2Fid/summaries');
    expect(aiConversationSummaryPath('conversation/id')).toBe('/api/v2/speechandtextanalytics/conversations/conversation%2Fid/summaries');
    expect(transcriptSearchPath()).toBe('/api/v2/speechandtextanalytics/transcripts/search');
    expect(transcriptSearchRequest('conversation-1')).toEqual({pageSize:100,pageNumber:1,types:['transcripts'],returnFields:['conversationId','communicationId'],query:[{type:'EXACT',fields:['conversationId'],value:'conversation-1'}]});
  });

  it('extracts only matching, bounded communication IDs from transcript search results', () => {
    expect(transcriptSearchCommunicationIds({results:[
      {conversationId:'conversation-1',communicationId:'voice-1'},
      {conversationId:'conversation-2',communicationId:'other-conversation'},
      {conversationId:'conversation-1',communicationId:'voice-1'},
      {conversationId:'conversation-1',communicationId:'x'.repeat(129)},
    ]},'conversation-1')).toEqual(['voice-1']);
    expect(transcriptSearchCommunicationIds({results:[{communicationId:'only-result'}]},'conversation-1')).toEqual(['only-result']);
    expect(transcriptSearchCommunicationIds({results:[{conversationId:'another-conversation',communicationId:'wrong'},{conversationId:'conversation-1',communicationId:'right'}]},'conversation-1')).toEqual(['right']);
    expect(transcriptSearchCommunicationIds({results:[{conversationId:'another-conversation',communicationId:'wrong'}]},'conversation-1')).toEqual([]);
  });

  it('loads AVA and AI summaries independently and tolerates unavailable summary endpoints', async () => {
    const calls:string[]=[];
    const client={get:async(path:string)=>{calls.push(path);if(path.includes('/speechandtextanalytics/'))return {entities:[{summary:'AI summary'}]};return {summary:'AVA summary',wrapUpCodes:['Auto wrap-up']};},post:async()=>undefined};
    await expect(fetchConversationSummaryArtifacts(client,'conversation-1')).resolves.toEqual({avaSummary:{summary:'AVA summary',wrapUpCodes:['Auto wrap-up']},aiSummary:{entities:[{summary:'AI summary'}]}});
    expect(calls).toEqual(['/api/v2/conversations/conversation-1/summaries','/api/v2/speechandtextanalytics/conversations/conversation-1/summaries']);
    const partialClient={get:async(path:string)=>{if(path.includes('/speechandtextanalytics/'))throw Object.assign(new Error('not found'),{status:404});return {summary:'AVA only'};},post:async()=>undefined};
    await expect(fetchConversationSummaryArtifacts(partialClient,'conversation-2')).resolves.toEqual({avaSummary:{summary:'AVA only'},aiSummary:null});
    const forbiddenClient={get:async()=>{throw Object.assign(new Error('forbidden'),{status:403});},post:async()=>undefined};
    await expect(fetchConversationSummaryArtifacts(forbiddenClient,'conversation-3')).rejects.toMatchObject({status:403});
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
