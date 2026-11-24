import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
let testDirectory = '';
let child: ChildProcess | undefined;
let baseUrl = '';
let cookie = '';
let csrf = '';
let serverOutput = '';
let ffmpegFixture = '';
let integrationDatabasePath='';

async function freePort() {
  const socket = net.createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const address = socket.address();
  if (!address || typeof address === 'string') throw new Error('Unable to reserve an API test port.');
  await new Promise<void>(resolve => socket.close(() => resolve()));
  return address.port;
}

async function waitForServer(url: string) {
  const deadline = Date.now() + 15_000;
  let lastError: unknown;
  while (Date.now() < deadline) {
    if (child?.exitCode !== null && child?.exitCode !== undefined) throw new Error(`API test server exited (${child.exitCode}).\n${serverOutput}`);
    try {
      const response = await fetch(`${url}/api/health`);
      if (response.ok) return;
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`API test server did not start: ${String(lastError)}\n${serverOutput}`);
}

async function request(route: string, init: RequestInit = {}, useCsrf = false) {
  const headers = new Headers(init.headers);
  if (cookie) headers.set('Cookie', cookie);
    if (useCsrf) headers.set('x-csrf-token', csrf);
    if (useCsrf) headers.set('Origin', 'http://localhost:5173');
  return fetch(`${baseUrl}${route}`, { ...init, headers });
}

async function requestAs(route:string,sessionCookie:string,init:RequestInit={}){
  const headers=new Headers(init.headers);headers.set('Cookie',sessionCookie);
  return fetch(`${baseUrl}${route}`,{...init,headers});
}

describe('HTTP API security and Mock Mode flows', () => {
  beforeAll(async () => {
    testDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'mfec-recording-explorer-test-'));
    if (process.env.FFMPEG_PATH) {
      ffmpegFixture = path.join(testDirectory, 'fixture.wav');
      execFileSync(process.env.FFMPEG_PATH, ['-hide_banner','-loglevel','error','-f','lavfi','-i','sine=frequency=440:duration=0.25','-c:a','pcm_s16le','-ar','8000','-ac','1','-y',ffmpegFixture]);
    }
    const port = await freePort();
    baseUrl = `http://127.0.0.1:${port}`;
    child = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
      cwd: root,
      env: {
        ...process.env,
        NODE_ENV: 'test', PORT: String(port), HOST: '127.0.0.1',
        APP_ORIGIN: 'http://localhost:5173', TRUST_PROXY: 'false', MOCK_MODE: 'true',
        SESSION_SECRET: 'integration-test-session-secret-with-sufficient-entropy',
        ...(process.env.FFMPEG_PATH ? { FFMPEG_PATH: process.env.FFMPEG_PATH } : {}),
        DATABASE_PATH: integrationDatabasePath=path.join(testDirectory, 'integration.sqlite'),
        LIBRARY_STORAGE_ROOT: path.join(testDirectory,'library-storage'),
        MASTER_ENCRYPTION_KEY: Buffer.alloc(32,17).toString('base64'),
        INITIAL_ADMIN_USERNAME: 'integration-admin', INITIAL_ADMIN_PASSWORD: 'Integration-Test-Password-456!',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout?.on('data', data => { serverOutput += String(data); });
    child.stderr?.on('data', data => { serverOutput += String(data); });
    await waitForServer(baseUrl);
  }, 25_000);

  afterAll(async () => {
    if (child && child.exitCode === null) {
      await fetch(`${baseUrl}/__test/shutdown`, { method: 'POST' }).catch(() => undefined);
      await new Promise<void>(resolve => child?.once('exit', () => resolve()));
    }
    if (testDirectory) await fs.rm(testDirectory, { recursive: true, force: true });
  }, 15_000);

  it('requires authentication, enforces login and CSRF, then returns explicitly synthetic results', async () => {
    const anonymous = await request('/api/genesys/connections');
    expect(anonymous.status).toBe(401);
    expect((await request('/api/library')).status).toBe(401);
    expect((await request('/api/library/destinations')).status).toBe(401);
    expect((await request('/api/library/worker-status')).status).toBe(401);
    expect((await request('/api/library/00000000-0000-4000-8000-000000000021/rearchive',{method:'POST'})).status).toBe(401);
    expect((await request('/api/playback-history')).status).toBe(401);
    expect((await request('/api/recordings/conversations/demo-ava-agent-001/summaries?connectionId=mock')).status).toBe(401);
    expect((await request('/api/recordings/conversations/demo-ava-agent-001/transcription?connectionId=mock')).status).toBe(401);
    const badLogin = await request('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'integration-admin', password: 'wrong password' }) });
    expect(badLogin.status).toBe(401);
    const login = await request('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'integration-admin', password: 'Integration-Test-Password-456!' }) });
    expect(login.status).toBe(200);
    const setCookie = login.headers.get('set-cookie') || '';
    cookie = setCookie.split(';', 1)[0];
    expect(cookie).toContain('mfec.recording.sid=');
    const auth = await login.json() as { csrfToken: string };
    csrf = auth.csrfToken;
    const playbackDb=new Database(integrationDatabasePath);
    const adminId=String((playbackDb.prepare("SELECT id FROM users WHERE username='integration-admin'").get() as {id:string}).id),playedAt=new Date().toISOString();
    playbackDb.prepare('INSERT INTO audit_logs(user_id,username,action,result,connection_id,conversation_id,recording_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(adminId,'integration-admin','PLAYBACK','SUCCESS','history-connection','history-conversation','history-recording',playedAt);
    playbackDb.prepare('INSERT INTO audit_logs(user_id,username,action,result,created_at) VALUES(?,?,?,?,?)').run(adminId,'integration-admin','LIBRARY_PLAYBACK','SUCCESS',playedAt);
    playbackDb.prepare('INSERT INTO audit_logs(user_id,username,action,result,created_at) VALUES(?,?,?,?,?)').run(adminId,'integration-admin','LOGIN','SUCCESS',playedAt);
    playbackDb.prepare('INSERT INTO audit_logs(user_id,username,action,result,created_at) VALUES(?,?,?,?,?)').run('another-user-id','another-user','PLAYBACK','SUCCESS',playedAt);
    const historyRow=playbackDb.prepare('INSERT INTO audit_logs(user_id,username,action,result,created_at) VALUES(?,?,?,?,?)');
    for(let index=0;index<15;index++)historyRow.run(adminId,'integration-admin','PLAYBACK','SUCCESS',new Date(Date.parse(playedAt)+index+1).toISOString());
    playbackDb.close();
    expect((await request('/api/playback-history')).status).toBe(200);
    const playbackHistory=await (await request('/api/playback-history')).json() as {items:{action:string;result:string;connectionId:string|null;conversationId:string|null;recordingId:string|null;playedBy:string;connectionName:string}[];total:number;page:number;pageSize:number;totalPages:number};
    expect(playbackHistory).toMatchObject({total:18,page:1,pageSize:15,totalPages:2});
    expect(playbackHistory.items).toHaveLength(15);
    const playbackHistoryPageTwo=await (await request('/api/playback-history?page=2')).json() as typeof playbackHistory;
    expect(playbackHistoryPageTwo.items.some(item=>item.playedBy==='another-user')).toBe(true);
    expect(playbackHistoryPageTwo.items.find(item=>item.connectionId==='history-connection')).toMatchObject({result:'SUCCESS',connectionName:'history-connection',playedBy:'integration-admin',conversationId:'history-conversation',recordingId:'history-recording'});
    expect(playbackHistoryPageTwo.items.find(item=>item.action==='LIBRARY_PLAYBACK')?.connectionName).toBe('—');
    expect(playbackHistoryPageTwo).toMatchObject({total:18,page:2,pageSize:15,totalPages:2});
    expect(playbackHistoryPageTwo.items).toHaveLength(3);
    const mockConnections = await request('/api/genesys/connections');
    expect(mockConnections.status).toBe(200);
    const listedConnections = await mockConnections.json() as { connections: { id: string; mock?: boolean }[] };
    expect(listedConnections.connections).toHaveLength(1);
    expect(listedConnections.connections[0]).toMatchObject({ id: 'mock', mock: true });

    const destinations=await request('/api/library/destinations');
    expect(destinations.status).toBe(200);
    expect(await destinations.json()).toMatchObject({destinations:[],defaultDestinationId:'',recordingOutputFormat:'m4a'});
    expect(await (await request('/api/library/destination-options')).json()).toMatchObject({destinations:[],defaultDestinationId:''});
    expect((await request('/api/library/destinations/default',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({destinationId:'missing-destination'})})).status).toBe(403);
    const recordingFormat=await request('/api/library/recording-format');
    expect(recordingFormat.status).toBe(200);
    const recordingFormatInfo=await recordingFormat.json() as {format:string;formats:string[];conversionAvailable:boolean};
    expect(recordingFormatInfo).toMatchObject({format:'m4a'});
    expect(recordingFormatInfo.formats).toEqual(['m4a','mp4','mp3','wav','webm','ogg_opus','ogg_vorbis','wav_ulaw']);
    expect((await request('/api/library/recording-format',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({format:'mp3'})})).status).toBe(403);
    const updateFormat=await request('/api/library/recording-format',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({format:'mp3'})},true);
    expect(updateFormat.status).toBe(recordingFormatInfo.conversionAvailable?200:503);
    if(recordingFormatInfo.conversionAvailable){expect(await updateFormat.json()).toMatchObject({format:'mp3',extension:'mp3',mimeType:'audio/mpeg'});expect(await (await request('/api/library/recording-format')).json()).toMatchObject({format:'mp3'});}
    if(ffmpegFixture&&recordingFormatInfo.conversionAvailable){
      const {transcodeRecordingAudio}=await import('../audio-transcode.js');
      const converted=await transcodeRecordingAudio(await fs.readFile(ffmpegFixture),'mp3',async(input,args)=>execFileSync(process.env.FFMPEG_PATH!,args,{input,maxBuffer:16*1024*1024}));
      const output=path.join(testDirectory,`converted.${converted.extension}`);
      await fs.writeFile(output,converted.bytes);
      expect(()=>execFileSync(process.env.FFMPEG_PATH!,['-hide_banner','-loglevel','error','-i',output,'-f','null','-'],{stdio:'ignore'})).not.toThrow();
      expect(converted.mimeType).toBe('audio/mpeg');
      expect(converted.bytes.length).toBeGreaterThan(0);
    }
    const schedules=await request('/api/library/schedules');
    expect(schedules.status).toBe(200);
    expect(await schedules.json()).toMatchObject({schedules:[]});
    const scheduleNoCsrf=await request('/api/library/schedules',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Lookback schedule',connectionId:'00000000-0000-4000-8000-000000000001',destinationId:'00000000-0000-4000-8000-000000000002',cadence:'daily',runTime:'02:00',timeZone:'Asia/Bangkok',lookbackDays:30})});
    expect(scheduleNoCsrf.status).toBe(403);
    const workerStatus=await request('/api/library/worker-status');
    expect(workerStatus.status).toBe(200);
    expect(await workerStatus.json()).toMatchObject({state:'idle',schedules:[]});
    const archivedLibrary=await request('/api/library');
    expect(archivedLibrary.status).toBe(200);
    expect(await archivedLibrary.json()).toMatchObject({items:[],total:0,page:1,pageSize:25});
    const destinationWithoutCsrf=await request('/api/library/destinations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Local',type:'local',path:'/tmp/library'})});
    expect(destinationWithoutCsrf.status).toBe(403);
    const savedDestination=await request('/api/library/destinations',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Integration archive',type:'local',path:path.join(testDirectory,'library-storage'),retentionDays:30})},true);
    expect(savedDestination.status).toBe(201);
    const savedDestinationBody=await savedDestination.json() as {destination:Record<string,unknown>};
    expect(savedDestinationBody.destination).toMatchObject({name:'Integration archive',type:'local',retentionDays:30});
    expect(savedDestinationBody.destination).not.toHaveProperty('password');
    expect((await request('/api/library/destinations/default',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({destinationId:savedDestinationBody.destination.id})},true)).status).toBe(200);
    expect(await (await request('/api/library/destinations')).json()).toMatchObject({defaultDestinationId:savedDestinationBody.destination.id});
    expect(await (await request('/api/library/destination-options')).json()).toMatchObject({defaultDestinationId:savedDestinationBody.destination.id,destinations:[{id:savedDestinationBody.destination.id,name:'Integration archive'}]});
    const archivedId='00000000-0000-4000-8000-000000000021',rangeAudio=Buffer.from('0123456789'),relativeAudio='range-test/fixture.m4a',audioNow=new Date().toISOString();
    await fs.mkdir(path.join(testDirectory,'library-storage','range-test'),{recursive:true});
    await fs.writeFile(path.join(testDirectory,'library-storage',relativeAudio),rangeAudio);
    const archiveDb=new Database(integrationDatabasePath);
    archiveDb.prepare("INSERT INTO archived_recordings(id,connection_id,conversation_id,recording_id,destination_id,relative_path,file_name,mime_type,size_bytes,sha256,conversation_start,metadata_json,archived_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .run(archivedId,'range-test-connection','range-test-conversation','range-test-recording',savedDestinationBody.destination.id,relativeAudio,'fixture.m4a','audio/mp4',rangeAudio.length,'test-sha256',audioNow,JSON.stringify({conversation:{wrapUpCodes:['Resolved'],wrapUpNotes:[]},transcriptions:[{communicationId:'fixture-communication',transcript:{utterances:[]}}]}),audioNow,new Date(Date.now()+86400000).toISOString());
    archiveDb.prepare("UPDATE archived_recordings SET direction='inbound',ani='+66812345678',dnis='+6621112222' WHERE id=?").run(archivedId);
    archiveDb.prepare('INSERT INTO connections(id,name,organization_label,region_id,api_base_url,oauth_base_url,client_id,client_secret_enc,enabled,is_default,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,0,?,?)').run('00000000-0000-4000-8000-000000000031','rearchive mock connection','test','us-east-1','https://api.mypurecloud.com','https://login.mypurecloud.com','test-client','',audioNow,audioNow);
    archiveDb.prepare("UPDATE archived_recordings SET connection_id='00000000-0000-4000-8000-000000000031' WHERE id=?").run(archivedId);
    archiveDb.close();
    const archiveMark=await request('/api/recordings/playability',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'00000000-0000-4000-8000-000000000031',conversationId:'range-test-conversation',recordingId:'range-test-recording',unplayable:true,source:'archive',archiveId:archivedId})},true);
    expect(archiveMark.status).toBe(200);
    expect(await (await request('/api/library')).json()).toMatchObject({items:[],total:0});
    expect(await (await request('/api/library?showUnplayable=true')).json()).toMatchObject({items:[{id:archivedId,unplayable:true}],total:1});
    expect(await (await request('/api/library?q=range-test-conversation&showUnplayable=true')).json()).toMatchObject({items:[{id:archivedId}],total:1});
    expect(await (await request('/api/library?conversationId=other-conversation&showUnplayable=true')).json()).toMatchObject({items:[],total:0});
    expect(await (await request('/api/library?direction=inbound&dnis=662111&showUnplayable=true')).json()).toMatchObject({items:[{id:archivedId}],total:1});
    expect(await (await request(`/api/library?destinationId=${savedDestinationBody.destination.id}&showUnplayable=true`)).json()).toMatchObject({items:[{id:archivedId}],total:1});
    expect(await (await request('/api/library?destinationId=other-destination&showUnplayable=true')).json()).toMatchObject({items:[],total:0});
    expect(await (await request('/api/library?direction=outbound&showUnplayable=true')).json()).toMatchObject({items:[],total:0});
    expect(await (await request('/api/library?agentName=Example+Agent&queueName=Support&showUnplayable=true')).json()).toMatchObject({items:[],total:0});
    expect((await request('/api/library?start=not-a-date')).status).toBe(400);
    expect((await request('/api/library/metadata-backfill/retry',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status).toBe(403);
    const archiveUnmark=await request('/api/recordings/playability',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'00000000-0000-4000-8000-000000000031',conversationId:'range-test-conversation',recordingId:'range-test-recording',unplayable:false,source:'archive',archiveId:archivedId})},true);
    expect(archiveUnmark.status).toBe(200);
    const rangedAudio=await request(`/api/library/${archivedId}/audio`,{headers:{Range:'bytes=2-5'}});
    expect(rangedAudio.status).toBe(206);
    expect(rangedAudio.headers.get('content-range')).toBe('bytes 2-5/10');
    expect(rangedAudio.headers.get('accept-ranges')).toBe('bytes');
    expect(Buffer.from(await rangedAudio.arrayBuffer())).toEqual(Buffer.from('2345'));
    const invalidRange=await request(`/api/library/${archivedId}/audio`,{headers:{Range:'bytes=10-'}});
    expect(invalidRange.status).toBe(416);
    expect(invalidRange.headers.get('content-range')).toBe('bytes */10');
    const noCsrfRearchive=await request(`/api/library/${archivedId}/rearchive`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    expect(noCsrfRearchive.status).toBe(403);
    const mockRearchive=await request(`/api/library/${archivedId}/rearchive`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'},true);
    expect(mockRearchive.status).toBe(409);
    expect(await fs.readFile(path.join(testDirectory,'library-storage',relativeAudio))).toEqual(rangeAudio);
    const libraryRows=await (await request('/api/library')).json() as {items:{id:string;displayNumber:string}[]};
    expect(libraryRows.items.find(item=>item.id===archivedId)?.displayNumber).toBe('+6621112222');
    const cleanupArchiveAudit=new Database(integrationDatabasePath);
    cleanupArchiveAudit.prepare("DELETE FROM audit_logs WHERE action='LIBRARY_PLAYBACK' AND conversation_id='range-test-conversation'").run();
    cleanupArchiveAudit.close();
    const destinationList=await (await request('/api/library/destinations')).json() as {destinations:{id:string;storageTotalBytes:number;storageFreeBytes:number;archivedBytes:number}[]};
    expect(destinationList.destinations[0]).toMatchObject({id:savedDestinationBody.destination.id,archivedBytes:rangeAudio.length});
    expect(destinationList.destinations[0].storageTotalBytes).toBeGreaterThan(0);
    expect(destinationList.destinations[0].storageFreeBytes).toBeGreaterThan(0);
    const mockSchedule=await request('/api/library/schedules',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Backfill',connectionId:'00000000-0000-4000-8000-000000000001',destinationId:'00000000-0000-4000-8000-000000000002',cadence:'daily',runTime:'02:00',timeZone:'Asia/Bangkok'})},true);
    expect(mockSchedule.status).toBe(409);

    const scheduleDb=new Database(integrationDatabasePath);
    const mockConnectionId='00000000-0000-4000-8000-000000000011',scheduleId='00000000-0000-4000-8000-000000000012',now=new Date().toISOString();
    scheduleDb.prepare('INSERT INTO connections(id,name,organization_label,region_id,api_base_url,oauth_base_url,client_id,client_secret_enc,enabled,is_default,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,0,?,?)').run(mockConnectionId,'Run-now test','test','us-east-1','https://api.mypurecloud.com','https://login.mypurecloud.com','test-client','',now,now);
    scheduleDb.prepare("INSERT INTO library_schedules(id,name,connection_id,destination_id,cadence,run_time,time_zone,lookback_days,enabled,cursor_at,backfill_complete,next_run_at,run_status,created_at,updated_at) VALUES(?,?,?,?,'daily','02:00','UTC',30,0,?,1,?,'idle',?,?)").run(scheduleId,'Paused run-now test',mockConnectionId,savedDestinationBody.destination.id,now,now,now,now);
    const lookbackScheduleId='00000000-0000-4000-8000-000000000013';
    scheduleDb.prepare("INSERT INTO library_schedules(id,name,connection_id,destination_id,cadence,run_time,time_zone,lookback_days,enabled,cursor_at,backfill_complete,next_run_at,run_status,created_at,updated_at) VALUES(?,?,?,?,'daily','02:00','UTC',550,0,?,1,?,'idle',?,?)").run(lookbackScheduleId,'Lookback update test',mockConnectionId,savedDestinationBody.destination.id,now,now,now,now);
    scheduleDb.prepare("INSERT INTO library_archive_queue(schedule_id,conversation_id,conversation_start,status,created_at) VALUES(?,?,?,'pending',?),(?,?,?,'pending',?)").run(lookbackScheduleId,'outside-lookback','2020-01-01T00:00:00.000Z',now,lookbackScheduleId,'inside-lookback',now,now);
    scheduleDb.close();
    const lookbackUpdate=await request(`/api/library/schedules/${lookbackScheduleId}`,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Lookback update test',connectionId:mockConnectionId,destinationId:savedDestinationBody.destination.id,cadence:'daily',runTime:'02:00',timeZone:'UTC',lookbackDays:30,enabled:false})},true);
    expect(lookbackUpdate.status).toBe(409);
    const lookbackCheck=new Database(integrationDatabasePath,{readonly:true});
    expect(lookbackCheck.prepare('SELECT conversation_id FROM library_archive_queue WHERE schedule_id=? ORDER BY conversation_id').all(lookbackScheduleId)).toEqual([{conversation_id:'inside-lookback'},{conversation_id:'outside-lookback'}]);
    expect(lookbackCheck.prepare('SELECT enabled,backfill_complete,lookback_days FROM library_schedules WHERE id=?').get(lookbackScheduleId)).toMatchObject({enabled:0,backfill_complete:1,lookback_days:550});
    lookbackCheck.close();
    await request(`/api/library/schedules/${lookbackScheduleId}`,{method:'DELETE'},true);
    expect((await request(`/api/library/schedules/${scheduleId}/run-now`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status).toBe(403);
    const runNow=await request(`/api/library/schedules/${scheduleId}/run-now`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'},true);
    expect(runNow.status).toBe(200);
    expect(await runNow.json()).toMatchObject({ok:true,queued:true});
    const workerDeadline=Date.now()+5000;
    while(Date.now()<workerDeadline){
      const pollDb=new Database(integrationDatabasePath,{readonly:true});
      const state=pollDb.prepare('SELECT run_requested,run_status FROM library_schedules WHERE id=?').get(scheduleId) as {run_requested:number;run_status:string};
      pollDb.close();
      if(state.run_requested===0&&state.run_status==='failed')break;
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    const verifyDb=new Database(integrationDatabasePath,{readonly:true});
    expect(verifyDb.prepare('SELECT enabled,run_requested,run_status,last_started_at,last_error FROM library_schedules WHERE id=?').get(scheduleId)).toMatchObject({enabled:0,run_requested:0,run_status:'failed'});
    const runResult=verifyDb.prepare('SELECT last_started_at,last_error FROM library_schedules WHERE id=?').get(scheduleId) as {last_started_at:string;last_error:string};
    expect(runResult.last_started_at).toBeTruthy();
    expect(runResult.last_error).toMatch(/Mock Mode/);
    verifyDb.close();
    const workerAfterRun=await (await request('/api/library/worker-status')).json() as {state:string;schedules:{id:string;run_status:string;enabled:number;failed_count:number}[]};
    expect(workerAfterRun.state).toBe('failed');
    expect(workerAfterRun.schedules.find(schedule=>schedule.id===scheduleId)).toMatchObject({run_status:'failed',enabled:0,failed_count:0});

    const noCsrf = await request('/api/recordings/search', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(noCsrf.status).toBe(403);
    const crossOrigin = await request('/api/genesys/connections', { headers: { Origin: 'https://attacker.example' } });
    expect(crossOrigin.status).toBe(403);

    const noCsrfConnectionTest = await request('/api/genesys/connections/test', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}),
    });
    expect(noCsrfConnectionTest.status).toBe(403);
    const noCsrfS3Test=await request('/api/s3/sources/test',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})});
    expect(noCsrfS3Test.status).toBe(403);
    const mockConnectionTest = await request('/api/genesys/connections/test', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}),
    }, true);
    expect(mockConnectionTest.status).toBe(409);
    expect((await mockConnectionTest.json() as { error: string }).error).toMatch(/Mock Mode/i);
    const s3Sources=await request('/api/s3/sources');
    expect(s3Sources.status).toBe(200);
    expect(await s3Sources.json()).toEqual({sources:[]});
    expect((await request('/api/s3/sources/test',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})})).status).toBe(403);
    expect((await request('/api/recordings/not-real/stream?connectionId=s3:missing&conversationId=conv&metadataKey=org/year=2026/month=11/day=23/hour=01/conversation_id=conv/recording_metadata.json')).status).toBe(404);
    expect((await request('/api/recordings/not-real/download?connectionId=s3:missing&conversationId=conv&metadataKey=org/year=2026/month=11/day=23/hour=01/conversation_id=conv/recording_metadata.json')).status).toBe(404);

    const s3AuthorizationDb=new Database(integrationDatabasePath),s3SourceId='00000000-0000-4000-8000-000000000041',s3ConnectionId='00000000-0000-4000-8000-000000000031',viewerId='integration-viewer-id',sourceNow=new Date().toISOString();
    const fixtureEncrypt=(plain:string)=>{const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',Buffer.alloc(32,17),iv),data=Buffer.concat([cipher.update(plain,'utf8'),cipher.final()]);return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${data.toString('base64')}`;};
    s3AuthorizationDb.prepare('INSERT INTO s3_sources(id,name,bucket,region,prefix,organization_id,genesys_connection_id,access_key_id_enc,secret_access_key_enc,session_token_enc,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)').run(s3SourceId,'Grant test source','integration-recordings','ap-southeast-1','', 'integration-org',s3ConnectionId,fixtureEncrypt('integration-access-key'),fixtureEncrypt('integration-secret-key'),'',sourceNow,sourceNow);
    s3AuthorizationDb.prepare('INSERT INTO users(id,username,password_hash,role,enabled,created_at,access_role_id) VALUES(?,?,?,?,1,?,?)').run(viewerId,'s3-authorization-viewer',bcrypt.hashSync('S3-Authorization-Password-456!',4),'viewer',sourceNow,'viewer');
    s3AuthorizationDb.close();
    const viewerLogin=await fetch(`${baseUrl}/api/auth/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'s3-authorization-viewer',password:'S3-Authorization-Password-456!'})});
    expect(viewerLogin.status).toBe(200);
    const viewerCookie=(viewerLogin.headers.get('set-cookie')||'').split(';',1)[0];
    expect(await (await requestAs('/api/s3/sources',viewerCookie)).json()).toEqual({sources:[]});
    const sourceQuery=`connectionId=s3:${s3SourceId}&conversationId=authorization-conversation&metadataKey=integration-org/year=2026/month=11/day=23/hour=01/conversation_id=authorization-conversation/recording_metadata.json`;
    expect((await requestAs(`/api/recordings/authorization-recording/stream?${sourceQuery}`,viewerCookie)).status).toBe(404);
    const grantDb=new Database(integrationDatabasePath);
    grantDb.prepare('INSERT INTO user_connection_access(user_id,connection_id) VALUES(?,?)').run(viewerId,s3ConnectionId);
    grantDb.close();
    expect((await (await requestAs('/api/s3/sources',viewerCookie)).json() as {sources:{id:string}[]}).sources).toMatchObject([{id:s3SourceId}]);
    const authorizedPlayback=await requestAs(`/api/recordings/authorization-recording/stream?${sourceQuery}`,viewerCookie);
    expect(authorizedPlayback.status,await authorizedPlayback.clone().text()).toBe(409);
    expect((await requestAs(`/api/recordings/authorization-recording/download?${sourceQuery}`,viewerCookie)).status).toBe(403);
    expect((await requestAs(`/api/recordings/conversations/authorization-conversation/screens?${sourceQuery}&recordingId=authorization-recording`,viewerCookie)).status).toBe(409);

    const search = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-14T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 1, pageSize: 25 }),
    }, true);
    expect(search.status).toBe(200);
    const result = await search.json() as { mock: boolean; results: { conversationId: string; recordingCount: number; recordings: {mediaType:string}[] }[] };
    expect(result.mock).toBe(true);
    expect(result.results).toHaveLength(3);
    expect(result.results.every(row => row.recordingCount > 0)).toBe(true);
    expect(result.results.every(row => row.recordings.every(recording => recording.mediaType === 'voice'))).toBe(true);
    expect((await request('/api/recordings/playability',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',conversationId:'demo-ava-agent-001',recordingId:'demo-recording-1',unplayable:true})},true)).status).toBe(200);
    expect((await (await request('/api/recordings/conversations/demo-ava-agent-001/recordings?connectionId=mock')).json() as {id:string}[]).map(item=>item.id)).toEqual([]);
    expect((await (await request('/api/recordings/conversations/demo-ava-agent-001/recordings?connectionId=mock&showUnplayable=true')).json() as {id:string;unplayable:boolean}[])).toMatchObject([{id:'demo-recording-1',unplayable:true}]);
    const hiddenMarked=await request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25})},true);
    expect((await hiddenMarked.json() as {results:{conversationId:string}[];totalHits:number}).results.map(row=>row.conversationId)).toEqual(['demo-bot-only-002','demo-transfer-003']);
    const shownMarked=await request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25,showUnplayable:true})},true);
    expect((await shownMarked.json() as {results:{conversationId:string;recordings:{id:string;unplayable:boolean}[]}[];totalHits:number}).results.find(row=>row.conversationId==='demo-ava-agent-001')?.recordings).toMatchObject([{id:'demo-recording-1',unplayable:true}]);
    expect((await request('/api/recordings/playability',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',conversationId:'demo-ava-agent-001',recordingId:'demo-recording-1',unplayable:false})},true)).status).toBe(200);

    const agentSuggestions=await request('/api/genesys/directory?connectionId=mock&type=agent&q=nich');
    expect(agentSuggestions.status).toBe(200);
    expect(await agentSuggestions.json()).toMatchObject({suggestions:[{id:'agent-101',name:'Nicha S.'}]});
    const groupSuggestions=await request('/api/genesys/directory?connectionId=mock&type=group&q=support');
    expect(await groupSuggestions.json()).toMatchObject({suggestions:[{id:'group-support',name:'Customer Support'}]});
    const queueSuggestions=await request('/api/genesys/directory?connectionId=mock&type=queue&q=customer');
    expect(await queueSuggestions.json()).toMatchObject({suggestions:[{id:'queue-care',name:'Customer Care'}]});
    const byAgentName=await request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25,agentName:'Nicha S.'})},true);
    expect((await byAgentName.json() as {results:{conversationId:string}[]}).results.map(row=>row.conversationId)).toEqual(['demo-ava-agent-001']);
    const byQueueName=await request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25,queueName:'Customer Care'})},true);
    expect((await byQueueName.json() as {results:{conversationId:string}[]}).results.map(row=>row.conversationId)).toEqual(['demo-ava-agent-001']);
    const byGroupName=await request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25,groupName:'Customer Support'})},true);
    expect((await byGroupName.json() as {results:{conversationId:string}[]}).results.map(row=>row.conversationId)).toEqual(['demo-ava-agent-001']);
    const phoneFormats=['0652936493','66652936493','+66652936493'];
    const phoneSearches=await Promise.all(phoneFormats.map(phone=>request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25,phone})},true)));
    const phoneResultIds=await Promise.all(phoneSearches.map(async response=>{expect(response.status).toBe(200);return (await response.json() as {results:{conversationId:string}[]}).results.map(row=>row.conversationId);}));
    expect(phoneResultIds[0]).toEqual(['demo-ava-agent-001']);
    expect(phoneResultIds[1]).toEqual(phoneResultIds[0]);
    expect(phoneResultIds[2]).toEqual(phoneResultIds[0]);
    const dnisSearches=await Promise.all(['020000000','6620000000','+6620000000'].map(dnis=>request('/api/recordings/search',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-11-14T00:00:00.000Z',intervalEnd:'2026-11-17T00:00:00.000Z',pageNumber:1,pageSize:25,dnis})},true)));
    const dnisResultIds=await Promise.all(dnisSearches.map(async response=>(await response.json() as {results:{conversationId:string}[]}).results.map(row=>row.conversationId)));
    expect(dnisResultIds[0]).toEqual(['demo-bot-only-002','demo-ava-agent-001']);
    expect(dnisResultIds[1]).toEqual(dnisResultIds[0]);
    expect(dnisResultIds[2]).toEqual(dnisResultIds[0]);

    const conversationRecordings=await request('/api/recordings/conversations/demo-ava-agent-001/recordings?connectionId=mock');
    expect(conversationRecordings.status).toBe(200);
    expect(await conversationRecordings.json()).toMatchObject([{id:'demo-recording-1',mediaType:'voice'}]);
    const mockConversationDetails=await request('/api/recordings/conversations/demo-ava-agent-001?connectionId=mock');
    expect(mockConversationDetails.status).toBe(200);
    expect(await mockConversationDetails.json()).toMatchObject({conversationId:'demo-ava-agent-001',queues:['Customer Care'],wrapUpCodes:['Resolved'],wrapUpNotes:[{agent:'Nicha S.',note:'Customer confirmed the issue was resolved after the account settings were updated.'}]});
    const mockSummaries=await request('/api/recordings/conversations/demo-ava-agent-001/summaries?connectionId=mock');
    expect(mockSummaries.status).toBe(501);
    const mockTranscription=await request('/api/recordings/conversations/demo-ava-agent-001/transcription?connectionId=mock');
    expect(mockTranscription.status).toBe(501);
    const messageRecordings=await request('/api/recordings/conversations/demo-ava-agent-001/recordings?connectionId=mock');
    expect((await messageRecordings.json() as {mediaType:string}[]).every(recording=>recording.mediaType==='voice')).toBe(true);
    const messageMetadata=await request('/api/recordings/demo-message-1/metadata?connectionId=mock&conversationId=demo-ava-agent-001');
    expect(messageMetadata.status).toBe(404);

    const defaultRecordingOnly = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-14T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 1, pageSize: 25 }),
    }, true);
    expect((await defaultRecordingOnly.json() as { results: unknown[] }).results).toHaveLength(3);

    const missingRecording = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-14T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', includeNoRecording: true, pageNumber: 1, pageSize: 50 }),
    }, true);
    expect(missingRecording.status).toBe(200);
    const allConversations = await missingRecording.json() as { results: { recordingCount: number; recordings: {mediaType:string}[] }[]; pageSize: number };
    expect(allConversations.results).toHaveLength(3);
    expect(allConversations.results.every(row => row.recordingCount > 0)).toBe(true);
    expect(allConversations.results.flatMap(row=>row.recordings).every(recording=>recording.mediaType==='voice')).toBe(true);

    const screenArchiveId='00000000-0000-4000-8000-000000000051',screenBytes=Buffer.from([0x1a,0x45,0xdf,0xa3,0x01,0x02,0x03]),screenPath='screen-test/monitor.webm',screenNow=new Date().toISOString();
    await fs.mkdir(path.join(testDirectory,'library-storage','screen-test'),{recursive:true});
    await fs.writeFile(path.join(testDirectory,'library-storage',screenPath),screenBytes);
    const screenDb=new Database(integrationDatabasePath);
    screenDb.prepare("INSERT INTO archived_recordings(id,connection_id,conversation_id,recording_id,destination_id,relative_path,file_name,mime_type,media_type,size_bytes,sha256,conversation_start,metadata_json,archived_at,expires_at) VALUES(?,?,?,?,?,?,?,'video/webm','screen',?,?,?, ?,?,?)").run(screenArchiveId,'screen-no-access-connection','screen-test-conversation','screen-test-recording',savedDestinationBody.destination.id,screenPath,'monitor.webm',screenBytes.length,'screen-fixture-sha256',screenNow,JSON.stringify({conversationId:'screen-test-conversation'}),screenNow,new Date(Date.now()+86400000).toISOString());
    screenDb.close();
    const screenLookup=await request(`/api/library/${screenArchiveId}/screens`);
    expect(screenLookup.status).toBe(200);
    const screenLookupBody=await screenLookup.json() as {tracks:{url:string;mimeType:string;name:string}[]};
    expect(screenLookupBody.tracks).toHaveLength(1);
    expect(screenLookupBody.tracks[0]).toMatchObject({mimeType:'video/webm',name:'monitor.webm · monitor.webm'});
    const deniedScreenLookup=await requestAs(`/api/library/${screenArchiveId}/screens`,viewerCookie);
    expect(deniedScreenLookup.status).toBe(403);
    expect((await requestAs(screenLookupBody.tracks[0].url,viewerCookie)).status).toBe(403);
    const screenStream=await request(screenLookupBody.tracks[0].url);
    expect(screenStream.status).toBe(200);
    expect(screenStream.headers.get('content-type')).toMatch(/video\/webm/i);
    expect(Buffer.from(await screenStream.arrayBuffer())).toEqual(screenBytes);
    expect((await request('/api/library/00000000-0000-4000-8000-000000000051/screens/unknown/stream')).status).toBe(404);
    const cleanupAuthorizationDb=new Database(integrationDatabasePath);
    cleanupAuthorizationDb.prepare('DELETE FROM s3_sources WHERE id=?').run(s3SourceId);
    cleanupAuthorizationDb.prepare('DELETE FROM users WHERE id=?').run(viewerId);
    cleanupAuthorizationDb.close();
  }, 30_000);

  it('lists saved live connections after trusted-region validation without exposing endpoint or secret fields', async () => {
    const liveDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'mfec-recording-explorer-live-test-'));
    const port = await freePort();
    const liveUrl = `http://127.0.0.1:${port}`;
    let liveChild: ChildProcess | undefined;
    let liveOutput = '';
    let liveCookie = '';
    let liveCsrf = '';
    try {
      const legacyDatabase=new Database(path.join(liveDirectory,'integration.sqlite'));
      legacyDatabase.exec("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrator','supervisor','quality_analyst','viewer')), enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)");
      legacyDatabase.prepare('INSERT INTO users(id,username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,1,?)').run('legacy-admin-id','live-integration-admin',bcrypt.hashSync('Live-Integration-Password-456!',4),'administrator',new Date().toISOString());
      legacyDatabase.close();
      liveChild = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
        cwd: root,
        env: {
          ...process.env,
          NODE_ENV: 'test', PORT: String(port), HOST: '127.0.0.1',
          APP_ORIGIN: 'http://localhost:5173', TRUST_PROXY: 'false', MOCK_MODE: 'false',
          SESSION_SECRET: 'live-integration-test-session-secret-with-sufficient-entropy',
          MASTER_ENCRYPTION_KEY: Buffer.alloc(32, 23).toString('base64'),
          DATABASE_PATH: path.join(liveDirectory, 'integration.sqlite'),
          LIBRARY_STORAGE_ROOT:path.join(liveDirectory,'library'),
          INITIAL_ADMIN_USERNAME: 'live-integration-admin', INITIAL_ADMIN_PASSWORD: 'Live-Integration-Password-456!',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      liveChild.stdout?.on('data', data => { liveOutput += String(data); });
      liveChild.stderr?.on('data', data => { liveOutput += String(data); });
      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline) {
        if (liveChild.exitCode !== null && liveChild.exitCode !== undefined) throw new Error(`Live API test server exited (${liveChild.exitCode}).\n${liveOutput}`);
        try { if ((await fetch(`${liveUrl}/api/health`)).ok) break; } catch { /* Wait for the local test server to start. */ }
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      const login = await fetch(`${liveUrl}/api/auth/login`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'live-integration-admin', password: 'Live-Integration-Password-456!' }),
      });
      expect(login.status).toBe(200);
      liveCookie = (login.headers.get('set-cookie') || '').split(';', 1)[0];
      liveCsrf = (await login.json() as { csrfToken: string }).csrfToken;
      const migratedDatabase=new Database(path.join(liveDirectory,'integration.sqlite'),{readonly:true});
      const migratedUserColumns=(migratedDatabase.prepare('PRAGMA table_info(users)').all() as {name:string}[]).map(column=>column.name);
      const playabilityColumns=(migratedDatabase.prepare('PRAGMA table_info(recording_playability)').all() as {name:string}[]).map(column=>column.name);
      expect(playabilityColumns).toContain('is_unplayable');
      expect(migratedUserColumns).toContain('access_role_id');
      expect(migratedUserColumns).toContain('department');
      const legacyRoleConstraint=(migratedDatabase.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get() as {sql:string}).sql;
      expect(legacyRoleConstraint).toContain("CHECK(role IN ('administrator','supervisor','quality_analyst','viewer'))");
      expect(migratedDatabase.prepare('SELECT access_role_id FROM users WHERE id=?').get('legacy-admin-id')).toEqual({access_role_id:'administrator'});
      migratedDatabase.close();

    const create = await fetch(`${liveUrl}/api/genesys/connections`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: liveCookie, 'x-csrf-token': liveCsrf, Origin: 'http://localhost:5173' },
        body: JSON.stringify({
          name: 'Saved integration organization', organizationLabel: 'Integration', regionId: 'ap-southeast-1',
          clientId: 'integration-client-id', clientSecret: 'integration-secret-that-must-not-leak', enabled: true, isDefault: true,
        }),
      });
      expect(create.status).toBe(201);
      const customRole=await fetch(`${liveUrl}/api/admin/roles`,{method:'POST',headers:{'content-type':'application/json',cookie:liveCookie,'x-csrf-token':liveCsrf,Origin:'http://localhost:5173'},body:JSON.stringify({name:'Library Operator',permissions:{libraryAdmin:true}})});
      expect(customRole.status).toBe(201);
      const customRoleBody=await customRole.json() as {role:{id:string}};
      const customUser=await fetch(`${liveUrl}/api/admin/users`,{method:'POST',headers:{'content-type':'application/json',cookie:liveCookie,'x-csrf-token':liveCsrf,Origin:'http://localhost:5173'},body:JSON.stringify({username:'library-operator',password:'Library-Operator-Password-456!',role:customRoleBody.role.id,connectionIds:[]})});
      expect(customUser.status).toBe(201);
      const customLogin=await fetch(`${liveUrl}/api/auth/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'library-operator',password:'Library-Operator-Password-456!'})});
      expect(customLogin.status).toBe(200);
      const customCookie=(customLogin.headers.get('set-cookie')||'').split(';',1)[0];
      const customConnections=await fetch(`${liveUrl}/api/genesys/connections`,{headers:{cookie:customCookie}});
      expect((await customConnections.json() as {connections:{id:string}[]}).connections).toHaveLength(1);
      const customScheduleList=await fetch(`${liveUrl}/api/library/schedules`,{headers:{cookie:customCookie}});
      expect(customScheduleList.status).toBe(200);
      const customRegions=await fetch(`${liveUrl}/api/genesys/regions`,{headers:{cookie:customCookie}});
      expect(customRegions.status).toBe(403);
      const customSearch=await fetch(`${liveUrl}/api/recordings/search`,{method:'POST',headers:{'content-type':'application/json',cookie:customCookie,Origin:'http://localhost:5173'},body:JSON.stringify({connectionId:'does-not-exist',intervalStart:'2026-10-01T00:00:00.000Z',intervalEnd:'2026-10-02T00:00:00.000Z'})});
      expect(customSearch.status).toBe(403);
      const deniedLibraryConfiguration=await fetch(`${liveUrl}/api/library/destinations`,{method:'POST',headers:{'content-type':'application/json',cookie:liveCookie,Origin:'http://localhost:5173'},body:JSON.stringify({name:'Blocked local',type:'local',path:path.join(liveDirectory,'library'),retentionDays:30})});
      expect(deniedLibraryConfiguration.status).toBe(403);

      const list = await fetch(`${liveUrl}/api/genesys/connections`, { headers: { cookie: liveCookie } });
      expect(list.status).toBe(200);
      const body = await list.json() as { connections: Record<string, unknown>[] };
      expect(body.connections).toHaveLength(1);
      expect(body.connections[0]).toMatchObject({ name: 'Saved integration organization', region_id: 'ap-southeast-1', enabled: 1, is_default: 1, secret_configured: 1 });
      expect(body.connections[0]).not.toHaveProperty('api_base_url');
      expect(body.connections[0]).not.toHaveProperty('oauth_base_url');
      expect(body.connections[0]).not.toHaveProperty('client_secret_enc');
      expect(JSON.stringify(body)).not.toContain('integration-secret-that-must-not-leak');

      const deleteUsedRegion = await fetch(`${liveUrl}/api/genesys/regions`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', cookie: liveCookie, 'x-csrf-token': liveCsrf, Origin: 'http://localhost:5173' },
        body: JSON.stringify({ regions: [] }),
      });
      expect(deleteUsedRegion.status).toBe(409);
    } finally {
      if (liveChild && liveChild.exitCode === null) {
        await fetch(`${liveUrl}/__test/shutdown`, { method: 'POST' }).catch(() => undefined);
        await new Promise<void>(resolve => liveChild?.once('exit', () => resolve()));
      }
      await fs.rm(liveDirectory, { recursive: true, force: true });
    }
  }, 30_000);

  it('lets administrators manage trusted regions and refuses to delete one used by a saved connection', async () => {
    const original = await request('/api/genesys/regions');
    expect(original.status).toBe(200);
    const originalRegions = (await original.json() as { regions: { id: string; name: string; api: string; oauth: string }[] }).regions;
    const add = await request('/api/genesys/regions', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ regions: [...originalRegions, { id: 'ca-central-1', name: 'Canada Central', api: 'https://api.cac1.pure.cloud', oauth: 'https://login.cac1.pure.cloud' }] }),
    }, true);
    expect(add.status).toBe(200);
    expect((await add.json() as { regions: { id: string }[] }).regions.map(region => region.id)).toContain('ca-central-1');

    const unsafe = await request('/api/genesys/regions', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ regions: [{ id: 'unsafe-1', name: 'Unsafe', api: 'https://api.attacker.test', oauth: 'https://login.attacker.test' }] }),
    }, true);
    expect(unsafe.status).toBe(400);

    const updateExisting = await request('/api/genesys/regions', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ regions: originalRegions.map(region => region.id === 'ap-southeast-1' ? { ...region, name: 'Singapore Region' } : region).concat({ id: 'ca-central-1', name: 'Canada Central', api: 'https://api.cac1.pure.cloud', oauth: 'https://login.cac1.pure.cloud' }) }),
    }, true);
    expect(updateExisting.status).toBe(200);
    expect((await updateExisting.json() as { regions: { id: string; name: string }[] }).regions.find(region => region.id === 'ap-southeast-1')?.name).toBe('Singapore Region');

    const removeAdded = await request('/api/genesys/regions', {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ regions: originalRegions }),
    }, true);
    expect(removeAdded.status).toBe(200);
  });

  it('stores UI appearance per user and restricts the shared default to administrators', async () => {
    const initial = await request('/api/user/appearance');
    expect(initial.status).toBe(200);
    expect((await initial.json() as { appearance: unknown; userOverride: boolean; canSetDefault: boolean })).toMatchObject({
      appearance: { theme: 'light', fontFamily: 'Prompt', fontSize: 13 }, userOverride: false, canSetDefault: true,
    });

    const invalidSize = await request('/api/user/appearance', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scope: 'user', appearance: { theme: 'dark', fontFamily: 'Prompt', fontSize: 25 } }),
    }, true);
    expect(invalidSize.status).toBe(400);

    const personal = await request('/api/user/appearance', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scope: 'user', appearance: { theme: 'dark', fontFamily: 'Century Gothic', fontSize: 24 } }),
    }, true);
    expect(personal.status).toBe(200);
    expect((await personal.json() as { appearance: unknown; userOverride: boolean }).appearance).toEqual({ theme: 'dark', fontFamily: 'Century Gothic', fontSize: 24 });

    const sharedDefault = await request('/api/user/appearance', {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scope: 'default', appearance: { theme: 'light', fontFamily: 'Prompt', fontSize: 15 } }),
    }, true);
    expect(sharedDefault.status).toBe(200);
    expect(await sharedDefault.json()).toMatchObject({
      appearance: { theme: 'dark', fontFamily: 'Century Gothic', fontSize: 24 },
      userOverride: true,
      defaultAppearance: { theme: 'light', fontFamily: 'Prompt', fontSize: 15 },
    });
    const clearPersonal = await request('/api/user/appearance', { method: 'DELETE' }, true);
    expect(clearPersonal.status).toBe(200);
    expect(await clearPersonal.json()).toMatchObject({
      appearance: { theme: 'light', fontFamily: 'Prompt', fontSize: 15 }, userOverride: false,
    });
  });

  it('limits the analytics interval and labels synthetic metadata as non-playable', async () => {
    const longRange = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-01T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 1, pageSize: 25 }),
    }, true);
    expect(longRange.status).toBe(200);
    const tooWide = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-06-01T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 1, pageSize: 25 }),
    }, true);
    expect(tooWide.status).toBe(400);
    const recordingSearch = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-14T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 2, pageSize: 1 }),
    }, true);
    expect(recordingSearch.status).toBe(200);
    const recordingPage = await recordingSearch.json() as { results: { conversationId: string }[]; totalHits: number };
    expect(recordingPage.results.map(result => result.conversationId)).toEqual(['demo-ava-agent-001']);
    expect(recordingPage.totalHits).toBe(3);
    const filteredPage = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-14T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 1, pageSize: 1, direction: 'inbound' }),
    }, true);
    const filteredResults = await filteredPage.json() as { results: { conversationId: string }[]; totalHits: number };
    expect(filteredResults.results.map(result => result.conversationId)).toEqual(['demo-bot-only-002']);
    expect(filteredResults.totalHits).toBe(2);
    const stream = await request('/api/recordings/demo-recording-1/stream?connectionId=mock&conversationId=demo-ava-agent-001');
    expect(stream.status).toBe(501);
    expect((await stream.json() as { error: string }).error).toMatch(/metadata only/i);
    const audit = await request('/api/audit');
    expect(audit.status).toBe(200);
    expect((await audit.json() as { logs: unknown[] }).logs.length).toBeGreaterThan(0);
  });

  it('returns bounded dashboard metrics from explicitly synthetic fixture data', async () => {
    const start='2026-11-14T00:00:00.000Z',end='2026-11-18T00:00:00.000Z';
    const dashboard=await request(`/api/dashboard/summary?connectionId=mock&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`);
    expect(dashboard.status).toBe(200);
    expect(await dashboard.json()).toMatchObject({
      available:true,mock:true,partial:false,
      metrics:{totalConversations:4,recordingsAvailable:3,recordingCoverage:75,averageDurationSeconds:((453+152+913+130)/4)},
    });
    const tooWide=await request(`/api/dashboard/summary?connectionId=mock&start=2026-10-01T00%3A00%3A00.000Z&end=2026-11-18T00%3A00%3A00.000Z`);
    expect(tooWide.status).toBe(400);
    const anonymous=await fetch(`${baseUrl}/api/dashboard/summary?connectionId=mock&start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`);
    expect(anonymous.status).toBe(401);
  });

  it('filters and paginates audit events and persists the retention window', async () => {
    const defaultAudit = await request('/api/audit');
    expect(defaultAudit.status).toBe(200);
    const defaultAuditBody=await defaultAudit.json() as {page:number;pageSize:number;totalPages:number};
    expect(defaultAuditBody).toMatchObject({page:1,pageSize:25});
    expect(defaultAuditBody.totalPages).toBeGreaterThanOrEqual(1);
    const filteredAudit = await request('/api/audit?action=SEARCH&pageSize=50');
    expect(filteredAudit.status).toBe(200);
    expect((await filteredAudit.json() as { logs: { action: string }[]; pageSize: number }).logs.every(row => row.action === 'SEARCH')).toBe(true);
    const retention = await request('/api/admin/audit-retention');
    expect(await retention.json()).toMatchObject({ days: 35, defaultDays: 35 });
    const update = await request('/api/admin/audit-retention', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ days: 60 }) }, true);
    expect(update.status).toBe(200);
    expect(await update.json()).toMatchObject({ days: 60 });
  });

  it('restricts administration, preserves a final administrator, and revokes disabled-user sessions', async () => {
    const roleList=await request('/api/admin/roles');
    expect(roleList.status).toBe(200);
    const roleValues=await roleList.json() as {roles:{id:string;name:string;builtIn:boolean;permissions:{realtimePlayback:boolean;realtimeDownload:boolean;libraryPlayback:boolean;libraryAdmin:boolean}}[]};
    expect(roleValues.roles.find(role=>role.id==='administrator')?.permissions).toEqual({realtimePlayback:true,realtimeDownload:true,libraryPlayback:true,libraryAdmin:true});
    const noSearchRole=await request('/api/admin/roles',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Archive Admin',permissions:{realtimePlayback:false,realtimeDownload:false,libraryPlayback:false,libraryAdmin:true}})},true);
    expect(noSearchRole.status).toBe(201);
    const archiveAdminRole=await noSearchRole.json() as {role:{id:string}};
    const createRole=await request('/api/admin/roles',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Archive Only',permissions:{realtimePlayback:false,realtimeDownload:false,libraryPlayback:true,libraryAdmin:false}})},true);
    expect(createRole.status).toBe(201);
    const archiveRole=await createRole.json() as {role:{id:string}};
    const builtInRoleEdit=await request('/api/admin/roles/administrator',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Root',permissions:{}})},true);
    expect(builtInRoleEdit.status).toBe(409);
    const duplicateRole=await request('/api/admin/roles',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Archive Only',permissions:{}})},true);
    expect(duplicateRole.status).toBe(409);
    const currentUsers = await request('/api/admin/users');
    const admin = ((await currentUsers.json()) as { users: { id: string; username: string }[] }).users.find(user => user.username === 'integration-admin');
    expect(admin).toBeTruthy();
    const create = await request('/api/admin/users', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'integration-viewer', password: 'Viewer-Integration-Password-456!', role: 'viewer', connectionIds: [] }),
    }, true);
    expect(create.status).toBe(201);
    const created = await create.json() as { id: string };

    const selfDemotion = await request(`/api/admin/users/${admin!.id}/role`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: 'viewer' }),
    }, true);
    expect(selfDemotion.status).toBe(400);

    const viewerLogin = await fetch(`${baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'integration-viewer', password: 'Viewer-Integration-Password-456!' }) });
    expect(viewerLogin.status).toBe(200);
    const viewerCookie = (viewerLogin.headers.get('set-cookie') || '').split(';', 1)[0];
    const viewerAuth = await viewerLogin.json() as { csrfToken: string };
    const viewerAudioDownload=await fetch(`${baseUrl}/api/recordings/demo-recording-1/download?connectionId=mock&conversationId=demo-ava-agent-001`,{headers:{Cookie:viewerCookie}});
    expect(viewerAudioDownload.status).toBe(403);
    const viewerS3Playback=await fetch(`${baseUrl}/api/recordings/not-real/stream?connectionId=s3:missing&conversationId=conv&metadataKey=org/year=2026/month=11/day=23/hour=01/conversation_id=conv/recording_metadata.json`,{headers:{Cookie:viewerCookie}});
    expect(viewerS3Playback.status).toBe(404);
    const viewerS3Download=await fetch(`${baseUrl}/api/recordings/not-real/download?connectionId=s3:missing&conversationId=conv&metadataKey=org/year=2026/month=11/day=23/hour=01/conversation_id=conv/recording_metadata.json`,{headers:{Cookie:viewerCookie}});
    expect(viewerS3Download.status).toBe(403);
    const viewerHistory=await (await fetch(`${baseUrl}/api/playback-history`,{headers:{Cookie:viewerCookie}})).json() as {total:number;page:number;pageSize:number;totalPages:number;items:{action:string;result:string}[]};
    expect(viewerHistory).toMatchObject({total:1,page:1,pageSize:15,totalPages:1,items:[{action:'PLAYBACK',result:'FAILED'}]});
    const viewerAdminPage = await fetch(`${baseUrl}/api/admin/users`, { headers: { Cookie: viewerCookie } });
    expect(viewerAdminPage.status).toBe(403);
    const roleRename=await request(`/api/admin/roles/${archiveRole.role.id}`,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Archive Reader',permissions:{realtimePlayback:false,realtimeDownload:false,libraryPlayback:true,libraryAdmin:false}})},true);
    expect(roleRename.status).toBe(200);
    const roleUserCreate=await request('/api/admin/users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'archive-reader',password:'Archive-Reader-Password-456!',role:archiveRole.role.id,connectionIds:[]})},true);
    expect(roleUserCreate.status).toBe(201);
    const archiveLogin=await fetch(`${baseUrl}/api/auth/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'archive-reader',password:'Archive-Reader-Password-456!'})});
    expect(archiveLogin.status).toBe(200);
    const archiveCookie=(archiveLogin.headers.get('set-cookie')||'').split(';',1)[0];
    const archiveAuth=await archiveLogin.json() as {user:{role:string;permissions:{libraryPlayback:boolean;realtimePlayback:boolean};};csrfToken:string};
    expect(archiveAuth.user).toMatchObject({role:archiveRole.role.id,permissions:{libraryPlayback:true,realtimePlayback:false}});
    expect((await fetch(`${baseUrl}/api/s3/sources`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    expect((await fetch(`${baseUrl}/api/library`,{headers:{Cookie:archiveCookie}})).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/library/destinations`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    expect((await fetch(`${baseUrl}/api/library/destination-options`,{headers:{Cookie:archiveCookie}})).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/library/schedules`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    expect((await fetch(`${baseUrl}/api/library/worker-status`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    expect((await fetch(`${baseUrl}/api/recordings/conversations/demo-ava-agent-001?connectionId=mock`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    expect((await fetch(`${baseUrl}/api/dashboard/summary?connectionId=mock&start=2026-11-14T00:00:00.000Z&end=2026-11-15T00:00:00.000Z`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    const archiveSearch=await fetch(`${baseUrl}/api/recordings/search`,{method:'POST',headers:{'content-type':'application/json',Cookie:archiveCookie,'x-csrf-token':archiveAuth.csrfToken,Origin:'http://localhost:5173'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-10-01T00:00:00.000Z',intervalEnd:'2026-10-02T00:00:00.000Z'})});
    expect(archiveSearch.status).toBe(403);
    expect((await fetch(`${baseUrl}/api/genesys/directory?connectionId=mock&type=agent&q=Ni`,{headers:{Cookie:archiveCookie}})).status).toBe(403);
    const archiveAdminCreated=await request('/api/admin/users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'archive-admin',password:'Archive-Admin-Password-456!',role:archiveAdminRole.role.id,connectionIds:[]})},true);
    expect(archiveAdminCreated.status).toBe(201);
    const archiveAdminLogin=await fetch(`${baseUrl}/api/auth/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'archive-admin',password:'Archive-Admin-Password-456!'})});
    expect(archiveAdminLogin.status).toBe(200);
    const archiveAdminCookie=(archiveAdminLogin.headers.get('set-cookie')||'').split(';',1)[0];
    const archiveAdminAuth=await archiveAdminLogin.json() as {csrfToken:string;user:{permissions:{libraryPlayback:boolean;libraryAdmin:boolean;realtimePlayback:boolean}}};
    expect(archiveAdminAuth.user.permissions).toMatchObject({libraryPlayback:true,libraryAdmin:true,realtimePlayback:false});
    expect((await fetch(`${baseUrl}/api/library/schedules`,{headers:{Cookie:archiveAdminCookie}})).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/library/destinations`,{headers:{Cookie:archiveAdminCookie}})).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/library/destinations/default`,{method:'PUT',headers:{'content-type':'application/json',Cookie:archiveAdminCookie,'x-csrf-token':archiveAdminAuth.csrfToken,Origin:'http://localhost:5173'},body:JSON.stringify({destinationId:''})})).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/recordings/search`,{method:'POST',headers:{'content-type':'application/json',Cookie:archiveAdminCookie,'x-csrf-token':archiveAdminAuth.csrfToken,Origin:'http://localhost:5173'},body:JSON.stringify({connectionId:'mock',intervalStart:'2026-10-01T00:00:00.000Z',intervalEnd:'2026-10-02T00:00:00.000Z'})})).status).toBe(403);
    expect((await fetch(`${baseUrl}/api/genesys/connections`,{headers:{Cookie:archiveAdminCookie}})).status).toBe(200);
    expect((await fetch(`${baseUrl}/api/genesys/directory?connectionId=mock&type=agent&q=Ni`,{headers:{Cookie:archiveAdminCookie}})).status).toBe(403);
    const roleInUseDelete=await request(`/api/admin/roles/${archiveRole.role.id}`,{method:'DELETE'},true);
    expect(roleInUseDelete.status).toBe(409);
    const roleReassignment=await request(`/api/admin/users/${(await roleUserCreate.json() as {id:string}).id}/role`,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({role:'viewer'})},true);
    expect(roleReassignment.status).toBe(200);
    const deleteRole=await request(`/api/admin/roles/${archiveRole.role.id}`,{method:'DELETE'},true);
    expect(deleteRole.status).toBe(204);
    const deleteArchiveAdminRole=await request(`/api/admin/roles/${archiveAdminRole.role.id}`,{method:'DELETE'},true);
    expect(deleteArchiveAdminRole.status).toBe(409);
    const viewerRegionUpdate = await fetch(`${baseUrl}/api/genesys/regions`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', Cookie: viewerCookie, 'x-csrf-token': viewerAuth.csrfToken, Origin: 'http://localhost:5173' },
      body: JSON.stringify({ regions: [] }),
    });
    expect(viewerRegionUpdate.status).toBe(403);
    const viewerDefaultAppearance = await fetch(`${baseUrl}/api/user/appearance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', Cookie: viewerCookie, 'x-csrf-token': viewerAuth.csrfToken, Origin: 'http://localhost:5173' },
      body: JSON.stringify({ scope: 'default', appearance: { theme: 'dark', fontFamily: 'Prompt', fontSize: 14 } }),
    });
    expect(viewerDefaultAppearance.status).toBe(403);

    const disable = await request(`/api/admin/users/${created.id}/enabled`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled: false }),
    }, true);
    expect(disable.status, await disable.clone().text()).toBe(200);
    const revoked = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: viewerCookie, 'x-csrf-token': viewerAuth.csrfToken } });
    expect(revoked.status).toBe(401);
    const removeUser = await request(`/api/admin/users/${created.id}`, { method: 'DELETE' }, true);
    expect(removeUser.status).toBe(204);
    const usersAfterDelete = await request('/api/admin/users');
    expect((await usersAfterDelete.json() as { users: { id: string }[] }).users.some(entry => entry.id === created.id)).toBe(false);
    const selfDelete = await request(`/api/admin/users/${admin!.id}`, { method: 'DELETE' }, true);
    expect(selfDelete.status).toBe(400);
  });

  it('supports profile updates, the eight-character policy, role-guarded resets, and encrypted SMTP settings', async () => {
    const createdResponse=await request('/api/admin/users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'policy-user',password:'InitialA1',role:'viewer',connectionIds:[],profile:{email:'policy@example.com',phone:'+66 81 234 5678',firstName:'Policy',lastName:'User',nickname:'Test',jobTitle:'Analyst',division:'Operations',department:'Quality'}})},true);
    expect(createdResponse.status,await createdResponse.clone().text()).toBe(201);
    const created=await createdResponse.json() as {id:string};
    const profileList=await request('/api/admin/users');
    expect((await profileList.json() as {users:Record<string,unknown>[]}).users.find(item=>item.id===created.id)).toMatchObject({email:'policy@example.com',phone:'+66 81 234 5678',firstName:'Policy',lastName:'User',nickname:'Test',jobTitle:'Analyst',division:'Operations',department:'Quality'});

    const login=await fetch(`${baseUrl}/api/auth/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'policy-user',password:'InitialA1'})});
    expect(login.status).toBe(200);
    const userCookie=(login.headers.get('set-cookie')||'').split(';',1)[0];
    const userCsrf=(await login.json() as {csrfToken:string}).csrfToken;
    const headers={'content-type':'application/json',cookie:userCookie,'x-csrf-token':userCsrf,Origin:'http://localhost:5173'};
    const userProfile=await fetch(`${baseUrl}/api/user/profile`,{headers:{cookie:userCookie}});
    expect(await userProfile.json()).toMatchObject({profile:{email:'policy@example.com',firstName:'Policy'}});
    const profileUpdate=await fetch(`${baseUrl}/api/user/profile`,{method:'PUT',headers,body:JSON.stringify({email:'updated@example.com',phone:'+66 99 000 0000',firstName:'Updated',lastName:'User',nickname:'Update',jobTitle:'Lead',division:'Service',department:'CX'})});
    expect(profileUpdate.status).toBe(200);
    const deniedReset=await fetch(`${baseUrl}/api/admin/users/${created.id}/password`,{method:'POST',headers,body:JSON.stringify({password:'ResetPass9'})});
    expect(deniedReset.status).toBe(403);
    const smtpDenied=await fetch(`${baseUrl}/api/admin/smtp`,{headers:{cookie:userCookie}});
    expect(smtpDenied.status).toBe(403);
    const userPasswordUpdate=await fetch(`${baseUrl}/api/auth/password`,{method:'POST',headers,body:JSON.stringify({currentPassword:'InitialA1',newPassword:'Changed!9'})});
    expect(userPasswordUpdate.status).toBe(200);
    const refreshedAuth=await userPasswordUpdate.json() as {csrfToken:string};

    const badPolicy=await request(`/api/admin/users/${created.id}/password`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:'12345678'})},true);
    expect(badPolicy.status).toBe(400);
    const reset=await request(`/api/admin/users/${created.id}/password`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:'ResetPass9'})},true);
    expect(reset.status).toBe(200);
    const revoked=await fetch(`${baseUrl}/api/auth/me`,{headers:{cookie:userCookie}});
    expect(revoked.status).toBe(401);
    const resetLogin=await fetch(`${baseUrl}/api/auth/login`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:'policy-user',password:'ResetPass9'})});
    expect(resetLogin.status).toBe(200);

    const smtpInitial=await request('/api/admin/smtp');
    expect(await smtpInitial.json()).toMatchObject({settings:{host:'smtp.gmail.com',port:587,secure:false,passwordConfigured:false}});
    const smtpTestWithoutCredentials=await request('/api/admin/smtp/test',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({to:'qa@example.com'})},true);
    expect(smtpTestWithoutCredentials.status).toBe(409);
    const smtpSave=await request('/api/admin/smtp',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({host:'smtp.gmail.com',port:587,secure:false,username:'sender@gmail.com',password:'secret-gmail-app-password',fromName:'MFEC',fromEmail:'sender@gmail.com',rejectUnauthorized:true})},true);
    expect(smtpSave.status).toBe(200);
    const savedBody=await smtpSave.json() as {settings:Record<string,unknown>};
    expect(savedBody.settings).toMatchObject({host:'smtp.gmail.com',port:587,passwordConfigured:true});
    expect(savedBody).not.toHaveProperty('password');
    expect(JSON.stringify(savedBody)).not.toContain('secret-gmail-app-password');
    const smtpAfterSave=await request('/api/admin/smtp');
    const smtpAfterBody=await smtpAfterSave.json() as {settings:Record<string,unknown>};
    expect(smtpAfterBody.settings.passwordConfigured).toBe(true);
    expect(JSON.stringify(smtpAfterBody)).not.toContain('secret-gmail-app-password');
    const persisted=new Database(path.join(testDirectory,'integration.sqlite'),{readonly:true});
    const storedSmtp=persisted.prepare("SELECT value_json FROM application_settings WHERE key='smtp_settings'").get() as {value_json:string};
    expect(storedSmtp.value_json).not.toContain('secret-gmail-app-password');
    expect(JSON.parse(storedSmtp.value_json)).toHaveProperty('passwordEnc');
    persisted.close();
    const clearPassword=await request('/api/admin/smtp',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({host:'smtp.gmail.com',port:587,secure:false,username:'sender@gmail.com',password:'',fromName:'MFEC',fromEmail:'sender@gmail.com',rejectUnauthorized:true})},true);
    expect(clearPassword.status).toBe(200);
    const retainedSecret=await request('/api/admin/smtp');
    expect((await retainedSecret.json() as {settings:{passwordConfigured:boolean}}).settings.passwordConfigured).toBe(true);

    const adminRows=await request('/api/admin/users');
    const currentAdmin=(await adminRows.json() as {users:{id:string;username:string}[]}).users.find(entry=>entry.username==='integration-admin')!;
    const selfReset=await request(`/api/admin/users/${currentAdmin.id}/password`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:'SelfReset9'})},true);
    expect(selfReset.status).toBe(400);
    expect(refreshedAuth.csrfToken).toEqual(expect.any(String));
    const deleteUser=await request(`/api/admin/users/${created.id}`,{method:'DELETE'},true);
    expect(deleteUser.status).toBe(204);
    const bootstrapDatabase=new Database(path.join(testDirectory,'integration.sqlite'),{readonly:true});
    expect(bootstrapDatabase.prepare('PRAGMA table_info(users)').all()).toEqual(expect.arrayContaining([
      expect.objectContaining({name:'email'}),expect.objectContaining({name:'phone'}),expect.objectContaining({name:'first_name'}),expect.objectContaining({name:'last_name'}),expect.objectContaining({name:'nickname'}),expect.objectContaining({name:'job_title'}),expect.objectContaining({name:'division'}),expect.objectContaining({name:'department'}),
    ]));
    const legacyRoleConstraint=String((bootstrapDatabase.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get() as {sql:string}).sql);
    expect(legacyRoleConstraint).toContain("CHECK(role IN ('administrator','supervisor','quality_analyst','viewer'))");
    expect(bootstrapDatabase.prepare("SELECT name FROM pragma_table_info('users') WHERE name='access_role_id'").get()).toBeTruthy();
    bootstrapDatabase.close();
  }, 30_000);

  it('requires a current password and a strong new password for credential changes', async () => {
    const weak = await request('/api/auth/password', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ currentPassword: 'Integration-Test-Password-456!', newPassword: 'weak' }),
    }, true);
    expect(weak.status, await weak.clone().text()).toBe(400);
    const wrongCurrent = await request('/api/auth/password', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ currentPassword: 'not the current password', newPassword: 'Another-Integration-Password-456!' }),
    }, true);
    expect(wrongCurrent.status).toBe(401);
  });
});
