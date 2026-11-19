import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import Database from 'better-sqlite3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
let testDirectory = '';
let child: ChildProcess | undefined;
let baseUrl = '';
let cookie = '';
let csrf = '';
let serverOutput = '';
let ffmpegFixture = '';

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
        MASTER_ENCRYPTION_KEY: Buffer.alloc(32, 17).toString('base64'),
        DATABASE_PATH: path.join(testDirectory, 'integration.sqlite'),
        LIBRARY_STORAGE_ROOT: path.join(testDirectory,'library-storage'),
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

    const mockConnections = await request('/api/genesys/connections');
    expect(mockConnections.status).toBe(200);
    const listedConnections = await mockConnections.json() as { connections: { id: string; mock?: boolean }[] };
    expect(listedConnections.connections).toHaveLength(1);
    expect(listedConnections.connections[0]).toMatchObject({ id: 'mock', mock: true });

    const destinations=await request('/api/library/destinations');
    expect(destinations.status).toBe(200);
    expect(await destinations.json()).toMatchObject({destinations:[],recordingOutputFormat:'m4a'});
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
      const converted=await transcodeRecordingAudio(await fs.readFile(ffmpegFixture),'mp3');
      const output=path.join(testDirectory,`converted.${converted.extension}`);
      await fs.writeFile(output,converted.bytes);
      expect(()=>execFileSync(process.env.FFMPEG_PATH!,['-hide_banner','-loglevel','error','-i',output,'-f','null','-'],{stdio:'ignore'})).not.toThrow();
      expect(converted.mimeType).toBe('audio/mpeg');
      expect(converted.bytes.length).toBeGreaterThan(0);
    }
    const schedules=await request('/api/library/schedules');
    expect(schedules.status).toBe(200);
    expect(await schedules.json()).toMatchObject({schedules:[]});
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
    const mockSchedule=await request('/api/library/schedules',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'Backfill',connectionId:'00000000-0000-4000-8000-000000000001',destinationId:'00000000-0000-4000-8000-000000000002',cadence:'daily',runTime:'02:00',timeZone:'Asia/Bangkok'})},true);
    expect(mockSchedule.status).toBe(409);

    const noCsrf = await request('/api/recordings/search', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(noCsrf.status).toBe(403);
    const crossOrigin = await request('/api/genesys/connections', { headers: { Origin: 'https://attacker.example' } });
    expect(crossOrigin.status).toBe(403);

    const noCsrfConnectionTest = await request('/api/genesys/connections/test', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}),
    });
    expect(noCsrfConnectionTest.status).toBe(403);
    const mockConnectionTest = await request('/api/genesys/connections/test', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}),
    }, true);
    expect(mockConnectionTest.status).toBe(409);
    expect((await mockConnectionTest.json() as { error: string }).error).toMatch(/Mock Mode/i);

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

    const conversationRecordings=await request('/api/recordings/conversations/demo-ava-agent-001/recordings?connectionId=mock');
    expect(conversationRecordings.status).toBe(200);
    expect(await conversationRecordings.json()).toMatchObject([{id:'demo-recording-1',mediaType:'voice'}]);
    const mockConversationDetails=await request('/api/recordings/conversations/demo-ava-agent-001?connectionId=mock');
    expect(mockConversationDetails.status).toBe(200);
    expect(await mockConversationDetails.json()).toMatchObject({conversationId:'demo-ava-agent-001',wrapUpNotes:[{agent:'Nicha S.',note:'Customer confirmed the issue was resolved after the account settings were updated.'}]});
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
  });

  it('lists saved live connections after trusted-region validation without exposing endpoint or secret fields', async () => {
    const liveDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'mfec-recording-explorer-live-test-'));
    const port = await freePort();
    const liveUrl = `http://127.0.0.1:${port}`;
    let liveChild: ChildProcess | undefined;
    let liveOutput = '';
    let liveCookie = '';
    let liveCsrf = '';
    try {
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

    const create = await fetch(`${liveUrl}/api/genesys/connections`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: liveCookie, 'x-csrf-token': liveCsrf, Origin: 'http://localhost:5173' },
        body: JSON.stringify({
          name: 'Saved integration organization', organizationLabel: 'Integration', regionId: 'ap-southeast-1',
          clientId: 'integration-client-id', clientSecret: 'integration-secret-that-must-not-leak', enabled: true, isDefault: true,
        }),
      });
      expect(create.status).toBe(201);
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
    expect(await defaultAudit.json()).toMatchObject({ page: 1, pageSize: 25, totalPages: 1 });
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
    const viewerAdminPage = await fetch(`${baseUrl}/api/admin/users`, { headers: { Cookie: viewerCookie } });
    expect(viewerAdminPage.status).toBe(403);
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
