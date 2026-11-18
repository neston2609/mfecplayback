import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const root = process.cwd();
let testDirectory = '';
let child: ChildProcess | undefined;
let baseUrl = '';
let cookie = '';
let csrf = '';
let serverOutput = '';

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
    const port = await freePort();
    baseUrl = `http://127.0.0.1:${port}`;
    child = spawn(process.execPath, ['--import', 'tsx', 'server/index.ts'], {
      cwd: root,
      env: {
        ...process.env,
        NODE_ENV: 'test', PORT: String(port), HOST: '127.0.0.1',
        APP_ORIGIN: 'http://localhost:5173', TRUST_PROXY: 'false', MOCK_MODE: 'true',
        SESSION_SECRET: 'integration-test-session-secret-with-sufficient-entropy',
        MASTER_ENCRYPTION_KEY: Buffer.alloc(32, 17).toString('base64'),
        DATABASE_PATH: path.join(testDirectory, 'integration.sqlite'),
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
    const result = await search.json() as { mock: boolean; results: { conversationId: string; recordingCount: number }[] };
    expect(result.mock).toBe(true);
    expect(result.results).toHaveLength(3);
    expect(result.results.every(row => row.recordingCount > 0)).toBe(true);

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
    const allConversations = await missingRecording.json() as { results: { recordingCount: number }[]; pageSize: number };
    expect(allConversations.results).toHaveLength(4);
    expect(allConversations.results.some(row => row.recordingCount === 0)).toBe(true);
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
    const tooWide = await request('/api/recordings/search', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ connectionId: 'mock', intervalStart: '2026-11-01T00:00:00.000Z', intervalEnd: '2026-11-17T00:00:00.000Z', pageNumber: 1, pageSize: 25 }),
    }, true);
    expect(tooWide.status).toBe(400);
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
