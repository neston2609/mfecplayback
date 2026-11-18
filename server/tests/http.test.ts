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
    expect(result.results.every(row => row.recordingCount === 1)).toBe(true);
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

    const disable = await request(`/api/admin/users/${created.id}/enabled`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled: false }),
    }, true);
    expect(disable.status, await disable.clone().text()).toBe(200);
    const revoked = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: viewerCookie, 'x-csrf-token': viewerAuth.csrfToken } });
    expect(revoked.status).toBe(401);
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
