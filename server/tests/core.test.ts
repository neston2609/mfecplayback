import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_REGIONS, trustedBaseUrl, validateRegionEndpoints } from '../regions.js';
import { encrypt, decrypt } from '../security.js';
import { MOCK_CONVERSATIONS, MOCK_RECORDINGS } from '../mock.js';
import { GenesysClient, verifyGenesysApiAccess } from '../genesys-client.js';

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

});
