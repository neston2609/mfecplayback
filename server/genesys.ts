import { db } from './db/index.js';
import { decrypt } from './security.js';
import { REGIONS } from './regions.js';

export type Connection = { id: string; name: string; organization_label: string; region_id: string; api_base_url: string; oauth_base_url: string; client_id: string; client_secret_enc: string; enabled: number; is_default: number };
type Token = { value: string; expires: number };
const tokens = new Map<string, Token>();
export class GenesysError extends Error { constructor(public status: number, message: string) { super(message); } }
export class GenesysClient {
  constructor(readonly connection: Connection) {}
  async accessToken() {
    if (process.env.MOCK_MODE === 'true') return 'mock-token';
    const cached = tokens.get(this.connection.id);
    if (cached && cached.expires > Date.now() + 30_000) return cached.value;
    const secret = decrypt(this.connection.client_secret_enc);
    let response:Response;try{response = await fetch(`${this.connection.oauth_base_url}/oauth/token`, {
      method: 'POST', signal: AbortSignal.timeout(12000),
      redirect: 'manual',
      headers: { Authorization: `Basic ${Buffer.from(`${this.connection.client_id}:${secret}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials' }),
    });}catch{throw new GenesysError(503,'Genesys authentication service could not be reached.');}
      if (!response.ok) throw new GenesysError(response.status >= 300 && response.status < 400 ? 502 : response.status, `Genesys authentication failed (HTTP ${response.status}).`);
    const body = await response.json() as { access_token?: string; expires_in?: number };
    if (!body.access_token) throw new Error('Genesys OAuth response did not include an access token.');
      tokens.set(this.connection.id, { value: body.access_token, expires: Date.now() + Math.max(1, (body.expires_in ?? 3600) - 60) * 1000 });
    return body.access_token;
  }
  async request<T>(method: 'GET' | 'POST', endpoint: string, payload?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
    if (process.env.MOCK_MODE === 'true') throw new Error('A real Genesys API request was attempted while Mock Mode is enabled.');
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = await this.accessToken();
      let response: Response;
      try {
        response = await fetch(new URL(endpoint, `${this.connection.api_base_url}/`), {
          method, signal: AbortSignal.timeout(25000), redirect: 'manual',
          headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...extraHeaders, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
          body: payload ? JSON.stringify(payload) : undefined,
        });
      } catch (error) { if (attempt < 2 && method === 'GET') {await new Promise(resolve=>setTimeout(resolve,250*(attempt+1)));continue;} throw new GenesysError(503,'Genesys API could not be reached.'); }
      if (response.ok) { if (response.status === 204) return undefined as T; return await response.json() as T; }
      if (response.status >= 300 && response.status < 400) throw new GenesysError(502, 'Genesys API returned an unexpected redirect.');
      if (response.status === 401 && attempt === 0) { tokens.delete(this.connection.id); continue; }
      if (response.status === 429 || [502, 503, 504].includes(response.status)) {
        if (attempt < 2) {
          const retry = Math.min(5000, Math.max(250, Number(response.headers.get('retry-after') || 1) * 1000));
          await new Promise(resolve => setTimeout(resolve, retry)); continue;
        }
      }
      throw new GenesysError(response.status, response.status === 403 ? 'Genesys denied access. Verify service-account permissions and recording/division access.' : `Genesys API request failed (HTTP ${response.status}).`);
    }
    throw new Error('Genesys API request failed after retries.');
  }
  get<T>(path: string) { return this.request<T>('GET', path); }
  post<T>(path: string, body: unknown) { return this.request<T>('POST', path, body); }
}
export function connectionById(id: string, userId: string, role: string): Connection {
  if (process.env.MOCK_MODE === 'true') throw new GenesysError(409, 'Live Genesys connections are disabled while Mock Mode is active.');
  const row = db.prepare("SELECT c.* FROM connections c LEFT JOIN user_connection_access a ON a.connection_id=c.id WHERE c.id=? AND c.enabled=1 AND (?='administrator' OR a.user_id=?)").get(id, role, userId) as Connection | undefined;
  if (!row) throw new GenesysError(404, 'Connection not found or access denied.');
  const region = REGIONS.find(value => value.id === row.region_id);
  if (!region || row.api_base_url !== region.api || row.oauth_base_url !== region.oauth) throw new GenesysError(500, 'Configured Genesys endpoints do not match a trusted region.');
  return row;
}
export function regions() { return REGIONS; }
