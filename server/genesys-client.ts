import { decrypt } from './security.js';
import type { Connection } from './genesys.js';

type Token = { value: string; expires: number };
const tokens = new Map<string, Token>();
const tokenRequests = new Map<string, Promise<string>>();
const rateLimitedUntil = new Map<string, number>();
const requestNextAt = new Map<string, number>();
const requestTails = new Map<string, Promise<void>>();
const MIN_REQUEST_INTERVAL_MS = 350;
export class GenesysError extends Error { constructor(public status: number, message: string, public retryAfterMs = 0) { super(message); } }

async function waitForRequestSlot(connectionId:string){
  const previous=requestTails.get(connectionId)||Promise.resolve();
  let release!:()=>void;
  const current=new Promise<void>(resolve=>{release=resolve;});
  requestTails.set(connectionId,current);
  await previous;
  const startAt=Math.max(Date.now(),requestNextAt.get(connectionId)||0);
  const wait=startAt-Date.now();
  if(wait)await new Promise(resolve=>setTimeout(resolve,wait));
  requestNextAt.set(connectionId,Date.now()+MIN_REQUEST_INTERVAL_MS);
  release();
}

function retryDelay(response:Response, fallbackMs:number, maxMs=24*60*60_000) {
  const header=response.headers.get('retry-after');
  if(header){const seconds=Number(header);if(Number.isFinite(seconds)&&seconds>=0)return Math.min(maxMs,Math.max(1000,seconds*1000));const date=Date.parse(header);if(Number.isFinite(date))return Math.min(maxMs,Math.max(1000,date-Date.now()));}
  const reset=response.headers.get('inin-ratelimit-reset')||response.headers.get('x-ratelimit-reset')||response.headers.get('ratelimit-reset')||response.headers.get('x-rate-limit-reset');
  if(reset){const numeric=Number(reset);const timestamp=Number.isFinite(numeric)?(numeric<1e12?numeric*1000:numeric):Date.parse(reset);if(Number.isFinite(timestamp))return Math.min(maxMs,Math.max(1000,timestamp-Date.now()));}
  return Math.min(maxMs,fallbackMs);
}

function rateLimitMessage(waitMs:number) { return `Genesys API rate limit reached. Retry in about ${Math.ceil(waitMs/1000)} seconds.`; }
function assertNotRateLimited(connectionId:string){
  const blockedUntil=rateLimitedUntil.get(connectionId)||0;
  if(blockedUntil>Date.now())throw new GenesysError(429,rateLimitMessage(blockedUntil-Date.now()),blockedUntil-Date.now());
  if(blockedUntil)rateLimitedUntil.delete(connectionId);
}
export class GenesysClient {
  constructor(readonly connection: Connection) {}
  clearCachedToken() { tokens.delete(this.connection.id); }
  async accessToken() {
    if (process.env.MOCK_MODE === 'true') return 'mock-token';
    assertNotRateLimited(this.connection.id);
    const cached = tokens.get(this.connection.id);
    if (cached && cached.expires > Date.now() + 30_000) return cached.value;
    const pending=tokenRequests.get(this.connection.id);if(pending)return pending;
    const request=(async()=>{
      await waitForRequestSlot(this.connection.id);
      assertNotRateLimited(this.connection.id);
      const secret = decrypt(this.connection.client_secret_enc);
      let response:Response;try{response = await fetch(`${this.connection.oauth_base_url}/oauth/token`, {
        method: 'POST', signal: AbortSignal.timeout(12000),
        redirect: 'manual',
        headers: { Authorization: `Basic ${Buffer.from(`${this.connection.client_id}:${secret}`).toString('base64')}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials' }),
      });}catch{throw new GenesysError(503,'Genesys authentication service could not be reached.');}
      if (!response.ok) {
        if(response.status===429){const waitMs=retryDelay(response,30_000);rateLimitedUntil.set(this.connection.id,Date.now()+waitMs);await response.body?.cancel().catch(()=>{});throw new GenesysError(429,rateLimitMessage(waitMs),waitMs);}
        await response.body?.cancel().catch(()=>{});
        throw new GenesysError(response.status >= 300 && response.status < 400 ? 502 : response.status, `Genesys authentication failed (HTTP ${response.status}).`);
      }
      const body = await response.json() as { access_token?: string; expires_in?: number };
      if (!body.access_token) throw new Error('Genesys OAuth response did not include an access token.');
      tokens.set(this.connection.id, { value: body.access_token, expires: Date.now() + Math.max(1, (body.expires_in ?? 3600) - 60) * 1000 });
      return body.access_token;
    })();
    tokenRequests.set(this.connection.id,request);
    try{return await request;}finally{if(tokenRequests.get(this.connection.id)===request)tokenRequests.delete(this.connection.id);}
  }
  async request<T>(method: 'GET' | 'POST', endpoint: string, payload?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
    if (process.env.MOCK_MODE === 'true') throw new Error('A real Genesys API request was attempted while Mock Mode is enabled.');
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = await this.accessToken();
      await waitForRequestSlot(this.connection.id);
      assertNotRateLimited(this.connection.id);
      let response: Response;
      try {
        response = await fetch(new URL(endpoint, `${this.connection.api_base_url}/`), {
          method, signal: AbortSignal.timeout(25000), redirect: 'manual',
          headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', ...extraHeaders, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
          body: payload ? JSON.stringify(payload) : undefined,
        });
      } catch { if(attempt<2&&method==='GET'){await new Promise(resolve=>setTimeout(resolve,250*(attempt+1)));continue;}throw new GenesysError(503,'Genesys API could not be reached.'); }
      if (response.ok) {
        if (response.status === 204) return undefined as T;
        const body = await response.text();
        if (!body.trim()) return undefined as T;
        try { return JSON.parse(body) as T; }
        catch { throw new GenesysError(502, 'Genesys API returned an invalid JSON response.'); }
      }
      if (response.status >= 300 && response.status < 400) throw new GenesysError(502, 'Genesys API returned an unexpected redirect.');
      if (response.status === 401 && attempt === 0) { tokens.delete(this.connection.id); continue; }
      if(response.status===429){
        const waitMs=retryDelay(response,30_000);
        rateLimitedUntil.set(this.connection.id,Date.now()+waitMs);
        await response.body?.cancel().catch(()=>{});
        throw new GenesysError(429,rateLimitMessage(waitMs),waitMs);
      }
      if ([502, 503, 504].includes(response.status)) {
        if (attempt < 2) {
          const retry = retryDelay(response,Math.min(5000,500*2**attempt),5000);
          await response.body?.cancel().catch(()=>{});
          await new Promise(resolve => setTimeout(resolve, retry)); continue;
        }
      }
      await response.body?.cancel().catch(()=>{});
      const message=response.status===403?'Genesys denied access. Verify service-account permissions and recording/division access.':response.status===400?'Genesys rejected the request (HTTP 400). Check the Analytics date interval and query filters.':`Genesys API request failed (HTTP ${response.status}).`;
      throw new GenesysError(response.status,message);
    }
    throw new Error('Genesys API request failed after retries.');
  }
  get<T>(path: string) { return this.request<T>('GET', path); }
  post<T>(path: string, body: unknown) { return this.request<T>('POST', path, body); }
}
export async function verifyGenesysApiAccess(client: GenesysClient) {
  const organization = await client.get<{ id?: string; name?: string }>('/api/v2/organizations/me');
  if (!organization || typeof organization !== 'object') throw new GenesysError(502, 'Genesys organization verification returned an invalid response.');
  return organization;
}
