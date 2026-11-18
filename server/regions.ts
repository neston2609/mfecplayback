import { db } from './db/index.js';

export type GenesysRegion = { id: string; name: string; api: string; oauth: string };

export const DEFAULT_REGIONS: GenesysRegion[] = [
  { id: 'us-east-1', name: 'US East', api: 'https://api.mypurecloud.com', oauth: 'https://login.mypurecloud.com' },
  { id: 'us-east-2', name: 'US East 2 (Gov)', api: 'https://api.use2.us-gov-pure.cloud', oauth: 'https://login.use2.us-gov-pure.cloud' },
  { id: 'us-west-2', name: 'US West', api: 'https://api.usw2.pure.cloud', oauth: 'https://login.usw2.pure.cloud' },
  { id: 'eu-west-1', name: 'EU West (Ireland)', api: 'https://api.mypurecloud.ie', oauth: 'https://login.mypurecloud.ie' },
  { id: 'eu-central-1', name: 'EU Central (Frankfurt)', api: 'https://api.mypurecloud.de', oauth: 'https://login.mypurecloud.de' },
  { id: 'ap-southeast-1', name: 'AP Southeast 1 (Singapore)', api: 'https://api.apse1.pure.cloud', oauth: 'https://login.apse1.pure.cloud' },
  { id: 'ap-northeast-1', name: 'AP Northeast (Tokyo)', api: 'https://api.mypurecloud.jp', oauth: 'https://login.mypurecloud.jp' },
  { id: 'ap-southeast-2', name: 'AP Southeast 2 (Sydney)', api: 'https://api.mypurecloud.com.au', oauth: 'https://login.mypurecloud.com.au' },
];

const officialEndpointHost = (host: string, kind: 'api' | 'oauth') => {
  const prefix = kind === 'api' ? 'api' : 'login';
  if (!host.startsWith(`${prefix}.`)) return false;
  const suffix = host.slice(prefix.length + 1);
  if (suffix === 'mypurecloud.com' || suffix === 'mypurecloud.ie' || suffix === 'mypurecloud.de' || suffix === 'mypurecloud.jp' || suffix === 'mypurecloud.com.au') return true;
  return new Set([
    'use1.pure.cloud', 'usw2.pure.cloud', 'apse1.pure.cloud', 'apse2.pure.cloud',
    'apne1.pure.cloud', 'apne2.pure.cloud', 'apne3.pure.cloud', 'aps1.pure.cloud',
    'apse3.pure.cloud', 'ape1.pure.cloud', 'euw1.pure.cloud', 'euw2.pure.cloud',
    'euw3.pure.cloud', 'euc1.pure.cloud', 'euc2.pure.cloud', 'mec1.pure.cloud',
    'cac1.pure.cloud', 'mxc1.pure.cloud', 'sae1.pure.cloud', 'use2.us-gov-pure.cloud',
  ]).has(suffix);
};

const REGIONS_SETTING = 'genesys_regions';
export function getRegions(): GenesysRegion[] {
  const stored = db.prepare('SELECT value_json FROM application_settings WHERE key=?').get(REGIONS_SETTING) as { value_json: string } | undefined;
  if (!stored) return DEFAULT_REGIONS;
  try {
    const parsed = JSON.parse(stored.value_json);
    if (!Array.isArray(parsed)) return DEFAULT_REGIONS;
    const ids = new Set<string>();
    const endpoints = new Set<string>();
    const regions = parsed.map((value: unknown) => {
      if (!value || typeof value !== 'object') throw new Error('Invalid region.');
      const region = value as GenesysRegion;
      if (typeof region.id !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(region.id) || typeof region.name !== 'string' || typeof region.api !== 'string' || typeof region.oauth !== 'string' || ids.has(region.id)) throw new Error('Invalid region.');
      ids.add(region.id);
      const validated = validateRegionEndpoints(region.api, region.oauth);
      if (endpoints.has(validated.api) || endpoints.has(validated.oauth)) throw new Error('Duplicate region endpoint.');
      endpoints.add(validated.api);
      endpoints.add(validated.oauth);
      return { id: region.id, name: region.name, ...validated };
    });
    return regions;
  } catch { /* Fall through to safe built-in regions if stored settings are invalid. */ }
  return DEFAULT_REGIONS;
}

export function saveRegions(regions: GenesysRegion[]) {
  db.prepare(`INSERT INTO application_settings(key,value_json) VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json`).run(REGIONS_SETTING, JSON.stringify(regions));
}

export function validateRegionEndpoints(apiValue: string, oauthValue: string) {
  let api: URL, oauth: URL;
  try { api = new URL(apiValue); oauth = new URL(oauthValue); }
  catch { throw new Error('Enter valid HTTPS Genesys Cloud API and OAuth URLs.'); }
  for (const url of [api, oauth]) {
    if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password || url.port) {
      throw new Error('Genesys Cloud region URLs must be HTTPS origins without paths or credentials.');
    }
  }
  if (!officialEndpointHost(api.hostname.toLowerCase(), 'api') || !officialEndpointHost(oauth.hostname.toLowerCase(), 'oauth') || api.hostname.slice(4).toLowerCase() !== oauth.hostname.slice(6).toLowerCase()) {
    throw new Error('Only matching official Genesys Cloud API and OAuth region domains are allowed.');
  }
  return { api: api.origin, oauth: oauth.origin };
}

export function trustedBaseUrl(value: string, kind: 'api' | 'oauth', regions: GenesysRegion[] = DEFAULT_REGIONS) {
  let parsed:URL;try{parsed=new URL(value);}catch{throw new Error('The endpoint must exactly match an official Genesys Cloud region URL.');}
  const region = regions.find(r => (kind === 'api' ? r.api : r.oauth) === parsed.origin);
  if (!region || parsed.protocol!=='https:' || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password || parsed.port) {
    throw new Error('The endpoint must exactly match an official Genesys Cloud region URL.');
  }
  return parsed.origin;
}
