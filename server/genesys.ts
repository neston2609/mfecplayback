import { db } from './db/index.js';
import { getRegions } from './regions.js';
import { GenesysError } from './genesys-client.js';
export { GenesysClient, GenesysError, verifyGenesysApiAccess } from './genesys-client.js';

export type Connection = { id: string; name: string; organization_label: string; region_id: string; api_base_url: string; oauth_base_url: string; client_id: string; client_secret_enc: string; enabled: number; is_default: number };
export function connectionById(id: string, userId: string, role: string): Connection {
  if (process.env.MOCK_MODE === 'true') throw new GenesysError(409, 'Live Genesys connections are disabled while Mock Mode is active.');
  const row = db.prepare("SELECT c.* FROM connections c LEFT JOIN user_connection_access a ON a.connection_id=c.id WHERE c.id=? AND c.enabled=1 AND (?='administrator' OR a.user_id=?)").get(id, role, userId) as Connection | undefined;
  if (!row) throw new GenesysError(404, 'Connection not found or access denied.');
  const region = getRegions().find(value => value.id === row.region_id);
  if (!region || row.api_base_url !== region.api || row.oauth_base_url !== region.oauth) throw new GenesysError(500, 'Configured Genesys endpoints do not match a trusted region.');
  return row;
}
export function regions() { return getRegions(); }
