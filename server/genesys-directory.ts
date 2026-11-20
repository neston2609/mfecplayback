import type { GenesysClient } from './genesys-client.js';

export type DirectoryType = 'agent' | 'group' | 'queue';
export type DirectorySuggestion = { id: string; name: string };
export const MOCK_DIRECTORY: Record<DirectoryType, DirectorySuggestion[]> = {
  agent: [{ id: 'agent-101', name: 'Nicha S.' }, { id: 'agent-203', name: 'Krit P.' }, { id: 'agent-187', name: 'Pim R.' }],
  group: [{ id: 'group-support', name: 'Customer Support' }, { id: 'group-sales', name: 'Sales & Retention' }],
  queue: [{ id: 'queue-care', name: 'Customer Care' }, { id: 'queue-sales', name: 'Sales' }, { id: 'queue-retention', name: 'Retention' }],
};
export const MOCK_GROUP_MEMBERS: Record<string, string[]> = { 'group-support': ['agent-101'], 'group-sales': ['agent-203', 'agent-187'] };

function entities(value: any): any[] {
  if (Array.isArray(value)) return value;
  for (const candidate of [value?.entities, value?.results, value?.users, value?.groups, value?.queues, value?.data]) {
    if (Array.isArray(candidate)) return candidate;
    if (candidate && candidate !== value) {
      const nested = entities(candidate);
      if (nested.length) return nested;
    }
  }
  return [];
}

function suggestion(item: any): DirectorySuggestion | undefined {
  const id = String(item?.id || item?.userId || item?.groupId || item?.queueId || '');
  const name = String(item?.name || item?.displayName || [item?.firstName, item?.lastName].filter(Boolean).join(' ') || '').trim();
  return id && name ? { id, name } : undefined;
}

function queryBody(query: string) {
  return { pageSize: 25, pageNumber: 1, query: [{ type: 'CONTAINS', fields: ['name'], value: query }] };
}

export async function searchDirectory(client: GenesysClient, type: DirectoryType, query: string): Promise<DirectorySuggestion[]> {
  const needle = query.trim();
  if (needle.length < 2) return [];
  const paths=type==='agent'?['/api/v2/users/search']:type==='group'?['/api/v2/groups/search']:['/api/v2/routing/queues'];
  let response:any;
  for(const endpoint of paths){
    try{
      if(type==='queue'){
        response=await client.get<any>(`${endpoint}?name=${encodeURIComponent(`*${needle}*`)}&pageSize=100&pageNumber=1`);
      }else{
        response=await client.post<any>(endpoint,queryBody(needle));
      }
      break;
    }catch(error){
      if(type!=='queue'||!(error instanceof Error)||!('status'in error)||![400,404,405].includes(Number((error as any).status)))throw error;
    }
  }
  const needleLower = needle.toLocaleLowerCase();
  return entities(response)
    .map(suggestion)
    .filter((item): item is DirectorySuggestion => Boolean(item && item.name.toLocaleLowerCase().includes(needleLower)))
    .sort((a, b) => Number(!a.name.toLocaleLowerCase().startsWith(needleLower)) - Number(!b.name.toLocaleLowerCase().startsWith(needleLower)) || a.name.localeCompare(b.name))
    .slice(0, 25);
}

export async function resolveDirectorySelection(client: GenesysClient, type: DirectoryType, value: string): Promise<DirectorySuggestion[]> {
  const needle = value.trim();
  if (!needle) return [];
  const direct = await searchDirectory(client, type, needle);
  const exact = direct.filter(item => item.name.localeCompare(needle, undefined, { sensitivity: 'accent' }) === 0);
  return exact.length ? exact : direct.filter(item => item.name.toLocaleLowerCase() === needle.toLocaleLowerCase());
}

export async function groupMemberUserIds(client: GenesysClient, groupId: string): Promise<Set<string>> {
  const ids = new Set<string>();
  for (let pageNumber = 1; pageNumber <= 10; pageNumber++) {
    const response = await client.get<any>(`/api/v2/groups/${encodeURIComponent(groupId)}/members?pageSize=100&pageNumber=${pageNumber}`);
    const members = entities(response);
    for (const member of members) {
      const id = String(member?.userId || member?.id || member?.member?.id || '');
      if (id) ids.add(id);
    }
    if (!members.length || members.length < 100) break;
  }
  return ids;
}
