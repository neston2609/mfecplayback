import { db } from './db/index.js';

export const ACCESS_PERMISSION_KEYS = [
  'realtimePlayback',
  'realtimeDownload',
  'libraryPlayback',
  'libraryAdmin',
] as const;

export type AccessPermission = typeof ACCESS_PERMISSION_KEYS[number];
export type RolePermissions = Record<AccessPermission, boolean>;
export type AccessRole = { id: string; name: string; permissions: RolePermissions; builtIn: boolean; userCount?: number };

const DEFAULT_ROLES: Array<{ id: string; name: string; permissions: RolePermissions }> = [
  { id: 'administrator', name: 'Administrator', permissions: { realtimePlayback: true, realtimeDownload: true, libraryPlayback: true, libraryAdmin: true } },
  { id: 'supervisor', name: 'Supervisor', permissions: { realtimePlayback: true, realtimeDownload: true, libraryPlayback: true, libraryAdmin: false } },
  { id: 'quality_analyst', name: 'Quality Analyst', permissions: { realtimePlayback: true, realtimeDownload: true, libraryPlayback: true, libraryAdmin: false } },
  { id: 'viewer', name: 'Viewer', permissions: { realtimePlayback: true, realtimeDownload: false, libraryPlayback: true, libraryAdmin: false } },
];

export function normalizeRolePermissions(value: unknown): RolePermissions {
  const input = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const libraryAdmin = input.libraryAdmin === true;
  return Object.fromEntries(ACCESS_PERMISSION_KEYS.map(key => [key, key === 'libraryPlayback' ? libraryAdmin || input[key] === true : input[key] === true])) as RolePermissions;
}

export function ensureDefaultAccessRoles() {
  const insert = db.prepare('INSERT OR IGNORE INTO access_roles(id,name,permissions_json,built_in,created_at,updated_at) VALUES(?,?,?,?,?,?)');
  const now = new Date().toISOString();
  for (const role of DEFAULT_ROLES) insert.run(role.id, role.name, JSON.stringify(role.permissions), 1, now, now);
  db.prepare('UPDATE users SET access_role_id=role WHERE access_role_id IS NULL').run();
}

export function listAccessRoles(): AccessRole[] {
  const rows=db.prepare(`SELECT r.id,r.name,r.permissions_json AS permissionsJson,r.built_in AS builtIn,
    (SELECT COUNT(*) FROM users u WHERE COALESCE(u.access_role_id,u.role)=r.id) AS userCount
    FROM access_roles r ORDER BY CASE WHEN r.id='administrator' THEN 0 ELSE 1 END,r.name COLLATE NOCASE`).all() as Array<{id:string;name:string;permissionsJson:string;builtIn:number;userCount:number}>;
  return rows.map(row => ({ id: row.id, name: row.name, permissions: normalizeRolePermissions(JSON.parse(row.permissionsJson)), builtIn: Boolean(row.builtIn), userCount: Number(row.userCount) }));
}

export function permissionsFromRole(roleId: string): RolePermissions {
  return getRolePermissions(roleId);
}

export function getRolePermissions(roleId: string): RolePermissions {
  const row = db.prepare('SELECT permissions_json AS permissionsJson FROM access_roles WHERE id=?').get(roleId) as {permissionsJson:string}|undefined;
  if (row) {
    try { return normalizeRolePermissions(JSON.parse(row.permissionsJson)); } catch { return normalizeRolePermissions({}); }
  }
  return normalizeRolePermissions(DEFAULT_ROLES.find(role => role.id === roleId)?.permissions);
}

export function hasAccessPermission(roleId: string, permission: AccessPermission): boolean {
  return (roleId === 'administrator' && permission === 'libraryAdmin') || (permission === 'libraryPlayback' && getRolePermissions(roleId).libraryAdmin) || getRolePermissions(roleId)[permission];
}

export function canUseRecordingSearch(roleId: string): boolean {
  return hasAccessPermission(roleId, 'realtimePlayback');
}

export function roleName(roleId: string): string {
  return (db.prepare('SELECT name FROM access_roles WHERE id=?').get(roleId) as {name:string}|undefined)?.name || roleId;
}

export function isBuiltInRole(roleId: string): boolean {
  return Boolean((db.prepare('SELECT built_in FROM access_roles WHERE id=?').get(roleId) as {built_in:number}|undefined)?.built_in);
}

export function validateRoleName(name: unknown): string | null {
  if (typeof name !== 'string') return null;
  const value = name.trim();
  return value.length >= 2 && value.length <= 64 && !/[<>\u0000-\u001f]/.test(value) ? value : null;
}
