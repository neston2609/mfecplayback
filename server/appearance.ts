import { db } from './db/index.js';

export type Appearance = {
  theme: 'light' | 'dark';
  fontFamily: 'Prompt' | 'Century Gothic';
  fontSize: number;
};

export const DEFAULT_APPEARANCE: Appearance = {
  theme: 'light',
  fontFamily: 'Prompt',
  fontSize: 13,
};

const DEFAULT_SETTING = 'ui_appearance_default';

export function parseAppearance(value: unknown): Appearance {
  if (!value || typeof value !== 'object') throw new Error('Appearance settings are invalid.');
  const appearance = value as Record<string, unknown>;
  if (appearance.theme !== 'light' && appearance.theme !== 'dark') throw new Error('Theme must be light or dark.');
  if (appearance.fontFamily !== 'Prompt' && appearance.fontFamily !== 'Century Gothic') throw new Error('Font family is not supported.');
  if (typeof appearance.fontSize !== 'number' || !Number.isInteger(appearance.fontSize) || appearance.fontSize < 12 || appearance.fontSize > 24) throw new Error('Font size must be between 12px and 24px.');
  return { theme: appearance.theme, fontFamily: appearance.fontFamily, fontSize: appearance.fontSize };
}

export function getDefaultAppearance(): Appearance {
  const row = db.prepare('SELECT value_json FROM application_settings WHERE key=?').get(DEFAULT_SETTING) as { value_json: string } | undefined;
  if (!row) return DEFAULT_APPEARANCE;
  try { return parseAppearance(JSON.parse(row.value_json)); }
  catch { return DEFAULT_APPEARANCE; }
}

export function getUserAppearance(userId: string): Appearance | null {
  const row = db.prepare('SELECT appearance_json FROM user_appearance WHERE user_id=?').get(userId) as { appearance_json: string } | undefined;
  if (!row) return null;
  try { return parseAppearance(JSON.parse(row.appearance_json)); }
  catch { return null; }
}

export function saveDefaultAppearance(appearance: Appearance) {
  db.prepare(`INSERT INTO application_settings(key,value_json) VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json`).run(DEFAULT_SETTING, JSON.stringify(appearance));
}

export function saveUserAppearance(userId: string, appearance: Appearance) {
  db.prepare(`INSERT INTO user_appearance(user_id,appearance_json) VALUES(?,?)
    ON CONFLICT(user_id) DO UPDATE SET appearance_json=excluded.appearance_json`).run(userId, JSON.stringify(appearance));
}

export function clearUserAppearance(userId: string) {
  db.prepare('DELETE FROM user_appearance WHERE user_id=?').run(userId);
}
