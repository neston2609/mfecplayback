import session from 'express-session';
import { db } from './db/index.js';

db.exec('CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, sess TEXT NOT NULL, expire INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions(expire);');

export class BetterSqliteSessionStore extends session.Store {
  private readonly cleanupTimer = setInterval(() => {
    try { db.prepare('DELETE FROM sessions WHERE expire<=?').run(Date.now()); } catch (error) { console.error('Session cleanup failed:', error); }
  }, 60 * 60 * 1000).unref();
  get(sid: string, callback: (err?: any, session?: session.SessionData | null) => void) {
    try {
      const row = db.prepare('SELECT sess,expire FROM sessions WHERE sid=?').get(sid) as { sess: string; expire: number } | undefined;
      if (!row) return callback(null, null);
      if (row.expire <= Date.now()) { db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); return callback(null, null); }
      callback(null, JSON.parse(row.sess) as session.SessionData);
    } catch (error) { callback(error); }
  }
  set(sid: string, value: session.SessionData, callback?: (err?: any) => void) {
    try {
      const cookie = value.cookie as session.Cookie;
      const expire = cookie?.expires ? new Date(cookie.expires).getTime() : Date.now() + Number(cookie?.maxAge || 8 * 3600000);
      db.prepare('INSERT INTO sessions(sid,sess,expire) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess,expire=excluded.expire').run(sid, JSON.stringify(value), expire);
      callback?.();
    } catch (error) { callback?.(error); }
  }
  destroy(sid: string, callback?: (err?: any) => void) {
    try { db.prepare('DELETE FROM sessions WHERE sid=?').run(sid); callback?.(); }
    catch (error) { callback?.(error); }
  }
  touch(sid: string, value: session.SessionData, callback?: (err?: any) => void) {
    try {
      const cookie = value.cookie as session.Cookie;
      const expire = cookie?.expires ? new Date(cookie.expires).getTime() : Date.now() + Number(cookie?.maxAge || 8 * 3600000);
      db.prepare('UPDATE sessions SET expire=? WHERE sid=?').run(expire, sid);
      callback?.();
    } catch (error) { callback?.(error); }
  }
  close() { clearInterval(this.cleanupTimer); }
}
