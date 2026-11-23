import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const databasePath = path.resolve(process.env.DATABASE_PATH || './runtime/recording-explorer.sqlite');
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
export const db = new Database(databasePath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
export function migrate() {
  const builtSchema = path.join(here, 'schema.sql');
  const sourceSchema = path.resolve('server/db/schema.sql');
  const schemaPath = fs.existsSync(builtSchema) ? builtSchema : sourceSchema;
  db.exec(fs.readFileSync(schemaPath, 'utf8'));
  const userColumns = new Set((db.prepare('PRAGMA table_info(users)').all() as { name: string }[]).map(column => column.name));
  const profileColumns: Record<string, string> = {
    email: "TEXT NOT NULL DEFAULT ''",
    phone: "TEXT NOT NULL DEFAULT ''",
    first_name: "TEXT NOT NULL DEFAULT ''",
    last_name: "TEXT NOT NULL DEFAULT ''",
    nickname: "TEXT NOT NULL DEFAULT ''",
    job_title: "TEXT NOT NULL DEFAULT ''",
    division: "TEXT NOT NULL DEFAULT ''",
    department: "TEXT NOT NULL DEFAULT ''",
  };
  for (const [column, definition] of Object.entries(profileColumns)) {
    if (!userColumns.has(column)) db.exec(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
  }
  if (!userColumns.has('access_role_id')) db.exec('ALTER TABLE users ADD COLUMN access_role_id TEXT REFERENCES access_roles(id) ON DELETE SET NULL');
  const libraryScheduleColumns=new Set((db.prepare('PRAGMA table_info(library_schedules)').all() as {name:string}[]).map(column=>column.name));
  if(!libraryScheduleColumns.has('run_time'))db.exec("ALTER TABLE library_schedules ADD COLUMN run_time TEXT NOT NULL DEFAULT '02:00'");
  if(!libraryScheduleColumns.has('run_requested'))db.exec('ALTER TABLE library_schedules ADD COLUMN run_requested INTEGER NOT NULL DEFAULT 0');
  if(!libraryScheduleColumns.has('lookback_days'))db.exec('ALTER TABLE library_schedules ADD COLUMN lookback_days INTEGER NOT NULL DEFAULT 550');
  const archivedRecordingColumns=new Set((db.prepare('PRAGMA table_info(archived_recordings)').all() as {name:string}[]).map(column=>column.name));
  if(!archivedRecordingColumns.has('flows'))db.exec("ALTER TABLE archived_recordings ADD COLUMN flows TEXT NOT NULL DEFAULT '[]'");
  if(!archivedRecordingColumns.has('interaction_type'))db.exec("ALTER TABLE archived_recordings ADD COLUMN interaction_type TEXT NOT NULL DEFAULT 'Unknown'");
  db.exec(`CREATE TABLE IF NOT EXISTS recording_playability (
    connection_id TEXT NOT NULL, conversation_id TEXT NOT NULL, recording_id TEXT NOT NULL,
    is_unplayable INTEGER NOT NULL DEFAULT 1 CHECK(is_unplayable IN (0,1)),
    marked_by TEXT NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY(connection_id,conversation_id,recording_id)
  )`);
  db.prepare(`UPDATE connections
    SET api_base_url='https://api.apse1.pure.cloud', oauth_base_url='https://login.apse1.pure.cloud',
        last_success_at=NULL, last_error=NULL, updated_at=?
    WHERE region_id='ap-southeast-1'
      AND api_base_url='https://api.mypurecloud.com.sg'
      AND oauth_base_url='https://login.mypurecloud.com.sg'`).run(new Date().toISOString());
}
