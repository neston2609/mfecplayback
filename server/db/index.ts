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
  db.prepare(`UPDATE connections
    SET api_base_url='https://api.apse1.pure.cloud', oauth_base_url='https://login.apse1.pure.cloud',
        last_success_at=NULL, last_error=NULL, updated_at=?
    WHERE region_id='ap-southeast-1'
      AND api_base_url='https://api.mypurecloud.com.sg'
      AND oauth_base_url='https://login.mypurecloud.com.sg'`).run(new Date().toISOString());
}
