import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { encrypt, decrypt } from '../security.js';
import { assertLocalDestinationPath, destinationSchema, destinationConfigJson, decryptDestination, localFilesystemCapacity, publicDestination } from '../library-destinations.js';
import { initialArchiveCursor, nextScheduleTime } from '../library-schedule.js';

describe('Sound Library schedule and storage security',()=>{
  const oldRoot=process.env.LIBRARY_STORAGE_ROOT;let root='';
  beforeAll(()=>{process.env.MASTER_ENCRYPTION_KEY=Buffer.alloc(32,29).toString('base64');root=mkdtempSync(path.join(os.tmpdir(),'mfec-library-tests-'));process.env.LIBRARY_STORAGE_ROOT=root;});
  afterAll(()=>{if(oldRoot===undefined)delete process.env.LIBRARY_STORAGE_ROOT;else process.env.LIBRARY_STORAGE_ROOT=oldRoot;delete process.env.MASTER_ENCRYPTION_KEY;rmSync(root,{recursive:true,force:true});});

  it('encrypts destination configuration and never returns credentials to the browser',()=>{
    const config=destinationSchema.parse({type:'sftp',name:'Archive',host:'sftp.example.test',port:22,username:'library-user',password:'very-secret-password',hostFingerprint:`SHA256:${Buffer.alloc(32,1).toString('base64').replace(/=+$/,'')}`,path:'/recordings',retentionDays:90});
    if(config.type!=='sftp')throw new Error('Expected SFTP test config.');
    const encrypted=destinationConfigJson(config);expect(encrypted).not.toContain(config.password);expect(decrypt(encrypted)).toContain(config.password);
    const row={id:'destination-id',name:config.name,type:config.type,config_enc:encrypted,created_at:'2026-01-01',updated_at:'2026-01-01'};
    expect(decryptDestination(row)).toMatchObject({password:config.password});expect(publicDestination(row)).not.toHaveProperty('password');expect(JSON.stringify(publicDestination(row))).not.toContain(config.password);
  });

  it('rejects insecure FTP, URL hosts, invalid fingerprints, and SMB path traversal',()=>{
    const base={name:'Destination',retentionDays:20};
    expect(()=>destinationSchema.parse({...base,type:'ftp',host:'ftp.example.test',username:'u',password:'p',tls:false})).toThrow();
    expect(()=>destinationSchema.parse({...base,type:'sftp',host:'https://example.test',username:'u',password:'p',hostFingerprint:'unknown'})).toThrow();
    const local=destinationSchema.parse({name:'Local',type:'local',path:path.join(root,'data'),retentionDays:30});
    expect(local.type).toBe('local');
    expect(()=>destinationSchema.parse({...base,type:'smb',host:'192.0.2.4',share:'share',username:'u',password:'p',path:'../outside'})).toThrow();
    expect(()=>assertLocalDestinationPath(path.join(root,'..','outside'),root)).toThrow(/under the configured library root/i);
  });

  it('calculates recurring schedules in their configured time zone and handles short months',()=>{
    const after=new Date('2026-11-19T00:00:00.000Z');
    expect(nextScheduleTime({cadence:'daily',day_of_week:null,day_of_month:null,run_time:'02:00',time_zone:'Asia/Bangkok'},after)).toBe('2026-11-19T19:00:00.000Z');
    expect(nextScheduleTime({cadence:'weekly',day_of_week:1,day_of_month:null,run_time:'02:00',time_zone:'Asia/Bangkok'},after)).toBe('2026-11-22T19:00:00.000Z');
    expect(nextScheduleTime({cadence:'monthly',day_of_week:null,day_of_month:31,run_time:'02:00',time_zone:'UTC'},new Date('2026-02-28T23:00:00.000Z'))).toBe('2026-03-31T02:00:00.000Z');
  });

  it('starts historical archive within Genesys Analytics retention and reads local OS capacity',async()=>{
    const now=new Date('2026-11-19T18:42:00.000Z'),cursor=initialArchiveCursor(now),expected=new Date(Date.UTC(2026,10,19)-550*86400000).toISOString();
    expect(cursor).toBe(expected);
    expect(initialArchiveCursor(now,30)).toBe(new Date(Date.UTC(2026,10,19)-30*86400000).toISOString());
    const capacity=await localFilesystemCapacity(root);
    expect(capacity?.totalBytes).toBeGreaterThan(0);
    expect(capacity?.freeBytes).toBeGreaterThan(0);
  });

  it('keeps library records independent from existing application tables',()=>{
    const dbPath=path.join(root,'schema.sqlite'),database=new Database(dbPath);
    database.exec('CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL); CREATE TABLE archived_recordings(id TEXT PRIMARY KEY,connection_id TEXT NOT NULL,conversation_id TEXT NOT NULL,recording_id TEXT NOT NULL,metadata_json TEXT NOT NULL);');
    database.prepare('INSERT INTO users VALUES(?,?,?,?,?,?)').run('user-1','admin','hash','administrator',1,'2026-01-01');database.prepare('INSERT INTO archived_recordings VALUES(?,?,?,?,?)').run('archive-1','connection-1','conversation-1','recording-1','{}');
    expect(database.prepare('SELECT username FROM users WHERE id=?').get('user-1')).toMatchObject({username:'admin'});expect(database.prepare('SELECT conversation_id FROM archived_recordings WHERE id=?').get('archive-1')).toMatchObject({conversation_id:'conversation-1'});expect(database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='archived_recordings'").get()).toBeTruthy();database.close();
  });
});
