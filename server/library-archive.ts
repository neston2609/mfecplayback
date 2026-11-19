import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { db } from './db/index.js';
import { connectionById, type Connection } from './genesys.js';
import { GenesysClient, GenesysError } from './genesys-client.js';
import { decryptDestination, deleteDestinationFile, readDestinationFile, readDestinationFileBuffer, writeDestinationFile, type DestinationRow } from './library-destinations.js';
import { getRecordingMedia, isMessageRecording, isVoiceRecording, isZipMediaContentType, listVoiceRecordings, validateRecordingMediaUrl } from './recording-media.js';
import { summarizeConversation } from './conversation-summary.js';
import { extractSingleAudioFromZip } from './zip-audio.js';
import { initialArchiveCursor, nextScheduleTime } from './library-schedule.js';
import { VOICE_RECORDING_FILTERS } from './conversation-query.js';
import { DEFAULT_RECORDING_OUTPUT_FORMAT, genesysMediaFormatKey, parseRecordingOutputFormat, preferredGenesysInputFormat, transcodeRecordingAudio, type RecordingOutputFormat } from './audio-transcode.js';

const DAY=86400000, PAGE_SIZE=100, MAX_PAGES_PER_WINDOW=100, WINDOWS_PER_TICK=2, ITEMS_PER_TICK=5;
type Schedule={id:string;name:string;connection_id:string;destination_id:string;cadence:'daily'|'weekly'|'monthly';day_of_week:number|null;day_of_month:number|null;run_time:string;time_zone:string;enabled:number;cursor_at:string;backfill_complete:number;next_run_at:string;run_status:string;last_started_at:string|null};
type QueueItem={id:number;schedule_id:string;conversation_id:string;conversation_start:string;attempts:number};
type ArchiveDeps={clientFor?:(connection:Connection)=>GenesysClient;writeFile?:typeof writeDestinationFile;now?:()=>Date;fetchMedia?:typeof fetch;outputFormat?:()=>RecordingOutputFormat;transcode?:typeof transcodeRecordingAudio};

export { nextScheduleTime } from './library-schedule.js';

function jsonSafe(value:any):any {
  if(Array.isArray(value))return value.map(jsonSafe);
  if(value&&typeof value==='object'){const result:Record<string,unknown>={};for(const [key,item] of Object.entries(value)){if(/token|secret|authorization|mediaUri|signed|url/i.test(key))continue;result[key]=jsonSafe(item);}return result;}
  if(typeof value==='string')return value.slice(0,4000);
  return value;
}

function extensionFor(mimeType:string, metadata:any) {
  const format=String(metadata?.fileFormat||metadata?.format||'').toLowerCase();if(['wav','wave','mp3','webm','ogg','opus','m4a','mp4'].includes(format))return format==='wave'?'wav':format;
  if(mimeType.includes('wav'))return 'wav';if(mimeType.includes('mpeg'))return 'mp3';if(mimeType.includes('ogg'))return 'ogg';if(mimeType.includes('mp4'))return 'm4a';if(mimeType.includes('webm'))return 'webm';return 'audio';
}

async function getMediaBytes(client:GenesysClient,connection:Connection,conversationId:string,recordingId:string,fetchMedia:typeof fetch,inputFormat='WEBM') {
  const playable=await getRecordingMedia(client,conversationId,recordingId,undefined,inputFormat);if(!playable)return undefined;
  const mediaUris=playable.metadata?.mediaUris;
  if(mediaUris&&typeof mediaUris==='object'&&!Array.isArray(mediaUris)&&!Object.keys(mediaUris).some(key=>genesysMediaFormatKey(key)===genesysMediaFormatKey(inputFormat)))return undefined;
  let voiceContext:any;
  if(!(typeof playable.metadata?.mediaType==='string'&&playable.metadata.mediaType.toLowerCase()==='voice'))voiceContext=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);
  if(!isVoiceRecording(playable.metadata,voiceContext)||isMessageRecording(playable.metadata))return undefined;
  let url=validateRecordingMediaUrl(playable.mediaUri,connection),response:Response|undefined;
  for(let redirects=0;redirects<=2;redirects++){
    try{response=await fetchMedia(url,{signal:AbortSignal.timeout(30000),redirect:'manual'});}catch{throw new Error('Genesys recording media could not be reached.');}
    if(response.status<300||response.status>=400)break;
    const location=response.headers.get('location');if(!location||redirects===2)throw new Error('Genesys recording media returned an invalid redirect.');url=validateRecordingMediaUrl(new URL(location,url).toString(),connection);
  }
  if(!response||!response.ok){await response?.body?.cancel().catch(()=>{});throw new Error(`Genesys recording media request failed (HTTP ${response?.status||0}).`);}
  if(Number(response.headers.get('content-length')||0)>256*1024*1024){await response.body?.cancel().catch(()=>{});throw new Error('Recording exceeds the 256 MB archive limit.');}
  if(!response.body)throw new Error('Genesys returned an empty recording media response.');
  const reader=response.body.getReader(),chunks:Buffer[]=[];let size=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>256*1024*1024){await reader.cancel();throw new Error('Recording exceeds the 256 MB archive limit.');}chunks.push(Buffer.from(value));}}finally{reader.releaseLock();}
  const mimeType=(response.headers.get('content-type')||'application/octet-stream').split(';')[0].toLowerCase();let bytes=Buffer.concat(chunks,size);
  if(isZipMediaContentType(mimeType)){const extracted=extractSingleAudioFromZip(bytes);bytes=extracted.audio;return {bytes,mimeType:extracted.mimeType,extension:extracted.filename.split('.').pop()||'audio',metadata:playable.metadata};}
  if(!/^audio\//.test(mimeType)&&mimeType!=='application/octet-stream'&&!mimeType.startsWith('video/webm'))throw new Error('Genesys returned an unsupported recording media type.');
  return {bytes,mimeType,extension:extensionFor(mimeType,playable.metadata),metadata:playable.metadata};
}

export class LibraryArchiveWorker {
  private timer:NodeJS.Timeout|undefined;private running=false;
  constructor(private readonly deps:ArchiveDeps={}){}
  start(){if(this.timer)return;this.timer=setInterval(()=>void this.tick(),30000);this.timer.unref();void this.tick();}
  stop(){if(this.timer)clearInterval(this.timer);this.timer=undefined;}
  async tick(){if(this.running)return;this.running=true;try{this.purgeExpired().catch(()=>{});const schedules=db.prepare("SELECT * FROM library_schedules WHERE enabled=1 OR run_requested=1 ORDER BY created_at").all() as Schedule[];for(const schedule of schedules){try{await this.runSchedule(schedule);}catch(error){const limited=error instanceof GenesysError&&error.status===429;db.prepare("UPDATE library_schedules SET run_status=?,run_requested=CASE WHEN ? THEN run_requested ELSE 0 END,last_error=?,updated_at=? WHERE id=?").run(limited?'queued':'failed',Number(limited),safeError(error),this.now().toISOString(),schedule.id);if(limited)break;}}}finally{this.running=false;}}
  private now(){return this.deps.now?.()||new Date();}
  private async runSchedule(schedule:Schedule){
    const now=this.now();
    const due=Date.parse(schedule.next_run_at)<=now.getTime();
    if(!schedule.backfill_complete||due){await this.enqueueWindows(schedule,now);}
    const pending=db.prepare("SELECT * FROM library_archive_queue WHERE schedule_id=? AND status='pending' AND attempts<5 ORDER BY conversation_start,id LIMIT ?").all(schedule.id,ITEMS_PER_TICK) as QueueItem[];
    if(pending.length){db.prepare("UPDATE library_schedules SET run_status='running',last_started_at=?,last_error=NULL,updated_at=? WHERE id=?").run(now.toISOString(),now.toISOString(),schedule.id);for(const item of pending){await this.archiveConversation(schedule,item);}}
    const stillPending=Number((db.prepare("SELECT COUNT(*) AS n FROM library_archive_queue WHERE schedule_id=? AND status='pending' AND attempts<5").get(schedule.id) as {n:number}).n);
    const refreshed=db.prepare('SELECT * FROM library_schedules WHERE id=?').get(schedule.id) as Schedule;
    if(!stillPending&&refreshed.backfill_complete&&Date.parse(refreshed.cursor_at)>=now.getTime()-60000){
      if(Date.parse(refreshed.next_run_at)<=now.getTime()){const next=nextScheduleTime(refreshed,now);db.prepare("UPDATE library_schedules SET next_run_at=?,run_requested=0,run_status='idle',last_finished_at=?,updated_at=? WHERE id=?").run(next,now.toISOString(),now.toISOString(),schedule.id);}
    }else if(!stillPending&&refreshed.backfill_complete){db.prepare("UPDATE library_schedules SET run_status='idle',last_finished_at=?,updated_at=? WHERE id=?").run(now.toISOString(),now.toISOString(),schedule.id);}
    else if(!stillPending){db.prepare("UPDATE library_schedules SET run_status='queued',updated_at=? WHERE id=?").run(now.toISOString(),schedule.id);}
  }
  private async enqueueWindows(schedule:Schedule,now:Date){
    const client=this.clientFor(schedule.connection_id);
    const due=Date.parse(schedule.next_run_at)<=now.getTime();
    if(schedule.backfill_complete&&!due)return;
    let cursor=Date.parse(schedule.cursor_at);const earliest=Date.parse(initialArchiveCursor(now));if(!Number.isFinite(cursor)||cursor<earliest)cursor=earliest;
    const targetTime=now.getTime();
    for(let window=0;window<WINDOWS_PER_TICK&&cursor<targetTime;window++){
      const end=Math.min(targetTime,cursor+DAY);const interval=`${new Date(cursor).toISOString()}/${new Date(end).toISOString()}`;
      for(let page=1;page<=MAX_PAGES_PER_WINDOW;page++){
        const result=await client.post<{conversations?:any[];totalHits?:number;totalCount?:number}>('/api/v2/analytics/conversations/details/query',{interval,paging:{pageSize:PAGE_SIZE,pageNumber:page},order:'asc',orderBy:'conversationStart',...VOICE_RECORDING_FILTERS});
        const conversations=Array.isArray(result?.conversations)?result.conversations:[];
        const insert=db.prepare("INSERT INTO library_archive_queue(schedule_id,conversation_id,conversation_start,status,created_at) VALUES(?,?,?,'pending',?) ON CONFLICT(schedule_id,conversation_id) DO NOTHING");
        const transaction=db.transaction(()=>{for(const conversation of conversations){if(!conversation?.conversationId)continue;const start=Date.parse(conversation.conversationStart);if(Number.isFinite(start)&&start>=cursor&&start<end)insert.run(schedule.id,String(conversation.conversationId).slice(0,128),new Date(start).toISOString(),now.toISOString());}});transaction();
        const total=result?.totalHits??result?.totalCount;if(!conversations.length||conversations.length<PAGE_SIZE||(Number.isFinite(total)&&page*PAGE_SIZE>=Number(total)))break;
        if(page===MAX_PAGES_PER_WINDOW)throw new Error(`Genesys returned more than ${PAGE_SIZE*MAX_PAGES_PER_WINDOW} conversations in one day. Reduce archive search density or use a separate connection; the cursor remains unchanged.`);
      }
      cursor=end;db.prepare("UPDATE library_schedules SET cursor_at=?,backfill_complete=?,run_status='queued',updated_at=? WHERE id=?").run(new Date(cursor).toISOString(),Number(cursor>=targetTime),now.toISOString(),schedule.id);
    }
  }
  private clientFor(connectionId:string){const row=db.prepare('SELECT * FROM connections WHERE id=? AND enabled=1').get(connectionId) as Connection|undefined;if(!row)throw new Error('The scheduled Genesys connection is unavailable or disabled.');const user=db.prepare("SELECT id,role FROM users WHERE enabled=1 AND role='administrator' ORDER BY created_at LIMIT 1").get() as {id:string;role:string}|undefined;if(!user)throw new Error('No enabled administrator is available to authorize the archive connection.');const connection=connectionById(row.id,user.id,user.role);return this.deps.clientFor?.(connection)||new GenesysClient(connection);}
  private async archiveConversation(schedule:Schedule,item:QueueItem){
    const now=this.now().toISOString();
    try{
      const connection=this.connection(schedule.connection_id),client=this.clientFor(schedule.connection_id);const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(item.conversation_id)}/details`);const recordings=await listVoiceRecordings(client,item.conversation_id,conversation);
      const valid=recordings.filter((recording:any)=>Boolean(recording?.id||recording?.recordingId));
      if(!valid.length)throw new Error('Genesys did not return any verified voice recording metadata for this recorded interaction; it will be retried.');
       const summary=summarizeConversation(conversation,{}),destination=db.prepare('SELECT * FROM library_destinations WHERE id=?').get(schedule.destination_id) as DestinationRow|undefined;if(!destination)throw new Error('The archive destination was deleted.');const config=decryptDestination(destination);let archived=0,alreadyArchived=0,mediaPending=false;
        for(const recording of valid){const recordingId=String(recording.id||recording.recordingId);if(db.prepare('SELECT id FROM archived_recordings WHERE connection_id=? AND conversation_id=? AND recording_id=?').get(connection.id,item.conversation_id,recordingId)){alreadyArchived++;continue;}
          const outputFormat=this.outputFormat();let playable;try{playable=await getMediaBytes(client,connection,item.conversation_id,recordingId,this.deps.fetchMedia||fetch,preferredGenesysInputFormat(outputFormat));}catch(error){if(error instanceof GenesysError&&error.status===429)throw error;if(String((recording as any)?.mediaType||'').toLowerCase()==='voice')throw error;continue;}if(!playable){if(String((recording as any)?.mediaType||'').toLowerCase()==='voice')mediaPending=true;continue;}
         const source={mimeType:playable.mimeType,extension:playable.extension};const converted=await (this.deps.transcode||transcodeRecordingAudio)(playable.bytes,outputFormat),conversion={format:converted.format,sourceMimeType:source.mimeType,sourceExtension:source.extension};playable={...playable,bytes:converted.bytes,mimeType:converted.mimeType,extension:converted.extension};
        const date=summary.conversationStart.slice(0,10),folder=`${date}/${item.conversation_id}`,safeId=recordingId.replace(/[^a-zA-Z0-9_-]/g,'_'),fileName=`${safeId}.${playable.extension}`,relativePath=`${folder}/${fileName}`;
        const tempDir=await fs.mkdtemp(path.join(os.tmpdir(),'mfec-library-'));const audioPath=path.join(tempDir,fileName),metaPath=path.join(tempDir,`${fileName}.json`);
        try{
           await fs.writeFile(audioPath,playable.bytes,{mode:0o600});const metadata={conversationId:item.conversation_id,connectionId:connection.id,recordingId,conversation:{...summary,conversationEnd:conversation.conversationEnd||'',agents:summary.agents,queues:summary.queues},recording:{...jsonSafe(recording),...jsonSafe(playable.metadata)},conversion,archivedAt:now};await fs.writeFile(metaPath,JSON.stringify(metadata,null,2),{mode:0o600});
          await (this.deps.writeFile||writeDestinationFile)(config,relativePath,audioPath);await (this.deps.writeFile||writeDestinationFile)(config,`${relativePath}.json`,metaPath);
          const archiveId=crypto.randomUUID(),sha256=crypto.createHash('sha256').update(playable.bytes).digest('hex'),expiresAt=new Date(Date.parse(now)+config.retentionDays*DAY).toISOString();
          db.prepare('INSERT INTO archived_recordings(id,connection_id,conversation_id,recording_id,destination_id,relative_path,file_name,mime_type,size_bytes,sha256,conversation_start,conversation_end,direction,ani,dnis,agent_names,queues,duration_ms,metadata_json,archived_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(archiveId,connection.id,item.conversation_id,recordingId,destination.id,relativePath,fileName,playable.mimeType,playable.bytes.length,sha256,summary.conversationStart,conversation.conversationEnd||null,summary.direction||'',summary.ani||'',summary.dnis||'',JSON.stringify(summary.agents||[]),JSON.stringify(summary.queues||[]),Number(playable.metadata?.durationMs||recording.durationMs)||null,JSON.stringify(metadata),now,expiresAt);archived++;
        }finally{await fs.rm(tempDir,{recursive:true,force:true});}
      }
      if(mediaPending)throw new Error('Recording media is not ready yet; it will be retried automatically.');
       if(!archived&&valid.length>alreadyArchived)throw new Error('No playable voice recording media was available; the conversation will be retried instead of skipped.');
      db.prepare("UPDATE library_archive_queue SET status='done',last_error=NULL WHERE id=?").run(item.id);
      const failed=Number((db.prepare("SELECT COUNT(*) AS n FROM library_archive_queue WHERE schedule_id=? AND status='failed'").get(schedule.id) as {n:number}).n);if(failed===0)db.prepare("UPDATE library_schedules SET last_error=NULL WHERE id=?").run(schedule.id);
    }catch(error){if(error instanceof GenesysError&&error.status===429)throw error;const attempts=item.attempts+1,status=attempts>=5?'failed':'pending';db.prepare('UPDATE library_archive_queue SET status=?,attempts=?,last_error=? WHERE id=?').run(status,attempts,safeError(error),item.id);db.prepare('UPDATE library_schedules SET last_error=?,run_status=?,updated_at=? WHERE id=?').run(safeError(error),status==='failed'?'failed':'queued',this.now().toISOString(),schedule.id);}
  }
  private outputFormat(){const injected=this.deps.outputFormat?.();if(injected)return parseRecordingOutputFormat(injected);const row=db.prepare("SELECT value_json FROM application_settings WHERE key='recording_output_format'").get() as {value_json:string}|undefined;if(!row)return DEFAULT_RECORDING_OUTPUT_FORMAT;try{return parseRecordingOutputFormat(JSON.parse(row.value_json));}catch{return DEFAULT_RECORDING_OUTPUT_FORMAT;}}
  private connection(id:string){const row=db.prepare('SELECT * FROM connections WHERE id=? AND enabled=1').get(id) as Connection|undefined;if(!row)throw new Error('The scheduled Genesys connection is unavailable or disabled.');return row;}
  private async purgeExpired(){const rows=db.prepare('SELECT a.*,d.name AS name,d.type AS type,d.config_enc AS config_enc FROM archived_recordings a JOIN library_destinations d ON d.id=a.destination_id WHERE a.expires_at<? LIMIT 100').all(this.now().toISOString()) as (any&DestinationRow)[];for(const row of rows){try{const config=decryptDestination(row);await deleteDestinationFile(config,row.relative_path);await deleteDestinationFile(config,`${row.relative_path}.json`);db.prepare('DELETE FROM archived_recordings WHERE id=?').run(row.id);}catch{/* Keep the index row if storage deletion failed; retry on the next sweep. */}}}
}

function safeError(error:unknown){return (error instanceof Error?error.message:'Archive failed.').replace(/\s+/g,' ').slice(0,240);}

export function listLibrary(query:string,limit:number,offset:number,connectionIds:string[]|null){const conditions:string[]=[];const values:unknown[]=[];if(connectionIds){if(!connectionIds.length)return {items:[],total:0};conditions.push(`connection_id IN (${connectionIds.map(()=>'?').join(',')})`);values.push(...connectionIds);}if(query){const like=`%${query.replace(/[\\%_]/g,'\\$&')}%`;conditions.push("(conversation_id LIKE ? ESCAPE '\\' OR recording_id LIKE ? ESCAPE '\\' OR file_name LIKE ? ESCAPE '\\' OR ani LIKE ? ESCAPE '\\' OR dnis LIKE ? ESCAPE '\\' OR agent_names LIKE ? ESCAPE '\\' OR queues LIKE ? ESCAPE '\\')");values.push(like,like,like,like,like,like,like);}const where=conditions.length?`WHERE ${conditions.join(' AND ')}`:'';const total=Number((db.prepare(`SELECT COUNT(*) AS n FROM archived_recordings ${where}`).get(...values) as {n:number}).n);const items=db.prepare(`SELECT a.id,a.connection_id AS connectionId,a.conversation_id AS conversationId,a.recording_id AS recordingId,a.destination_id AS destinationId,d.name AS destinationName,d.type AS destinationType,a.relative_path AS relativePath,a.file_name AS fileName,a.mime_type AS mimeType,a.size_bytes AS sizeBytes,a.conversation_start AS conversationStart,a.conversation_end AS conversationEnd,a.direction,a.ani,a.dnis,a.agent_names AS agentNames,a.queues,a.duration_ms AS durationMs,a.archived_at AS archivedAt,a.expires_at AS expiresAt FROM archived_recordings a JOIN library_destinations d ON d.id=a.destination_id ${where} ORDER BY a.conversation_start DESC,a.archived_at DESC LIMIT ? OFFSET ?`).all(...values,limit,offset);return {items,total};}

export function archivedRecordingById(id:string){return db.prepare('SELECT a.*,d.name AS destination_name,d.type,d.config_enc FROM archived_recordings a JOIN library_destinations d ON d.id=a.destination_id WHERE a.id=?').get(id) as (Record<string,any>&DestinationRow)|undefined;}
export async function archivedRecordingStream(row:Record<string,any>){return readDestinationFile(decryptDestination(row as unknown as DestinationRow),String(row.relative_path));}
export async function archivedRecordingMetadata(row:Record<string,any>){const config=decryptDestination(row as unknown as DestinationRow);try{const bytes=await readDestinationFileBuffer(config,`${row.relative_path}.json`);return JSON.parse(bytes.toString('utf8'));}catch(error){if(row.metadata_json)return JSON.parse(row.metadata_json);throw error;}}
export function retryFailedArchive(scheduleId:string){return db.prepare("UPDATE library_archive_queue SET status='pending',attempts=0,last_error=NULL WHERE schedule_id=? AND status='failed'").run(scheduleId).changes;}
