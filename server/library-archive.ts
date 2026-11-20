import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { db } from './db/index.js';
import { connectionById, type Connection } from './genesys.js';
import { GenesysClient, GenesysError } from './genesys-client.js';
import { decryptDestination, deleteDestinationFile, readDestinationFile, readDestinationFileBuffer, writeDestinationFile, type DestinationRow } from './library-destinations.js';
import type { ByteRange } from './audio-range.js';
import { getRecordingMedia, isMessageRecording, isVoiceRecording, isZipMediaContentType, listVoiceRecordings, recordingMediaUriForFormats, validateRecordingMediaUrl } from './recording-media.js';
import { archivedConversationDisplay, collectQueueIds, conversationQueueNames, summarizeConversation, withParticipantLines } from './conversation-summary.js';
import { mapParticipantUserNames } from './participant-users.js';
import { extractSingleAudioFromZip } from './zip-audio.js';
import { initialArchiveCursor, nextScheduleTime } from './library-schedule.js';
import { MAX_ANALYTICS_CONVERSATIONS, queryAllConversations, VOICE_RECORDING_FILTERS } from './conversation-query.js';
import { DEFAULT_RECORDING_OUTPUT_FORMAT, genesysMediaFormatKey, parseRecordingOutputFormat, preferredGenesysInputFormat, transcodeRecordingAudio, type RecordingOutputFormat } from './audio-transcode.js';

const DAY=86400000, WINDOWS_PER_TICK=2, ITEMS_PER_TICK=5;
type Schedule={id:string;name:string;connection_id:string;destination_id:string;cadence:'daily'|'weekly'|'monthly';day_of_week:number|null;day_of_month:number|null;run_time:string;time_zone:string;lookback_days:number;enabled:number;cursor_at:string;backfill_complete:number;next_run_at:string;run_status:string;last_started_at:string|null;run_requested?:number};
type QueueItem={id:number;schedule_id:string;conversation_id:string;conversation_start:string;attempts:number};
type ArchiveDeps={clientFor?:(connection:Connection)=>GenesysClient;writeFile?:typeof writeDestinationFile;now?:()=>Date;fetchMedia?:typeof fetch;outputFormat?:()=>RecordingOutputFormat;transcode?:typeof transcodeRecordingAudio};

async function resolveQueueNames(client:GenesysClient,conversation:any){
  const ids=collectQueueIds(conversation);if(!ids.length)return {};
  const names:Record<string,string>={};let cursor=0;
  async function worker(){while(true){const index=cursor++,id=ids[index];if(!id)return;try{const queue=await client.get<{name?:string}>(`/api/v2/routing/queues/${encodeURIComponent(id)}`);if(typeof queue?.name==='string'&&queue.name.trim())names[id]=queue.name.trim();}catch(error){if(!(error instanceof GenesysError&&[403,404].includes(error.status)))throw error;}}}
  await Promise.all(Array.from({length:Math.min(4,ids.length)},worker));return names;
}

export { nextScheduleTime } from './library-schedule.js';

function jsonSafe(value:any):any {
  if(Array.isArray(value))return value.map(jsonSafe);
  if(value&&typeof value==='object'){const result:Record<string,unknown>={};for(const [key,item] of Object.entries(value)){if(/token|secret|authorization|mediaUri|signed|url/i.test(key))continue;result[key]=jsonSafe(item);}return result;}
  if(typeof value==='string')return value.slice(0,4000);
  return value;
}

function visibleDirectionNumber(summary:any,row:any){
  const direction=String(summary?.direction||row?.direction||'').toLowerCase();
  if(direction==='outbound')return summary?.callbackNumber||summary?.ani||row?.ani||'';
  if(direction==='inbound')return summary?.dnis||row?.dnis||summary?.ani||row?.ani||'';
  return summary?.ani||row?.ani||summary?.dnis||row?.dnis||'';
}

function extensionFor(mimeType:string, metadata:any) {
  const format=String(metadata?.fileFormat||metadata?.format||'').toLowerCase();if(['wav','wave','mp3','webm','ogg','opus','m4a','mp4'].includes(format))return format==='wave'?'wav':format;
  if(mimeType.includes('wav'))return 'wav';if(mimeType.includes('mpeg'))return 'mp3';if(mimeType.includes('ogg'))return 'ogg';if(mimeType.includes('mp4'))return 'm4a';if(mimeType.includes('webm'))return 'webm';return 'audio';
}

async function getMediaBytes(client:GenesysClient,connection:Connection,conversationId:string,recordingId:string,fetchMedia:typeof fetch,inputFormat='WEBM') {
  const fallbackFormats=['WEBM','MP3','WAV','WAV_ULAW','OGG_OPUS','OGG_VORBIS','M4A','MP4'];
  let playable;
  try{playable=await getRecordingMedia(client,conversationId,recordingId,undefined,inputFormat,fallbackFormats,true);}
  catch(error){
    if(!(error instanceof GenesysError&&[400,404].includes(error.status)))throw error;
    const fallbacks=fallbackFormats.filter(format=>genesysMediaFormatKey(format)!==genesysMediaFormatKey(inputFormat));
    for(const format of fallbacks){
      try{playable=await getRecordingMedia(client,conversationId,recordingId,undefined,format,fallbackFormats,true);if(playable)break;}
      catch(fallbackError){if(!(fallbackError instanceof GenesysError&&[400,404].includes(fallbackError.status)))throw fallbackError;}
    }
    if(!playable)throw error;
  }
  if(!playable)return undefined;
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
  private timer:NodeJS.Timeout|undefined;private running=false;private refreshing=false;private rerunRequested=false;private activeScheduleId:string|undefined;
  constructor(private readonly deps:ArchiveDeps={}){}
  start(){if(this.timer)return;this.timer=setInterval(()=>void this.tick(),30000);this.timer.unref();void this.tick();}
  stop(){if(this.timer)clearInterval(this.timer);this.timer=undefined;}
  status(){
    const schedules=db.prepare("SELECT s.id,s.name,s.enabled,s.run_status,s.cursor_at,s.backfill_complete,s.last_started_at,s.last_finished_at,s.last_error,s.updated_at,s.run_requested,c.name AS connection_name,d.name AS destination_name,(SELECT COUNT(*) FROM library_archive_queue q WHERE q.schedule_id=s.id AND q.status='pending') AS pending_count,(SELECT COUNT(*) FROM library_archive_queue q WHERE q.schedule_id=s.id AND q.status='failed') AS failed_count FROM library_schedules s JOIN connections c ON c.id=s.connection_id JOIN library_destinations d ON d.id=s.destination_id ORDER BY s.created_at").all() as (Schedule&{connection_name:string;destination_name:string;last_finished_at:string|null;last_error:string|null;updated_at:string;pending_count:number;failed_count:number})[];
    const isArchiving=Boolean(this.activeScheduleId);
    const hasQueued=schedules.some(schedule=>Number(schedule.pending_count)>0||schedule.run_status==='queued'||schedule.run_requested===1);
    const hasFailed=schedules.some(schedule=>Number(schedule.failed_count)>0||schedule.run_status==='failed');
    const state=isArchiving?'archiving':hasQueued?'queued':hasFailed?'failed':'idle';
    return {state,checkedAt:this.now().toISOString(),schedules:schedules.map(({run_requested,...schedule})=>({...schedule,run_status:this.activeScheduleId===schedule.id?'running':Number(schedule.pending_count)>0?'queued':Number(schedule.failed_count)>0?'failed':schedule.run_status==='running'?'idle':schedule.run_status}))};
  }
  async tick(){if(this.refreshing||this.running){this.rerunRequested=true;return;}this.running=true;try{this.purgeExpired().catch(()=>{});const schedules=db.prepare("SELECT * FROM library_schedules WHERE enabled=1 OR run_requested=1 ORDER BY created_at").all() as Schedule[];for(const schedule of schedules){this.activeScheduleId=schedule.id;try{await this.runSchedule(schedule);}catch(error){const limited=error instanceof GenesysError&&error.status===429;db.prepare("UPDATE library_schedules SET run_status=?,run_requested=CASE WHEN ? THEN run_requested ELSE 0 END,last_error=?,updated_at=? WHERE id=?").run(limited?'queued':'failed',Number(limited),safeError(error),this.now().toISOString(),schedule.id);if(limited)break;}finally{this.activeScheduleId=undefined;}}}finally{this.activeScheduleId=undefined;this.running=false;if(this.rerunRequested){this.rerunRequested=false;setImmediate(()=>void this.tick());}}}
  private now(){return this.deps.now?.()||new Date();}
  async rearchive(row:Record<string,any>){
    if(this.running||this.refreshing)throw new GenesysError(409,'The archive worker is busy. Retry this refresh in a moment.');
    if(process.env.MOCK_MODE==='true')throw new GenesysError(409,'Re-archive is unavailable while Mock Mode is enabled.');
    this.refreshing=true;
    try{return await this.rearchiveUnlocked(row);}finally{this.refreshing=false;if(this.rerunRequested){this.rerunRequested=false;setImmediate(()=>void this.tick());}}
  }
  private async rearchiveUnlocked(row:Record<string,any>){
    const connection=this.connection(String(row.connection_id)),client=this.clientFor(connection.id);
    const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(String(row.conversation_id))}/details`);
    const recordings=await listVoiceRecordings(client,String(row.conversation_id),conversation);
    const recording=recordings.find((item:any)=>String(item?.id||item?.recordingId||'')===String(row.recording_id));
    if(!recording)throw new Error('Genesys no longer returns this voice recording. The archived copy has not been changed.');
    const namedConversation=await mapParticipantUserNames(client,conversation);
    const queueNames=await resolveQueueNames(client,namedConversation);
    const displayConversation=withParticipantLines(namedConversation);
    const summary={...summarizeConversation(namedConversation),queues:conversationQueueNames(namedConversation,queueNames)};
    const destination=db.prepare('SELECT * FROM library_destinations WHERE id=?').get(row.destination_id) as DestinationRow|undefined;
    if(!destination)throw new Error('The archive destination was deleted. The archived copy has not been changed.');
    const config=decryptDestination(destination),outputFormat=this.outputFormat();
    const playable=await getMediaBytes(client,connection,String(row.conversation_id),String(row.recording_id),this.deps.fetchMedia||fetch,preferredGenesysInputFormat(outputFormat));
    if(!playable)throw new Error('Genesys did not return playable voice media. The archived copy has not been changed.');
    const expectedDurationMs=Number(recording.durationMs||recording.duration||row.duration_ms||(summary.durationSeconds??0)*1000||0)||undefined;
    const converted=await (this.deps.transcode||transcodeRecordingAudio)(playable.bytes,outputFormat,undefined,expectedDurationMs);
    const archivedAt=this.now().toISOString(),date=(summary.conversationStart||String(row.conversation_start)).slice(0,10);
    const safeId=String(row.recording_id).replace(/[^a-zA-Z0-9_-]/g,'_');
    const revision=crypto.randomUUID();
    const fileName=`${safeId}.refresh-${revision}.${converted.extension}`;
    const relativePath=`${date}/${row.conversation_id}/${fileName}`;
    const conversion={format:converted.format,sourceMimeType:playable.mimeType,sourceExtension:playable.extension};
    const metadata={conversationId:row.conversation_id,connectionId:connection.id,recordingId:row.recording_id,conversation:{...summary,conversationEnd:conversation.conversationEnd||'',agents:summary.agents,flows:summary.flows,queues:summary.queues,interactionType:summary.interactionType,durationSeconds:summary.durationSeconds,participants:displayConversation.participants},recording:{...jsonSafe(recording),...jsonSafe(playable.metadata)},conversion,archivedAt};
    const tempDir=await fs.mkdtemp(path.join(os.tmpdir(),'mfec-library-refresh-'));
    const audioPath=path.join(tempDir,fileName),metaPath=path.join(tempDir,`${fileName}.json`);
    let wroteAudio=false,wroteMetadata=false;
    try{
      await fs.writeFile(audioPath,converted.bytes,{mode:0o600});
      await fs.writeFile(metaPath,JSON.stringify(metadata,null,2),{mode:0o600});
      await (this.deps.writeFile||writeDestinationFile)(config,relativePath,audioPath);wroteAudio=true;
      await (this.deps.writeFile||writeDestinationFile)(config,`${relativePath}.json`,metaPath);wroteMetadata=true;
      const actualAudio=await readDestinationFileBuffer(config,relativePath,256*1024*1024);
      const actualMetadata=await readDestinationFileBuffer(config,`${relativePath}.json`);
      const expectedMetadata=Buffer.from(JSON.stringify(metadata,null,2));
      if(!crypto.createHash('sha256').update(actualAudio).digest().equals(crypto.createHash('sha256').update(converted.bytes).digest())||!actualMetadata.equals(expectedMetadata))throw new Error('New archive files failed storage verification; the previous archive was kept.');
      const expiresAt=new Date(Date.parse(archivedAt)+config.retentionDays*DAY).toISOString();
      const durationMs=summary.durationSeconds===null?Number(playable.metadata?.durationMs||recording.durationMs)||null:summary.durationSeconds*1000;
      const applyUpdate=db.transaction(()=>db.prepare(`UPDATE archived_recordings SET relative_path=?,file_name=?,mime_type=?,size_bytes=?,sha256=?,conversation_start=?,conversation_end=?,direction=?,ani=?,dnis=?,agent_names=?,flows=?,queues=?,interaction_type=?,duration_ms=?,metadata_json=?,archived_at=?,expires_at=? WHERE id=?`).run(relativePath,fileName,converted.mimeType,converted.bytes.length,crypto.createHash('sha256').update(converted.bytes).digest('hex'),summary.conversationStart||row.conversation_start,conversation.conversationEnd||null,summary.direction||'',summary.ani||'',summary.dnis||'',JSON.stringify(summary.agents||[]),JSON.stringify(summary.flows||[]),JSON.stringify(summary.queues||[]),summary.interactionType||'Unknown',durationMs,JSON.stringify(metadata),archivedAt,expiresAt,row.id));
      const updated=applyUpdate();
      if(!updated.changes)throw new Error('Archived recording no longer exists; the new copy was not indexed.');
      if(row.relative_path&&row.relative_path!==relativePath){await deleteDestinationFile(config,String(row.relative_path)).catch(()=>{});await deleteDestinationFile(config,`${row.relative_path}.json`).catch(()=>{});}
      return {fileName,archivedAt,sizeBytes:converted.bytes.length};
    }catch(error){
      if(wroteAudio)await deleteDestinationFile(config,relativePath).catch(()=>{});
      if(wroteMetadata)await deleteDestinationFile(config,`${relativePath}.json`).catch(()=>{});
      throw error;
    }finally{await fs.rm(tempDir,{recursive:true,force:true});}
  }
  private async runSchedule(schedule:Schedule){
    const now=this.now();
    const currentLookback=db.prepare('SELECT lookback_days FROM library_schedules WHERE id=?').get(schedule.id) as {lookback_days:number}|undefined;
    if(currentLookback){const earliest=initialArchiveCursor(now,currentLookback.lookback_days);db.prepare('DELETE FROM library_archive_queue WHERE schedule_id=? AND conversation_start<?').run(schedule.id,earliest);schedule={...schedule,lookback_days:currentLookback.lookback_days,cursor_at:(db.prepare('SELECT cursor_at FROM library_schedules WHERE id=?').get(schedule.id) as {cursor_at:string}).cursor_at};}
    const manualRun=Number(schedule.run_requested)===1;
    db.prepare("UPDATE library_schedules SET run_status='running',last_started_at=?,last_error=NULL,updated_at=? WHERE id=?").run(now.toISOString(),now.toISOString(),schedule.id);
    // A manual run should produce recent recordings first, rather than making
    // the user wait for the entire 550-day initial backfill to reach today.
    if(manualRun){
      try{await this.enqueueRecentWindow(schedule,now);}
      catch(error){
        if(error instanceof GenesysError&&error.status===429)throw error;
        db.prepare("UPDATE library_schedules SET run_requested=0 WHERE id=?").run(schedule.id);
        throw error;
      }
      db.prepare("UPDATE library_schedules SET run_requested=0 WHERE id=?").run(schedule.id);
    }
    const due=Date.parse(schedule.next_run_at)<=now.getTime();
    if(!manualRun&&(!schedule.backfill_complete||due)){await this.enqueueWindows(schedule,now);}
    let pending:QueueItem[]=[];
    if(manualRun){
      const recentStart=new Date(now.getTime()-DAY).toISOString();
      pending=db.prepare("SELECT * FROM library_archive_queue WHERE schedule_id=? AND status='pending' AND attempts<5 AND conversation_start>=? ORDER BY conversation_start DESC,id DESC LIMIT ?").all(schedule.id,recentStart,ITEMS_PER_TICK) as QueueItem[];
    }
    if(!pending.length)pending=db.prepare("SELECT * FROM library_archive_queue WHERE schedule_id=? AND status='pending' AND attempts<5 ORDER BY conversation_start DESC,id DESC LIMIT ?").all(schedule.id,ITEMS_PER_TICK) as QueueItem[];
    for(const item of pending){
      const lookback=db.prepare('SELECT lookback_days FROM library_schedules WHERE id=?').get(schedule.id) as {lookback_days:number}|undefined;
      const earliest=Date.parse(initialArchiveCursor(this.now(),lookback?.lookback_days||schedule.lookback_days||550));
      if(Date.parse(item.conversation_start)<earliest){db.prepare('DELETE FROM library_archive_queue WHERE id=?').run(item.id);continue;}
      await this.archiveConversation(schedule,item);
    }
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
    let cursor=Date.parse(schedule.cursor_at);const earliest=Date.parse(initialArchiveCursor(now,Number(schedule.lookback_days)||550));if(!Number.isFinite(cursor)||cursor<earliest)cursor=earliest;
    let expectedCursor=schedule.cursor_at;
    const targetTime=now.getTime();
    for(let window=0;window<WINDOWS_PER_TICK&&cursor<targetTime;window++){
      const end=Math.min(targetTime,cursor+DAY);await this.enqueueWindow(client,schedule,cursor,end,now);
      const stored=db.prepare('SELECT cursor_at FROM library_schedules WHERE id=?').get(schedule.id) as {cursor_at:string}|undefined;
      if(!stored||stored.cursor_at!==expectedCursor)return;
      cursor=end;const nextCursor=new Date(cursor).toISOString();const updated=db.prepare("UPDATE library_schedules SET cursor_at=?,backfill_complete=?,run_status='queued',updated_at=? WHERE id=? AND cursor_at=?").run(nextCursor,Number(cursor>=targetTime),now.toISOString(),schedule.id,expectedCursor);
      if(!updated.changes)return;
      expectedCursor=nextCursor;
    }
  }
  private async enqueueRecentWindow(schedule:Schedule,now:Date){
    const end=now.getTime(),start=end-DAY,client=this.clientFor(schedule.connection_id);
    await this.enqueueWindow(client,schedule,start,end,now);
  }
  private async enqueueWindow(client:GenesysClient,schedule:Schedule,start:number,end:number,now:Date){
    const interval=`${new Date(start).toISOString()}/${new Date(end).toISOString()}`;
    const {conversations,partial}=await queryAllConversations(client,interval,VOICE_RECORDING_FILTERS,MAX_ANALYTICS_CONVERSATIONS);
    if(partial)throw new Error(`Genesys returned more than ${MAX_ANALYTICS_CONVERSATIONS} conversations in one archive window. Reduce archive search density or use a separate connection; the cursor remains unchanged.`);
    const insert=db.prepare("INSERT INTO library_archive_queue(schedule_id,conversation_id,conversation_start,status,created_at) VALUES(?,?,?,'pending',?) ON CONFLICT(schedule_id,conversation_id) DO NOTHING");
    const currentLookback=db.prepare('SELECT lookback_days FROM library_schedules WHERE id=?').get(schedule.id) as {lookback_days:number}|undefined;
    const earliest=Date.parse(initialArchiveCursor(now,currentLookback?.lookback_days||schedule.lookback_days||550));
    const transaction=db.transaction(()=>{for(const conversation of conversations){if(!conversation?.conversationId)continue;const conversationStart=Date.parse(conversation.conversationStart);if(Number.isFinite(conversationStart)&&conversationStart>=start&&conversationStart<end&&conversationStart>=earliest)insert.run(schedule.id,String(conversation.conversationId).slice(0,128),new Date(conversationStart).toISOString(),now.toISOString());}});transaction();
  }
  private clientFor(connectionId:string){const row=db.prepare('SELECT * FROM connections WHERE id=? AND enabled=1').get(connectionId) as Connection|undefined;if(!row)throw new Error('The scheduled Genesys connection is unavailable or disabled.');const user=db.prepare("SELECT id,role FROM users WHERE enabled=1 AND role='administrator' ORDER BY created_at LIMIT 1").get() as {id:string;role:string}|undefined;if(!user)throw new Error('No enabled administrator is available to authorize the archive connection.');const connection=connectionById(row.id,user.id,user.role);return this.deps.clientFor?.(connection)||new GenesysClient(connection);}
  private async archiveConversation(schedule:Schedule,item:QueueItem){
    const now=this.now().toISOString();
    try{
      const currentLookback=db.prepare('SELECT lookback_days FROM library_schedules WHERE id=?').get(schedule.id) as {lookback_days:number}|undefined;
      const earliest=Date.parse(initialArchiveCursor(this.now(),currentLookback?.lookback_days||schedule.lookback_days||550));
      if(Date.parse(item.conversation_start)<earliest){db.prepare('DELETE FROM library_archive_queue WHERE id=?').run(item.id);return;}
      const connection=this.connection(schedule.connection_id),client=this.clientFor(schedule.connection_id);const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(item.conversation_id)}/details`);const recordings=await listVoiceRecordings(client,item.conversation_id,conversation);
      const valid=recordings.filter((recording:any)=>Boolean(recording?.id||recording?.recordingId));
      if(!valid.length)throw new Error('Genesys did not return any verified voice recording metadata for this recorded interaction; it will be retried.');
        const namedConversation=await mapParticipantUserNames(client,conversation),queueNames=await resolveQueueNames(client,namedConversation),displayConversation=withParticipantLines(namedConversation),summary={...summarizeConversation(namedConversation),queues:conversationQueueNames(namedConversation,queueNames)},destination=db.prepare('SELECT * FROM library_destinations WHERE id=?').get(schedule.destination_id) as DestinationRow|undefined;if(!destination)throw new Error('The archive destination was deleted.');const config=decryptDestination(destination);let archived=0,alreadyArchived=0,mediaPending=false;
       for(const recording of valid){const current=db.prepare('SELECT lookback_days FROM library_schedules WHERE id=?').get(schedule.id) as {lookback_days:number}|undefined;if(Date.parse(item.conversation_start)<Date.parse(initialArchiveCursor(this.now(),current?.lookback_days||schedule.lookback_days||550))){db.prepare('DELETE FROM library_archive_queue WHERE id=?').run(item.id);return;}const recordingId=String(recording.id||recording.recordingId);if(db.prepare('SELECT id FROM archived_recordings WHERE connection_id=? AND conversation_id=? AND recording_id=?').get(connection.id,item.conversation_id,recordingId)){alreadyArchived++;continue;}
           const outputFormat=this.outputFormat();let playable;try{playable=await getMediaBytes(client,connection,item.conversation_id,recordingId,this.deps.fetchMedia||fetch,preferredGenesysInputFormat(outputFormat));}catch(error){if(error instanceof GenesysError&&error.status===429)throw error;if(String((recording as any)?.mediaType||'').toLowerCase()==='voice')throw error;continue;}if(!playable){if(String((recording as any)?.mediaType||'').toLowerCase()==='voice')mediaPending=true;continue;}
          const expectedDurationMs=Number(recording?.durationMs||recording?.duration||(summary.durationSeconds??0)*1000||0)||undefined;const source={mimeType:playable.mimeType,extension:playable.extension};const converted=await (this.deps.transcode||transcodeRecordingAudio)(playable.bytes,outputFormat,undefined,expectedDurationMs);const conversion={format:converted.format,sourceMimeType:source.mimeType,sourceExtension:source.extension};playable={...playable,bytes:converted.bytes,mimeType:converted.mimeType,extension:converted.extension};
        const date=summary.conversationStart.slice(0,10),folder=`${date}/${item.conversation_id}`,safeId=recordingId.replace(/[^a-zA-Z0-9_-]/g,'_'),fileName=`${safeId}.${playable.extension}`,relativePath=`${folder}/${fileName}`;
        const tempDir=await fs.mkdtemp(path.join(os.tmpdir(),'mfec-library-'));const audioPath=path.join(tempDir,fileName),metaPath=path.join(tempDir,`${fileName}.json`);
        try{
            await fs.writeFile(audioPath,playable.bytes,{mode:0o600});const metadata={conversationId:item.conversation_id,connectionId:connection.id,recordingId,conversation:{...summary,conversationEnd:conversation.conversationEnd||'',agents:summary.agents,flows:summary.flows,queues:summary.queues,interactionType:summary.interactionType,durationSeconds:summary.durationSeconds,participants:displayConversation.participants},recording:{...jsonSafe(recording),...jsonSafe(playable.metadata)},conversion,archivedAt:now};await fs.writeFile(metaPath,JSON.stringify(metadata,null,2),{mode:0o600});
          await (this.deps.writeFile||writeDestinationFile)(config,relativePath,audioPath);await (this.deps.writeFile||writeDestinationFile)(config,`${relativePath}.json`,metaPath);
            const archiveId=crypto.randomUUID(),sha256=crypto.createHash('sha256').update(playable.bytes).digest('hex'),expiresAt=new Date(Date.parse(now)+config.retentionDays*DAY).toISOString();
            const latestLookback=db.prepare('SELECT lookback_days FROM library_schedules WHERE id=?').get(schedule.id) as {lookback_days:number}|undefined;
            if(Date.parse(item.conversation_start)<Date.parse(initialArchiveCursor(this.now(),latestLookback?.lookback_days||schedule.lookback_days||550))){await deleteDestinationFile(config,relativePath).catch(()=>{});await deleteDestinationFile(config,`${relativePath}.json`).catch(()=>{});db.prepare('DELETE FROM library_archive_queue WHERE id=?').run(item.id);return;}
            db.prepare('INSERT INTO archived_recordings(id,connection_id,conversation_id,recording_id,destination_id,relative_path,file_name,mime_type,size_bytes,sha256,conversation_start,conversation_end,direction,ani,dnis,agent_names,flows,queues,interaction_type,duration_ms,metadata_json,archived_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(archiveId,connection.id,item.conversation_id,recordingId,destination.id,relativePath,fileName,playable.mimeType,playable.bytes.length,sha256,summary.conversationStart,conversation.conversationEnd||null,summary.direction||'',summary.ani||'',summary.dnis||'',JSON.stringify(summary.agents||[]),JSON.stringify(summary.flows||[]),JSON.stringify(summary.queues||[]),summary.interactionType||'Unknown',summary.durationSeconds===null?Number(playable.metadata?.durationMs||recording.durationMs)||null:summary.durationSeconds*1000,JSON.stringify(metadata),now,expiresAt);archived++;
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

export function listLibrary(query:string,limit:number,offset:number,connectionIds:string[]|null){const conditions:string[]=[];const values:unknown[]=[];if(connectionIds){if(!connectionIds.length)return {items:[],total:0};conditions.push(`connection_id IN (${connectionIds.map(()=>'?').join(',')})`);values.push(...connectionIds);}if(query){const like=`%${query.replace(/[\\%_]/g,'\\$&')}%`;conditions.push("(conversation_id LIKE ? ESCAPE '\\' OR recording_id LIKE ? ESCAPE '\\' OR file_name LIKE ? ESCAPE '\\' OR ani LIKE ? ESCAPE '\\' OR dnis LIKE ? ESCAPE '\\' OR agent_names LIKE ? ESCAPE '\\' OR flows LIKE ? ESCAPE '\\' OR queues LIKE ? ESCAPE '\\' OR interaction_type LIKE ? ESCAPE '\\')");values.push(like,like,like,like,like,like,like,like,like);}const where=conditions.length?`WHERE ${conditions.join(' AND ')}`:'';const total=Number((db.prepare(`SELECT COUNT(*) AS n FROM archived_recordings ${where}`).get(...values) as {n:number}).n);const rows=db.prepare(`SELECT a.id,a.connection_id AS connectionId,a.conversation_id AS conversationId,a.recording_id AS recordingId,a.destination_id AS destinationId,d.name AS destinationName,d.type AS destinationType,a.relative_path AS relativePath,a.file_name AS fileName,a.mime_type AS mimeType,a.size_bytes AS sizeBytes,a.conversation_start AS conversationStart,a.conversation_end AS conversationEnd,a.direction,a.ani,a.dnis,a.agent_names AS agentNames,a.flows,a.queues,a.interaction_type AS interactionType,a.duration_ms AS durationMs,a.metadata_json AS metadataJson,a.archived_at AS archivedAt,a.expires_at AS expiresAt FROM archived_recordings a JOIN library_destinations d ON d.id=a.destination_id ${where} ORDER BY a.conversation_start DESC,a.archived_at DESC LIMIT ? OFFSET ?`).all(...values,limit,offset) as Record<string,any>[];const items=rows.map(({metadataJson,...row})=>{let metadata:any={};try{metadata=JSON.parse(String(metadataJson||'{}'));}catch{}const display=archivedConversationDisplay({conversation:{...(metadata?.conversation||{}),direction:metadata?.conversation?.direction||row.direction,callbackNumber:metadata?.conversation?.callbackNumber,ani:metadata?.conversation?.ani||row.ani,dnis:metadata?.conversation?.dnis||row.dnis,agents:metadata?.conversation?.agents,flows:metadata?.conversation?.flows,queues:metadata?.conversation?.queues,interactionType:metadata?.conversation?.interactionType,durationSeconds:metadata?.conversation?.durationSeconds},participants:metadata?.conversation?.participants},row.durationMs);return {...row,callbackNumber:display.callbackNumber,displayNumber:visibleDirectionNumber({...display,dnis:display.dnis||row.dnis},row),agents:display.agents.length?display.agents:(()=>{try{return JSON.parse(String(row.agentNames||'[]')).filter((name:unknown)=>typeof name==='string'&&!/^[0-9a-f-]{36}$/i.test(name)&&!['agent','user','unknown'].includes(name.toLowerCase()));}catch{return [];}})(),flows:display.flows,queues:display.queues.length?display.queues:(()=>{try{return JSON.parse(String(row.queues||'[]')).filter((name:unknown)=>typeof name==='string'&&!/^[0-9a-f-]{36}$/i.test(name));}catch{return [];}})(),interactionType:display.interactionType==='Unknown'?String(row.interactionType||'Unknown'):display.interactionType,durationSeconds:display.durationSeconds};});return {items,total};}

export function archivedRecordingById(id:string){return db.prepare('SELECT a.*,d.name AS destination_name,d.type,d.config_enc FROM archived_recordings a JOIN library_destinations d ON d.id=a.destination_id WHERE a.id=?').get(id) as (Record<string,any>&DestinationRow)|undefined;}
export async function archivedRecordingStream(row:Record<string,any>,range?:ByteRange){return readDestinationFile(decryptDestination(row as unknown as DestinationRow),String(row.relative_path),range);}
export async function archivedRecordingMetadata(row:Record<string,any>){const config=decryptDestination(row as unknown as DestinationRow);try{const bytes=await readDestinationFileBuffer(config,`${row.relative_path}.json`);return JSON.parse(bytes.toString('utf8'));}catch(error){if(row.metadata_json)return JSON.parse(row.metadata_json);throw error;}}
export function retryFailedArchive(scheduleId:string){return db.prepare("UPDATE library_archive_queue SET status='pending',attempts=0,last_error=NULL WHERE schedule_id=? AND status='failed'").run(scheduleId).changes;}
