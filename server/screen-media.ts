import type { Connection } from './genesys.js';
import { GenesysError } from './genesys-client.js';
import { getRecordingMedia, isScreenRecording, validateRecordingMediaUrl } from './recording-media.js';
import { extractScreenTracksFromZip, screenTrackFromWebm, type ScreenTrack } from './screen-recording.js';

const MAX_SCREEN_BYTES=256*1024*1024;
const MAX_SCREEN_ZIP_BYTES=128*1024*1024;

export async function fetchGenesysScreenTracks(client:{get<T>(path:string):Promise<T>},connection:Connection,conversationId:string,recordingId:string,fetchMedia:typeof fetch=fetch):Promise<ScreenTrack[]>{
  const media=await fetchGenesysScreenMedia(client,connection,conversationId,recordingId,fetchMedia);
  return tracksFromBytes(media.bytes,media.fileName);
}

export async function fetchGenesysScreenMedia(client:{get<T>(path:string):Promise<T>},connection:Connection,conversationId:string,recordingId:string,fetchMedia:typeof fetch=fetch){
  let playable;
  try{playable=await getRecordingMedia(client,conversationId,recordingId,undefined,'WEBM',['SCREEN','SCREEN_RECORDING','ZIP'],true);}
  catch(error){if(error instanceof GenesysError&&[400,404].includes(error.status))throw new Error('Genesys screen recording media is not available.');throw error;}
  if(!playable||!isScreenRecording(playable.metadata))throw new Error('Genesys did not identify this recording as screen media.');
  const bytes=await fetchTrustedBytes(playable.mediaUri,connection,fetchMedia),fileName=String(playable.metadata.fileName||playable.metadata.filename||`${recordingId}.webm`);
  const tracks=tracksFromBytes(bytes,fileName);
  return {bytes,fileName,tracks,mimeType:tracks.length>1||bytes[0]===0x50&&bytes[1]===0x4b?'application/zip':'video/webm',extension:tracks.length>1||bytes[0]===0x50&&bytes[1]===0x4b?'zip':'webm',metadata:playable.metadata};
}

export function tracksFromBytes(bytes:Buffer,name='Screen recording.webm'):ScreenTrack[]{
  if(bytes.subarray(0,4).equals(Buffer.from([0x50,0x4b,0x03,0x04]))||bytes.subarray(0,4).equals(Buffer.from([0x50,0x4b,0x05,0x06])))return extractScreenTracksFromZip(bytes);
  return [screenTrackFromWebm(bytes,name)];
}

async function fetchTrustedBytes(value:string,connection:Connection,fetchMedia:typeof fetch){
  let url=validateRecordingMediaUrl(value,connection),response:Response|undefined;
  for(let redirects=0;redirects<=2;redirects++){
    try{response=await fetchMedia(url,{signal:AbortSignal.timeout(30000),redirect:'manual'});}catch{throw new Error('Genesys screen recording media could not be reached.');}
    if(response.status<300||response.status>=400)break;
    const location=response.headers.get('location');if(!location||redirects===2)throw new Error('Genesys screen media returned an invalid redirect.');url=validateRecordingMediaUrl(new URL(location,url).toString(),connection);
  }
  if(!response||!response.ok){await response?.body?.cancel().catch(()=>{});throw new Error(`Genesys screen media request failed (HTTP ${response?.status||0}).`);}
  const contentType=(response.headers.get('content-type')||'').split(';')[0].toLowerCase(),limit=/zip/.test(contentType)?MAX_SCREEN_ZIP_BYTES:MAX_SCREEN_BYTES,declared=Number(response.headers.get('content-length')||0);
  if(declared>limit){await response.body?.cancel().catch(()=>{});throw new Error(`Screen recording exceeds the ${Math.round(limit/1024/1024)} MB playback limit.`);}
  if(!response.body)throw new Error('Genesys returned an empty screen recording response.');
  const reader=response.body.getReader(),chunks:Buffer[]=[];let size=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){await reader.cancel();throw new Error(`Screen recording exceeds the ${Math.round(limit/1024/1024)} MB playback limit.`);}chunks.push(Buffer.from(value));}}finally{reader.releaseLock();}
  return Buffer.concat(chunks,size);
}
