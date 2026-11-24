import crypto from 'node:crypto';
import type { ScreenTrack } from './screen-recording.js';

type CacheEntry={owner:string;tracks:ScreenTrack[];bytes:number;expires:number;created:number};
const cache=new Map<string,CacheEntry>();
const TTL_MS=2*60*1000,MAX_CACHED_BYTES=256*1024*1024,MAX_ENTRIES=4;
let cachedBytes=0;

export function cacheScreenTracks(owner:string,tracks:ScreenTrack[]){
  const now=Date.now();prune(now);const bytes=tracks.reduce((sum,track)=>sum+track.bytes.length,0);
  if(bytes>MAX_CACHED_BYTES)return undefined;
  while(cache.size>=MAX_ENTRIES||cachedBytes+bytes>MAX_CACHED_BYTES){const oldest=[...cache.entries()].sort((a,b)=>a[1].created-b[1].created)[0];if(!oldest)break;cachedBytes-=oldest[1].bytes;cache.delete(oldest[0]);}
  const id=crypto.randomUUID();cache.set(id,{owner,tracks,bytes,expires:now+TTL_MS,created:now});cachedBytes+=bytes;return id;
}

export function getCachedScreenTrack(cacheId:string,owner:string,trackId:string){
  const now=Date.now();prune(now);const entry=cache.get(cacheId);if(!entry||entry.owner!==owner)return undefined;
  const track=entry.tracks.find(value=>value.id===trackId);return track;
}

function prune(now:number){for(const [id,entry] of cache){if(entry.expires<=now){cachedBytes-=entry.bytes;cache.delete(id);}}}
