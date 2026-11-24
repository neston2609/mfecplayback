import { GenesysError } from './genesys-client.js';
import { transcriptSearchCommunicationIds, transcriptSearchPath, transcriptSearchRequest } from './conversation-artifacts.js';
import { normalizeTranscriptionError, conversationCommunicationIds, transcriptionRequestPath, validateTranscriptUrl } from './transcription.js';

type TranscriptClient={get<T=unknown>(path:string):Promise<T>;post<T=unknown>(path:string,body:unknown):Promise<T>};

export function redactTranscriptMetadata(value:any):any{if(Array.isArray(value))return value.map(redactTranscriptMetadata);if(value&&typeof value==='object'){const safe:Record<string,unknown>={};for(const [key,item] of Object.entries(value)){if(/token|secret|authorization|mediaUri|signed|url/i.test(key))safe[key]='[REDACTED]';else safe[key]=redactTranscriptMetadata(item);}return safe;}return value;}

async function boundedBody(response:Response,limit:number){
  const declared=Number(response.headers.get('content-length')||0);
  if(declared>limit){await response.body?.cancel().catch(()=>{});throw Object.assign(new Error('Genesys transcription exceeds the safe size limit.'),{status:413});}
  if(!response.body)throw Object.assign(new Error('Genesys returned an empty transcription document.'),{status:502});
  const reader=response.body.getReader(),chunks:Buffer[]=[];let total=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>limit){await reader.cancel();throw Object.assign(new Error('Genesys transcription exceeds the safe size limit.'),{status:413});}chunks.push(Buffer.from(value));}}
  finally{reader.releaseLock();}
  return Buffer.concat(chunks,total);
}

export async function fetchConversationTranscriptions(client:TranscriptClient,connection:{api_base_url:string},conversationId:string,conversation:any,fetcher:typeof fetch=fetch){
  const detailIds=conversationCommunicationIds(conversation);let communicationIds:string[];
  try{
    const matches=await client.post<unknown>(transcriptSearchPath(),transcriptSearchRequest(conversationId));
    const searched=transcriptSearchCommunicationIds(matches,conversationId);communicationIds=searched.length?searched:detailIds;
  }catch(error){if(error instanceof GenesysError&&[400,404,405,501].includes(error.status))communicationIds=detailIds;else if((error as {status?:number})?.status===403)throw Object.assign(new Error('Genesys denied access to transcription search. Check Speech and Text Analytics permissions for this account.'),{status:403});else throw error;}
  if(!communicationIds.length)return [];
  let cursor=0;const output=new Array<{communicationId:string;transcript:unknown}|undefined>(communicationIds.length);
  async function worker(){while(true){const index=cursor++,communicationId=communicationIds[index];if(!communicationId)return;try{
    const value=await client.get<{url?:string}>(transcriptionRequestPath(conversationId,communicationId));if(!value?.url)return;
    const url=validateTranscriptUrl(value.url,connection);let response:Response;
    try{response=await fetcher(url,{signal:AbortSignal.timeout(20000),redirect:'manual'});}catch{throw Object.assign(new Error('Genesys transcription could not be retrieved.'),{status:502});}
    if(response.status>=300&&response.status<400){await response.body?.cancel().catch(()=>{});throw Object.assign(new Error('Genesys transcript storage returned an unexpected redirect.'),{status:502});}
     if(!response.ok){await response.body?.cancel().catch(()=>{});if([404,409,410].includes(response.status))return;throw Object.assign(new Error(`Genesys transcript storage returned HTTP ${response.status}.`),{status:response.status===403?403:502});}
    const body=await boundedBody(response,16*1024*1024),contentType=response.headers.get('content-type')||'';let transcript:unknown;
    try{transcript=JSON.parse(body.toString('utf8'));}catch{if(/^text\/(?:plain|vtt)/i.test(contentType))transcript=body.toString('utf8');else throw Object.assign(new Error('Genesys returned an invalid transcription document.'),{status:502});}
    output[index]={communicationId,transcript:redactTranscriptMetadata(transcript)};
  }catch(error){if(error instanceof GenesysError&&[404,409,410].includes(error.status))return;if((error as {status?:number})?.status===403)throw Object.assign(new Error('Genesys denied access to a conversation transcript. Check Speech and Text Analytics permissions for this account.'),{status:403});throw error;}}}
  try{await Promise.all(Array.from({length:Math.min(4,communicationIds.length)},worker));}catch(error){throw normalizeTranscriptionError(error);}
  return output.filter((item):item is {communicationId:string;transcript:unknown}=>Boolean(item));
}
