import { GenesysError } from './genesys-client.js';

type ParticipantUserClient={get<T>(path:string):Promise<T>};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function participantUserLookupId(participant:any):string{
  const purpose=String(participant?.purpose||'').toLowerCase();
  if(purpose==='user')return typeof participant?.participantId==='string'?participant.participantId:'';
  if(purpose!=='agent')return '';
  const userId=typeof participant?.userId==='string'?participant.userId:'';
  if(userId)return userId;
  const participantName=typeof participant?.participantName==='string'?participant.participantName:'';
  return UUID.test(participantName)?participantName:'';
}

export async function mapParticipantUserNames(client:ParticipantUserClient,conversation:any){
  const participants=Array.isArray(conversation?.participants)?conversation.participants:[];
  const ids=[...new Set<string>(participants.map(participantUserLookupId).filter(Boolean))];
  if(!ids.length)return conversation;
  const names:Record<string,string>={};let cursor=0;
  async function worker(){while(true){const index=cursor++;if(index>=ids.length)return;const id=ids[index];try{const user=await client.get<any>(`/api/v2/users/${encodeURIComponent(id)}`);const name=typeof user?.name==='string'&&user.name.trim()?user.name.trim():[user?.firstName,user?.lastName].filter(value=>typeof value==='string'&&value.trim()).join(' ').trim();if(name)names[id]=name;}catch(error){if(!(error instanceof GenesysError&&[403,404].includes(error.status)))throw error;}}}
  await Promise.all(Array.from({length:Math.min(4,ids.length)},worker));
  return {...conversation,participants:participants.map((participant:any)=>{const id=participantUserLookupId(participant);return id&&names[id]?{...participant,participantName:names[id]}:participant;})};
}
