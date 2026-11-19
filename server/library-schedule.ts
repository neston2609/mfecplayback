const DAY=86400000;
export const GENESYS_ANALYTICS_LOOKBACK_DAYS=550;
export type ScheduleTiming={cadence:'daily'|'weekly'|'monthly';day_of_week:number|null;day_of_month:number|null;run_time:string;time_zone:string};

export function initialArchiveCursor(now=new Date()){
  const startOfUtcDay=Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate());
  return new Date(startOfUtcDay-GENESYS_ANALYTICS_LOOKBACK_DAYS*DAY).toISOString();
}

export function nextScheduleTime(schedule:ScheduleTiming, after:Date) {
  const [hour,minute]=schedule.run_time.split(':').map(Number);
  const parts=(date:Date)=>Object.fromEntries(new Intl.DateTimeFormat('en-US',{timeZone:schedule.time_zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23',weekday:'short'}).formatToParts(date).map(part=>[part.type,part.value]));
  const localNow=parts(after);let year=Number(localNow.year),month=Number(localNow.month),day=Number(localNow.day);
  const weekdayIndex=(label:string)=>['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].indexOf(label);
  const wallTime=(y:number,m:number,d:number)=>{const target=Date.UTC(y,m-1,d,hour,minute);let candidate=new Date(target);for(let correction=0;correction<4;correction++){const local=parts(candidate);const represented=Date.UTC(Number(local.year),Number(local.month)-1,Number(local.day),Number(local.hour),Number(local.minute));candidate=new Date(candidate.getTime()+target-represented);}return candidate;};
  if(schedule.cadence==='daily'){
    let candidate=wallTime(year,month,day);if(candidate<=after){const next=new Date(Date.UTC(year,month-1,day+1));candidate=wallTime(next.getUTCFullYear(),next.getUTCMonth()+1,next.getUTCDate());}return candidate.toISOString();
  }
  if(schedule.cadence==='weekly'){
    let delta=((schedule.day_of_week??0)-weekdayIndex(localNow.weekday)+7)%7;let candidate=wallTime(year,month,day+delta);if(candidate<=after)candidate=wallTime(year,month,day+delta+7);return candidate.toISOString();
  }
  for(let offset=0;offset<3;offset++){
    const first=new Date(Date.UTC(year,month-1+offset,1)),targetDay=Math.min(schedule.day_of_month??1,new Date(Date.UTC(first.getUTCFullYear(),first.getUTCMonth()+1,0)).getUTCDate());
    const candidate=wallTime(first.getUTCFullYear(),first.getUTCMonth()+1,targetDay);if(candidate>after)return candidate.toISOString();
  }
  return new Date(after.getTime()+DAY).toISOString();
}
