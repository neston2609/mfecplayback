import { useCallback, useEffect, useState } from 'react';
import { AlertCircle, History, RefreshCw } from 'lucide-react';

type Playback={id:number;action:'PLAYBACK'|'SCREEN_PLAYBACK'|'LIBRARY_PLAYBACK';result:string;connectionId:string|null;connectionName:string;playedBy:string;conversationId:string|null;recordingId:string|null;createdAt:string};

async function loadPage(page:number){
  const response=await fetch(`/api/playback-history?page=${page}`,{credentials:'include'});
  const value=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(value.error||`Request failed (${response.status})`);
  return value as {items:Playback[];total:number;page:number;pageSize:number;totalPages:number};
}

function formatDate(value:string){return value?new Intl.DateTimeFormat('en-GB',{dateStyle:'medium',timeStyle:'short',timeZone:'UTC'}).format(new Date(value)):'—';}

export function PlaybackHistoryPage(){
  const [items,setItems]=useState<Playback[]>([]),[page,setPage]=useState(1),[total,setTotal]=useState(0),[totalPages,setTotalPages]=useState(1),[loading,setLoading]=useState(true),[error,setError]=useState('');
  const load=useCallback(async(nextPage=page)=>{setLoading(true);try{const result=await loadPage(nextPage);setItems(result.items);setPage(result.page);setTotal(result.total);setTotalPages(result.totalPages);setError('');}catch(e){setError((e as Error).message);}finally{setLoading(false);}},[page]);
  useEffect(()=>{void load(1);},[]);
   return <div className="page-content"><div className="page-header"><div><div className="eyebrow">WORKSPACE · RECENT</div><h1>Playback History</h1><p>Recent recordings played from Genesys or Sound Library.</p></div><div className="header-actions"><button className="secondary" onClick={()=>void load()} disabled={loading}><RefreshCw size={15}/>Refresh</button></div></div>{error&&<div className="inline-error"><AlertCircle size={15}/>{error}</div>}<section className="panel audit-panel"><div className="list-heading"><div><h2>Recent playback</h2><p>{total.toLocaleString()} playback record{total===1?'':'s'} · 15 records per page</p></div></div><div className="table-wrap"><table><thead><tr><th>Played at (UTC)</th><th>Played by</th><th>Source</th><th>Result</th><th>Genesys Configuration</th><th>Conversation</th><th>Recording</th></tr></thead><tbody>{items.length?items.map(item=><tr key={item.id}><td>{formatDate(item.createdAt)}</td><td>{item.playedBy||'—'}</td><td>{item.action==='LIBRARY_PLAYBACK'?'Sound Library':item.action==='SCREEN_PLAYBACK'?'Screen video':'Genesys'}</td><td><span className={`status-pill ${item.result==='SUCCESS'?'available':'unavailable'}`}>{item.result}</span></td><td>{item.action!=='LIBRARY_PLAYBACK'?(item.connectionName||'—'):'—'}</td><td><small>{item.conversationId||'—'}</small></td><td><small>{item.recordingId||'—'}</small></td></tr>):<tr><td colSpan={7}><div className="empty-state"><div className="empty-icon"><History size={22}/></div><b>{loading?'Loading playback history…':'No playback history yet'}</b><span>{loading?'':'Successfully played or attempted recordings will appear here.'}</span></div></td></tr>}</tbody></table></div><div className="table-footer"><span>Showing {total?((page-1)*15+1):0}–{Math.min(page*15,total)} of {total}</span><div className="pagination"><button className="secondary" disabled={loading||page<=1} onClick={()=>void load(page-1)}>Previous</button><span>Page {page} of {totalPages}</span><button className="secondary" disabled={loading||page>=totalPages} onClick={()=>void load(page+1)}>Next</button></div></div></section></div>;
}
