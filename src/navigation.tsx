import { useState } from 'react';
import { Activity, ChevronDown, Globe2, History, LayoutDashboard, Search, Settings, Shield, ShieldCheck, Users } from 'lucide-react';
import type { User } from './types';

export const navGroups=[
  {title:'Overview',items:[['Dashboard','/dashboard',LayoutDashboard],['Recording Search','/search',Search]]},
  {title:'Workspace',items:[['Playback History','/history',History],['Audit Logs','/audit',ShieldCheck]]},
  {title:'Administration',items:[['Genesys Configuration','/connections',Activity],['Genesys Regions','/regions',Globe2],['Users & Access','/access',Users],['Settings','/settings',Settings]]},
] as const;

export function NavigationSidebar({mobile,path,user,onNavigate}:{mobile:boolean;path:string;user:User;onNavigate:(to:string)=>void}){
  const [openGroup,setOpenGroup]=useState('');
  return <aside className={`sidebar ${mobile?'sidebar-open':''}`}>
    {navGroups.map(group=>{
      const visibleItems=group.items.filter(([label])=>label!=='Genesys Regions'||user.role==='administrator');
      return <div className="nav-group" key={group.title}>
        <button className="nav-group-toggle" aria-expanded={openGroup===group.title} onClick={()=>setOpenGroup(openGroup===group.title?'':group.title)}>
          <span>{group.title}</span><ChevronDown size={14} className={openGroup===group.title?'nav-chevron-open':''}/>
        </button>
        {openGroup===group.title&&<div className="nav-group-items">{visibleItems.map(([label,href,Icon])=><button key={href} className={`nav-item ${path===href?'active':''}`} onClick={()=>onNavigate(href)}><Icon size={17}/><span>{label}</span>{label==='Audit Logs'&&<span className="nav-dot"/>}</button>)}</div>}
      </div>;
    })}
    <div className="sidebar-bottom"><div className="secure-note"><Shield size={15}/><span><b>Secure workspace</b><small>Activity is audited</small></span></div><div className="side-version">MFEC Recording Explorer <span>v1.0.0</span></div></div>
  </aside>;
}

export function navTitle(path:string){return navGroups.reduce<string|undefined>((found,group)=>found||group.items.find(([,href])=>href===path)?.[0],undefined)||'Recording Search';}
export function AppFooter(){return <footer className="app-footer"><span>Developed by MFEC Public Company</span><span>Last updated: {__BUILD_DATE__}</span></footer>;}
declare const __BUILD_DATE__:string;
