import { useState } from 'react';
import { Activity, Archive, ChevronDown, Globe2, History, LayoutDashboard, Search, Settings, Shield, ShieldCheck, Users } from 'lucide-react';
import type { User } from './types';

export const navGroups=[
  {title:'Overview',items:[['Dashboard','/dashboard',LayoutDashboard],['Recording Search','/search',Search]]},
  {title:'Workspace',items:[['Playback History','/history',History],['Audit Logs','/audit',ShieldCheck]]},
  {title:'Sound Library',items:[['Library','/library',Archive],['Schedule Archive','/library/schedules',History],['Worker Status','/library/worker',Activity],['Library Setting','/library/settings',Settings]]},
  {title:'Administration',items:[['Genesys Configuration','/connections',Activity],['Genesys Regions','/regions',Globe2],['Users & Access','/access',Users],['Settings','/settings',Settings]]},
] as const;

export function NavigationSidebar({mobile,path,user,autoCollapseSubmenu,onNavigate}:{mobile:boolean;path:string;user:User;autoCollapseSubmenu:boolean;onNavigate:(to:string)=>void}){
  const [openGroup,setOpenGroup]=useState('');
  const permissions=user.permissions;
  const isAdmin=user.isAdministrator??user.role==='administrator';
  const canRealtime=isAdmin||Boolean(permissions?.realtimePlayback);
  const canLibrary=isAdmin||Boolean(permissions?.libraryPlayback||permissions?.libraryAdmin);
  return <aside className={`sidebar ${mobile?'sidebar-open':''}`}>
    {navGroups.map(group=>{
      const visibleItems=group.items.filter(([label,href])=>{
        if(href==='/dashboard'&&!canRealtime)return false;
        if(href==='/audit'&&!isAdmin)return false;
        if(label==='Genesys Regions'&&!isAdmin)return false;
        if((label==='Users & Access'||label==='Genesys Configuration')&&!isAdmin)return false;
        if((label==='Schedule Archive'||label==='Worker Status'||label==='Library Setting')&&!isAdmin&&!permissions?.libraryAdmin)return false;
        if(href==='/search'&&!canRealtime)return false;
        if(href==='/library'&&!canLibrary)return false;
        return true;
      });
      const expanded=!autoCollapseSubmenu||openGroup===group.title;
      return <div className="nav-group" key={group.title}>
        <button className="nav-group-toggle" aria-expanded={expanded} onClick={()=>autoCollapseSubmenu&&setOpenGroup(openGroup===group.title?'':group.title)}>
          <span>{group.title}</span><ChevronDown size={14} className={expanded?'nav-chevron-open':''}/>
        </button>
         {expanded&&<div className="nav-group-items">{visibleItems.map(([label,href,Icon])=><button key={href} className={`nav-item ${path===href?'active':''}`} onClick={()=>onNavigate(href)}><Icon size={17}/><span>{label}</span>{label==='Audit Logs'&&<span className="nav-dot"/>}</button>)}</div>}
      </div>;
    })}
    <div className="sidebar-bottom"><div className="secure-note"><Shield size={15}/><span><b>Secure workspace</b><small>Activity is audited</small></span></div><div className="side-version">MFEC Recording Explorer <span>v{__APP_VERSION__}</span></div></div>
  </aside>;
}

export function navTitle(path:string){return navGroups.reduce<string|undefined>((found,group)=>found||group.items.find(([,href])=>href===path)?.[0],undefined)||'Recording Search';}
export function AppFooter(){return <footer className="app-footer"><span>Developed by MFEC Public Company</span><span>Last updated: {__BUILD_DATE__}</span></footer>;}
declare const __BUILD_DATE__:string;
declare const __APP_VERSION__:string;
