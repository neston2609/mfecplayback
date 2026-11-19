export type LibraryTab='library'|'schedules'|'worker'|'settings';

export function libraryTabFromPath(path:string):LibraryTab{
  if(path==='/library/schedules')return 'schedules';
  if(path==='/library/worker')return 'worker';
  if(path==='/library/settings')return 'settings';
  return 'library';
}

export function pathForLibraryTab(tab:LibraryTab){
  return tab==='schedules'?'/library/schedules':tab==='worker'?'/library/worker':tab==='settings'?'/library/settings':'/library';
}
