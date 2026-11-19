export type LibraryTab='library'|'schedules'|'settings';

export function libraryTabFromPath(path:string):LibraryTab{
  if(path==='/library/schedules')return 'schedules';
  if(path==='/library/settings')return 'settings';
  return 'library';
}

export function pathForLibraryTab(tab:LibraryTab){
  return tab==='schedules'?'/library/schedules':tab==='settings'?'/library/settings':'/library';
}
