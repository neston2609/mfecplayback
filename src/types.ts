export type RolePermissions={realtimePlayback:boolean;realtimeDownload:boolean;libraryPlayback:boolean;libraryAdmin:boolean};
export type User={id:string;username:string;role:string;roleName?:string;permissions?:RolePermissions;isAdministrator?:boolean};
