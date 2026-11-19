import fs from 'node:fs/promises';
import path from 'node:path';
import { createReadStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Client as FtpClient } from 'basic-ftp';
import { Client as SmbClient } from 'smb3-client';
import { Client as SshClient, type SFTPWrapper } from 'ssh2';
import { z } from 'zod';
import { decrypt, encrypt } from './security.js';
import { Readable } from 'node:stream';
import crypto from 'node:crypto';
import type { ByteRange } from './audio-range.js';
import { byteRangeStream } from './audio-range.js';

export const DEFAULT_LIBRARY_PATH = process.env.LIBRARY_STORAGE_ROOT || '/var/lib/mfec-recording-explorer/library';
export function assertLocalDestinationPath(destinationPath:string,rootPath=process.env.LIBRARY_STORAGE_ROOT||'/var/lib/mfec-recording-explorer/library'){const root=path.resolve(rootPath),configured=path.resolve(destinationPath||root);if(configured!==root&&!configured.startsWith(`${root}${path.sep}`))throw new Error(`Local destinations must stay under the configured library root (${root}).`);return configured;}
export async function localFilesystemCapacity(destinationPath:string):Promise<{totalBytes:number;freeBytes:number}|null>{
  try{
    const root=path.resolve(process.env.LIBRARY_STORAGE_ROOT||DEFAULT_LIBRARY_PATH),configured=assertLocalDestinationPath(destinationPath,root),realRoot=await fs.realpath(root),realConfigured=await fs.realpath(configured);
    if(realConfigured!==realRoot&&!realConfigured.startsWith(`${realRoot}${path.sep}`))return null;
    const stats=await fs.statfs(realConfigured),blockSize=Number(stats.bsize);
    if(!Number.isFinite(blockSize)||blockSize<=0)return null;
    return {totalBytes:Number(stats.blocks)*blockSize,freeBytes:Number(stats.bavail)*blockSize};
  }catch{return null;}
}

const hostSchema = z.string().trim().min(1).max(253).refine(value => !/[\s/@?#]/.test(value), 'Enter a host name or IP address, not a URL.');
const remotePathSchema=z.string().trim().max(500).refine(value=>!value.replace(/\\/g,'/').split('/').includes('..'),'Remote path cannot contain parent-directory traversal.');
const fingerprintSchema=z.string().trim().regex(/^SHA256:[A-Za-z0-9+/]{43}=?$/,'Enter the server SHA-256 fingerprint (SHA256:...).').refine(value=>Buffer.from(value.slice(7),'base64').length===32,'SHA-256 fingerprint must be a 32-byte base64 digest.');
const common = { name: z.string().trim().min(1).max(100), retentionDays: z.number().int().min(1).max(3650).default(365) };
export const destinationSchema = z.discriminatedUnion('type', [
  z.object({ ...common, type: z.literal('local'), path: z.string().trim().min(1).max(500).refine(value=>{try{assertLocalDestinationPath(value);return true;}catch{return false;}},'Local destinations must stay under the configured library root.') }),
  z.object({ ...common, type: z.literal('sftp'), host: hostSchema, port: z.number().int().min(1).max(65535).default(22), username: z.string().trim().min(1).max(256), password: z.string().min(1).max(1024), hostFingerprint: fingerprintSchema , path: remotePathSchema.default('') }),
  z.object({ ...common, type: z.literal('ftp'), host: hostSchema, port: z.number().int().min(1).max(65535).default(21), username: z.string().trim().min(1).max(256), password: z.string().min(1).max(1024), path: remotePathSchema.default(''), tls: z.literal(true).default(true) }),
  z.object({ ...common, type: z.literal('smb'), host: hostSchema, port: z.number().int().min(1).max(65535).default(445), share: z.string().trim().min(1).max(80).regex(/^[^\\/:*?"<>|]+$/), domain: z.string().trim().max(128).default(''), username: z.string().trim().min(1).max(256), password: z.string().min(1).max(1024), path: remotePathSchema.default('') }),
]);
export type DestinationConfig = z.infer<typeof destinationSchema>;
export type DestinationRow = { id: string; name: string; type: DestinationConfig['type']; config_enc: string; created_at: string; updated_at: string };

export function decryptDestination(row: DestinationRow): DestinationConfig {
  return destinationSchema.parse({ name: row.name, ...JSON.parse(decrypt(row.config_enc)) });
}

export function publicDestination(row: DestinationRow) {
  const config = decryptDestination(row);
  const { password: _password, ...safe } = config as DestinationConfig & { password?: string }; void _password;
  return { id: row.id, ...safe, passwordConfigured: 'password' in config, createdAt: row.created_at, updatedAt: row.updated_at };
}

function localPath(config: Extract<DestinationConfig, {type:'local'}>, relativePath = '') {
  const root = path.resolve(DEFAULT_LIBRARY_PATH),configured=path.resolve(config.path||root);
  if (configured !== root && !configured.startsWith(`${root}${path.sep}`)) throw new Error(`Local destinations must stay under the configured library root (${root}).`);
  const target=path.resolve(configured,...relativePath.split('/'));
  if (target !== configured && !target.startsWith(`${configured}${path.sep}`)) throw new Error('Library path escaped its destination directory.');
  return { base:configured, target };
}

async function assertLocalFilesystemPath(target:string){const root=path.resolve(DEFAULT_LIBRARY_PATH);await fs.mkdir(root,{recursive:true,mode:0o750});await fs.mkdir(target,{recursive:true,mode:0o750});const realRoot=await fs.realpath(root);const realTarget=await fs.realpath(target);if(realTarget!==realRoot&&!realTarget.startsWith(`${realRoot}${path.sep}`))throw new Error('Local library path resolves outside the configured storage root through a symbolic link.');return realTarget;}
async function assertLocalParentPath(target:string){const root=path.resolve(DEFAULT_LIBRARY_PATH);await fs.mkdir(root,{recursive:true,mode:0o750});const realRoot=await fs.realpath(root);let current=path.resolve(target);while(true){try{const real=await fs.realpath(current);if(real!==realRoot&&!real.startsWith(`${realRoot}${path.sep}`))throw new Error('Local library path resolves outside the configured storage root through a symbolic link.');return;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;const parent=path.dirname(current);if(parent===current)throw error;current=parent;}}}

function safeParts(value:string){const parts=value.replace(/\\/g,'/').split('/').filter(part=>part&&part!=='.');if(parts.some(part=>part==='..'||part.includes('\0')))throw new Error('Remote path cannot contain parent-directory traversal.');return parts;}
function remotePath(config: Exclude<DestinationConfig,{type:'local'}>, name: string) {
  const cleanBase = safeParts(config.path).join('/');
  const cleanName=safeParts(name).join('/');
  return [config.type === 'smb' ? config.share : '', cleanBase, cleanName].filter(Boolean).join('/');
}

function sshConnect(config: Extract<DestinationConfig,{type:'sftp'}>) {
  return new Promise<{ssh:SshClient;sftp:SFTPWrapper}>((resolve,reject)=>{
    const ssh=new SshClient(); let settled=false;
    const fail=(error:Error)=>{if(!settled){settled=true;ssh.end();reject(error.message.includes('host key')?new Error('SFTP host fingerprint did not match the pinned SHA-256 fingerprint.'):new Error('SFTP connection failed. Check the host, credentials, and network.'));}};
    ssh.once('error',fail);
    ssh.once('ready',()=>ssh.sftp((error,sftp)=>{if(error)return fail(error);if(settled)return;settled=true;ssh.removeListener('error',fail);resolve({ssh,sftp});}));
    ssh.connect({host:config.host,port:config.port,username:config.username,password:config.password,readyTimeout:10000,keepaliveInterval:10000,hostHash:'sha256',hostVerifier:(fingerprint:string)=>`SHA256:${Buffer.from(fingerprint,'hex').toString('base64').replace(/=+$/,'')}`===config.hostFingerprint.replace(/=+$/,'')});
  });
}

function sftpCall<T>(sftp:SFTPWrapper, method:'mkdir'|'rename'|'unlink'|'stat', ...args:any[]):Promise<T> {
  return new Promise((resolve,reject)=>(sftp[method] as any)(...args,(error:Error|null,value:T)=>error?reject(error):resolve(value)));
}

async function sftpEnsureDir(sftp:SFTPWrapper, directory:string) {
  const parts=directory.split('/').filter(Boolean); let current='';
  for(const part of parts){current+=`/${part}`;try{await sftpCall(sftp,'mkdir',current);}catch(error){const exists=await sftpCall(sftp,'stat',current).then(()=>true,()=>false);if(!exists)throw error;}}
}

function smbClient(config:Extract<DestinationConfig,{type:'smb'}>) {
  return new SmbClient({host:config.host,port:config.port,domain:config.domain,username:config.username,password:config.password,connectTimeout:10000,requestTimeout:30000,signing:'required',encryption:'required'});
}

function smbRelative(config:Extract<DestinationConfig,{type:'smb'}>, relativeName=''){const parts=[...safeParts(config.path),...safeParts(relativeName)];return parts.join('/');}

async function smbEnsureDir(client:SmbClient, config:Extract<DestinationConfig,{type:'smb'}>) {
  const parts=safeParts(config.path);let current='';
  for(const part of parts){current=current?`${current}/${part}`:part;try{await client.mkdir(`${config.share}/${current}`);}catch{const exists=await client.stat(`${config.share}/${current}`).then(stat=>stat.isDirectory,()=>false);if(!exists)throw new Error('SMB destination folder could not be created.');}}
}

export async function testDestination(config:DestinationConfig) {
  const token=`.mfec-library-check-${crypto.randomUUID()}.tmp`;
  if(config.type==='local'){
    const base=assertLocalDestinationPath(config.path,DEFAULT_LIBRARY_PATH);const target=path.resolve(base,token);await assertLocalParentPath(base);await fs.mkdir(base,{recursive:true,mode:0o750});await assertLocalFilesystemPath(base);await fs.writeFile(target,'MFEC library destination check',{flag:'wx',mode:0o600});await fs.unlink(target);return;
  }
  if(config.type==='sftp'){
    const {ssh,sftp}=await sshConnect(config);try{const directory=path.posix.join('/',...safeParts(config.path));await sftpEnsureDir(sftp,directory);const target=path.posix.join(directory,token);const stream=sftp.createWriteStream(target,{flags:'wx',mode:0o600});await pipeline(BufferReadable('MFEC library destination check'),stream);await sftpCall(sftp,'unlink',target);}finally{ssh.end();}return;
  }
  if(config.type==='ftp'){
    const ftp=new FtpClient(10000,{allowSeparateTransferHost:false});try{await ftp.access({host:config.host,port:config.port,user:config.username,password:config.password,secure:true});const directory=path.posix.join('/',...safeParts(config.path));await ftp.ensureDir(directory);const target=path.posix.join(directory,token);await ftp.uploadFrom(BufferReadable('MFEC library destination check'),target);await ftp.remove(target);}finally{ftp.close();}return;
  }
  const smb=smbClient(config);try{await smb.connect();await smbEnsureDir(smb,config);const target=`${config.share}/${token}`;await pipeline(BufferReadable('MFEC library destination check'),smb.createWriteStream(target));await smb.rm(target);}finally{await smb.close().catch(()=>{});}
}

function BufferReadable(value:string){return Readable.from([Buffer.from(value)]);}

export async function writeDestinationFile(config:DestinationConfig, relativeName:string, sourcePath:string) {
  const tempName=`${relativeName}.part`;
  if(config.type==='local'){
    const {target}=localPath(config,relativeName);const {target:temp}=localPath(config,tempName);await assertLocalParentPath(path.dirname(target));await fs.mkdir(path.dirname(target),{recursive:true,mode:0o750});await assertLocalFilesystemPath(path.dirname(target));await pipeline(createReadStream(sourcePath),await fs.open(temp,'w',0o600).then(handle=>handle.createWriteStream()));await fs.unlink(target).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;});await fs.rename(temp,target);return;
  }
  if(config.type==='sftp'){
    const {ssh,sftp}=await sshConnect(config);try{const directory=path.posix.join('/',...safeParts(config.path));await sftpEnsureDir(sftp,directory);const target=path.posix.join(directory,...safeParts(relativeName));const temp=path.posix.join(directory,...safeParts(tempName));await pipeline(createReadStream(sourcePath),sftp.createWriteStream(temp,{flags:'w',mode:0o600}));await sftpCall(sftp,'unlink',target).catch(()=>{});await sftpCall(sftp,'rename',temp,target);}finally{ssh.end();}return;
  }
  if(config.type==='ftp'){
    const ftp=new FtpClient(30000,{allowSeparateTransferHost:false});try{await ftp.access({host:config.host,port:config.port,user:config.username,password:config.password,secure:true});const directory=path.posix.join('/',...safeParts(config.path));await ftp.ensureDir(directory);const target=path.posix.join(directory,...safeParts(relativeName)),temp=path.posix.join(directory,...safeParts(tempName));await ftp.uploadFrom(sourcePath,temp);await ftp.remove(target).catch(()=>{});await ftp.rename(temp,target);}finally{ftp.close();}return;
  }
  const smb=smbClient(config);try{await smb.connect();await smbEnsureDir(smb,config);const target=smbRelative(config,relativeName),temp=smbRelative(config,tempName);await pipeline(createReadStream(sourcePath),smb.createWriteStream(temp));await smb.rm(target).catch(()=>{});await smb.rename(temp,target);}finally{await smb.close().catch(()=>{});}
}

export async function readDestinationFileBuffer(config:DestinationConfig, relativeName:string, maxBytes=16*1024*1024){
  const stream=await readDestinationFile(config,relativeName),chunks:Buffer[]=[];let total=0;
  for await(const chunk of stream){const data=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);total+=data.length;if(total>maxBytes){stream.destroy();throw new Error('Archived metadata document exceeds the safe size limit.');}chunks.push(data);}
  return Buffer.concat(chunks,total);
}

export async function readDestinationFile(config:DestinationConfig, relativeName:string, range?:ByteRange) {
  if(config.type==='local'){const target=localPath(config,relativeName).target;await assertLocalFilesystemPath(path.dirname(target));const stream=createReadStream(target,range);stream.once('open',()=>void assertLocalFilesystemPath(path.dirname(target)).catch(error=>stream.destroy(error as Error)));return stream;}
  if(config.type==='sftp'){
    const {ssh,sftp}=await sshConnect(config);const stream=sftp.createReadStream(path.posix.join('/',...safeParts(config.path),...safeParts(relativeName)),range?{start:range.start,end:range.end}:undefined);stream.once('close',()=>ssh.end());stream.once('error',()=>ssh.end());return stream;
  }
  if(config.type==='smb'){
    const smb=smbClient(config);await smb.connect();const stream=smb.createReadStream(smbRelative(config,relativeName));const close=()=>{void smb.close().catch(()=>{});};stream.once('close',close);stream.once('error',close);return range?byteRangeStream(stream,range):stream;
  }
  const temp=path.join(process.env.TMPDIR||process.env.TEMP||'/tmp',`mfec-library-${crypto.randomUUID()}`);const ftp=new FtpClient(30000,{allowSeparateTransferHost:false});try{await ftp.access({host:config.host,port:config.port,user:config.username,password:config.password,secure:true});await ftp.downloadTo(temp,path.posix.join('/',...safeParts(config.path),...safeParts(relativeName)));}finally{ftp.close();}const stream=createReadStream(temp,range);stream.once('close',()=>void fs.unlink(temp).catch(()=>{}));return stream;
}

export async function deleteDestinationFile(config:DestinationConfig, relativeName:string) {
  if(config.type==='local'){const target=localPath(config,relativeName).target;try{await assertLocalParentPath(path.dirname(target));}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}await fs.unlink(target).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;});return;}
  if(config.type==='sftp'){const {ssh,sftp}=await sshConnect(config);try{await sftpCall(sftp,'unlink',path.posix.join('/',...safeParts(config.path),...safeParts(relativeName)));}finally{ssh.end();}return;}
  if(config.type==='ftp'){const ftp=new FtpClient(30000,{allowSeparateTransferHost:false});try{await ftp.access({host:config.host,port:config.port,user:config.username,password:config.password,secure:true});await ftp.remove(path.posix.join('/',...safeParts(config.path),...safeParts(relativeName)));}finally{ftp.close();}return;}
  const smb=smbClient(config);try{await smb.connect();await smb.rm(smbRelative(config,relativeName));}finally{await smb.close().catch(()=>{});}
}

export function destinationConfigJson(config:DestinationConfig) { return encrypt(JSON.stringify(config)); }
