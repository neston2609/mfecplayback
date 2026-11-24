import 'dotenv/config';
import express, { type Request, type Response as ExpressResponse, type NextFunction } from 'express';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { extractSingleAudioFromZip } from './zip-audio.js';
import { parseByteRange } from './audio-range.js';
import { normalizeTranscriptionError } from './transcription.js';
import { fetchConversationTranscriptions } from './conversation-transcription.js';
import { analyticsConversationDetailsPath, fetchConversationSummaryArtifacts } from './conversation-artifacts.js';
import { collectAfterCallNotes, collectWrapUpCodeIds, withWrapUpCodeNames } from './wrapup.js';
import { db, migrate } from './db/index.js';
import { clearUserAppearance, getDefaultAppearance, getUserAppearance, parseAppearance, saveDefaultAppearance, saveUserAppearance } from './appearance.js';
import { conversationHasVoiceSession, getRecordingMedia, isMessageRecording, isScreenRecording, isVoiceRecording, isZipMediaContentType, listConversationRecordings, listPlayableRecordings, listVoiceRecordings, recordingMediaRequestPath, recordingMediaUri, safeRecordingMetadata, validateRecordingMediaUrl } from './recording-media.js';
import { MAX_ANALYTICS_CONVERSATIONS, queryAllConversations, VOICE_RECORDING_FILTERS } from './conversation-query.js';
import { collectQueueIds, conversationQueueNames, conversationWrapUpCodeNames, summarizeConversation, withParticipantLines } from './conversation-summary.js';
import { BetterSqliteSessionStore } from './session-store.js';
import { decrypt, encrypt, safeEqual } from './security.js';
import { isPasswordPolicySatisfied } from './password-policy.js';
import { parseSmtpSettings, publicSmtpSettings, sendConfiguredEmail, type SmtpSettings } from './mailer.js';
import { getRegions, saveRegions, trustedBaseUrl, validateRegionEndpoints, type GenesysRegion } from './regions.js';
import { connectionById, type Connection } from './genesys.js';
import { GenesysClient, GenesysError, verifyGenesysApiAccess } from './genesys-client.js';
import { MOCK_CONVERSATIONS, MOCK_RECORDINGS } from './mock.js';
import { DEFAULT_LIBRARY_PATH, decryptDestination, deleteDestinationFile, destinationConfigJson, destinationSchema, localFilesystemCapacity, publicDestination, readDestinationFileBuffer, testDestination, writeDestinationFile, type DestinationRow } from './library-destinations.js';
import { archivedRecordingById, archivedRecordingMetadata, archivedRecordingStream, LibraryArchiveWorker, listLibrary, retryFailedArchive } from './library-archive.js';
import { initialArchiveCursor, nextScheduleTime } from './library-schedule.js';
import { mapParticipantUserNames, participantUserLookupId } from './participant-users.js';
import { groupMemberUserIds, MOCK_DIRECTORY, MOCK_GROUP_MEMBERS, resolveDirectorySelection, searchDirectory } from './genesys-directory.js';
import { conversationHasPhoneMatch, phoneSearchMatches } from './phone-search.js';
import { getUnplayableRecordingKeys, setRecordingUnplayable } from './recording-playability.js';
import { decryptS3Source, findS3RecordingMetadataKey, getS3RecordingAudio, publicS3Source, resolveS3Recording, s3SourceConfigJson, s3SourceSchema, searchS3Recordings, testS3Source, type S3RecordingSearch, type S3SourceRow } from './s3-source.js';
import { canUseRecordingSearch, ensureDefaultAccessRoles, getRolePermissions, hasAccessPermission, isBuiltInRole, listAccessRoles, normalizeRolePermissions, roleName, validateRoleName } from './access-control.js';
import { DEFAULT_RECORDING_OUTPUT_FORMAT, RECORDING_OUTPUT_FORMATS, checkAudioConverter, genesysMediaFormatKey, parseRecordingOutputFormat, preferredGenesysInputFormat, recordingOutputInfo, transcodeRecordingAudio } from './audio-transcode.js';
import { fetchGenesysScreenTracks, tracksFromBytes } from './screen-media.js';
import { cacheScreenTracks, getCachedScreenTrack } from './screen-cache.js';

declare module 'express-session' { interface SessionData { user?: { id: string; username: string; role: string }; csrf?: string } }
if (process.env.NODE_ENV !== 'production' && !process.env.MOCK_MODE) process.env.MOCK_MODE = 'true';
const app = express();
let shutdownServer: () => void = () => undefined;
const port = Number(process.env.PORT || 4178);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be a valid TCP port.');
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
const host = process.env.HOST || (process.env.NODE_ENV === 'production' ? '127.0.0.1' : '0.0.0.0');
const sessionSecret = process.env.SESSION_SECRET || (process.env.NODE_ENV === 'production' ? '' : crypto.randomBytes(48).toString('base64url'));
if (sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters.');
if (!Number.isFinite(Number(process.env.SESSION_MAX_AGE_HOURS || 8)) || Number(process.env.SESSION_MAX_AGE_HOURS || 8) < 1 || Number(process.env.SESSION_MAX_AGE_HOURS || 8) > 24) throw new Error('SESSION_MAX_AGE_HOURS must be between 1 and 24.');
validateProductionConfig();
migrate();
ensureDefaultAccessRoles();
bootstrapUser();
purgeExpiredAuditLogs();
const auditRetentionTimer=setInterval(purgeExpiredAuditLogs,24*60*60*1000);
auditRetentionTimer.unref();
const libraryArchiveWorker=new LibraryArchiveWorker();
const destinationInputSchema=z.object({name:z.string().trim().min(1).max(100),type:z.enum(['local','sftp','ftp','smb']),path:z.string().trim().max(500).optional(),host:z.string().trim().max(253).optional(),port:z.number().int().min(1).max(65535).optional(),username:z.string().trim().max(256).optional(),password:z.string().max(1024).optional(),share:z.string().trim().max(80).optional(),domain:z.string().trim().max(128).optional(),hostFingerprint:z.string().trim().max(100).optional(),retentionDays:z.number().int().min(1).max(3650).default(365),tls:z.literal(true).optional()});
const scheduleSchema=z.object({name:z.string().trim().min(1).max(100),connectionId:z.string().uuid(),destinationId:z.string().uuid(),cadence:z.enum(['daily','weekly','monthly']),dayOfWeek:z.number().int().min(0).max(6).optional(),dayOfMonth:z.number().int().min(1).max(31).optional(),lookbackDays:z.number().int().min(1).max(550).default(30),runTime:z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/),timeZone:z.string().min(1).max(100).refine(value=>{try{new Intl.DateTimeFormat('en-US',{timeZone:value});return true;}catch{return false;}},'Choose a supported time zone.'),enabled:z.boolean().default(true)}).superRefine((value,context)=>{if(value.cadence==='weekly'&&value.dayOfWeek===undefined)context.addIssue({code:'custom',path:['dayOfWeek'],message:'Choose a weekday.'});if(value.cadence==='monthly'&&value.dayOfMonth===undefined)context.addIssue({code:'custom',path:['dayOfMonth'],message:'Choose a day of the month.'});});

app.disable('x-powered-by');
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'same-site' },
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
    fontSrc: ["'self'", 'data:'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
    mediaSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"],
  } },
}));
app.use(express.json({ limit: '256kb' }));
app.use('/api', rejectCrossOrigin);
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false }));
const sessionStore = new BetterSqliteSessionStore();
app.use(session({
  store: sessionStore,
  secret: sessionSecret, resave: false, saveUninitialized: false,
  name:'mfec.recording.sid',
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: Number(process.env.SESSION_MAX_AGE_HOURS || 8) * 60 * 60 * 1000 },
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many login attempts. Try again later.' } });
app.get('/api/health', (_req, res) => res.json({ ok: true, mode: process.env.MOCK_MODE === 'true' ? 'mock' : 'genesys', timestamp: new Date().toISOString() }));
if (process.env.NODE_ENV === 'test') app.post('/__test/shutdown', (_req,res) => { res.status(204).end(); shutdownServer(); });
app.get('/api/auth/me', requireAuth, (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not signed in.' });
  req.session.csrf ??= crypto.randomBytes(24).toString('hex');
  res.json({ user: publicUser(req.session.user!), csrfToken: req.session.csrf });
});
app.get('/api/user/appearance', requireAuth, (req, res) => {
  const userAppearance = getUserAppearance(req.session.user!.id);
  const defaultAppearance = getDefaultAppearance();
  const canSetDefault = req.session.user!.role === 'administrator';
  res.json({
    appearance: userAppearance ?? defaultAppearance,
    userOverride: userAppearance !== null,
    defaultAppearance,
    canSetDefault,
  });
});
app.put('/api/user/appearance', requireAuth, requireCsrf, (req, res, next) => {
  try {
    const appearanceSchema = z.object({
      theme: z.enum(['light', 'dark']),
      fontFamily: z.enum(['Prompt', 'Century Gothic']),
      fontSize: z.number().int().min(12).max(24),
    });
    const input = z.object({ scope: z.enum(['user', 'default']), appearance: appearanceSchema }).parse(req.body);
    const appearance = parseAppearance(input.appearance);
    if (input.scope === 'default') {
      if (req.session.user!.role !== 'administrator') throw httpError(403, 'Administrator role required to change the default appearance.');
      saveDefaultAppearance(appearance);
      audit(req, 'APPEARANCE_DEFAULT_UPDATE', 'SUCCESS');
    } else {
      saveUserAppearance(req.session.user!.id, appearance);
      audit(req, 'APPEARANCE_USER_UPDATE', 'SUCCESS');
    }
    const userAppearance = getUserAppearance(req.session.user!.id);
    const defaultAppearance = getDefaultAppearance();
    res.json({ appearance: userAppearance ?? defaultAppearance, userOverride: userAppearance !== null, defaultAppearance, canSetDefault: req.session.user!.role === 'administrator' });
  } catch (error) { next(error); }
});
app.delete('/api/user/appearance', requireAuth, requireCsrf, (req, res, next) => {
  try {
    clearUserAppearance(req.session.user!.id);
    audit(req, 'APPEARANCE_USER_RESET', 'SUCCESS');
    res.json({ appearance: getDefaultAppearance(), userOverride: false, defaultAppearance: getDefaultAppearance(), canSetDefault: req.session.user!.role === 'administrator' });
  } catch (error) { next(error); }
});
app.get('/api/user/profile', requireAuth, (req, res) => {
  const profile = db.prepare('SELECT email,phone,first_name AS firstName,last_name AS lastName,nickname,job_title AS jobTitle,division,department FROM users WHERE id=?').get(req.session.user!.id);
  res.json({ profile });
});
app.put('/api/user/profile', requireAuth, requireCsrf, (req, res, next) => {
  try {
    const profile = profileSchema.parse(req.body);
    db.prepare('UPDATE users SET email=?,phone=?,first_name=?,last_name=?,nickname=?,job_title=?,division=?,department=? WHERE id=?')
      .run(profile.email,profile.phone,profile.firstName,profile.lastName,profile.nickname,profile.jobTitle,profile.division,profile.department,req.session.user!.id);
    audit(req,'USER_PROFILE_UPDATE','SUCCESS');
    res.json({ profile });
  } catch (error) { next(error); }
});
app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const input = z.object({ username: z.string().min(1).max(128), password: z.string().min(1).max(1024) }).parse(req.body);
    const user = db.prepare('SELECT id,username,password_hash,role,enabled FROM users WHERE username=?').get(input.username.trim()) as { id: string; username: string; password_hash: string; role: string; enabled: number } | undefined;
    if (!user || !user.enabled || !(await bcrypt.compare(input.password, user.password_hash))) {
      audit(req, 'LOGIN', 'DENIED'); return res.status(401).json({ error: 'Invalid username or password.' });
    }
    await regenerate(req);
     const selectedRole=(db.prepare('SELECT access_role_id FROM users WHERE id=?').get(user.id) as {access_role_id:string|null}|undefined)?.access_role_id||user.role;
    req.session.user = { id: user.id, username: user.username, role: selectedRole };
    req.session.csrf = crypto.randomBytes(24).toString('hex');
    audit(req, 'LOGIN', 'SUCCESS');
    res.json({ user: publicUser(req.session.user!), csrfToken: req.session.csrf });
  } catch (error) { next(error); }
});
app.post('/api/auth/logout', requireAuth, requireCsrf, (req, res) => {
  audit(req, 'LOGOUT', 'SUCCESS'); req.session.destroy(() => { res.clearCookie('mfec.recording.sid'); res.status(204).end(); });
});
app.post('/api/auth/password', requireAuth, requireCsrf, async (req, res, next) => {
  try {
    const input = z.object({ currentPassword: z.string().min(1).max(1024), newPassword: z.string().min(8).max(256) }).parse(req.body);
    if (!isPasswordPolicySatisfied(input.newPassword)) throw httpError(400, 'Password must be at least 8 characters and include a letter plus a number or special character.');
    const user = db.prepare('SELECT password_hash FROM users WHERE id=? AND enabled=1').get(req.session.user!.id) as { password_hash: string } | undefined;
    if (!user || !(await bcrypt.compare(input.currentPassword, user.password_hash))) throw httpError(401, 'Current password is incorrect.');
    const newHash = await bcrypt.hash(input.newPassword, 12);
    const currentSessionId=req.sessionID;
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(newHash, req.session.user!.id);
    const currentUser = req.session.user!;
    const revoke=db.prepare('DELETE FROM sessions WHERE sid=?');
    for(const row of db.prepare('SELECT sid,sess FROM sessions').all() as {sid:string;sess:string}[]){try{if(JSON.parse(row.sess)?.user?.id===currentUser.id&&row.sid!==currentSessionId)revoke.run(row.sid);}catch{revoke.run(row.sid);}}
    await regenerate(req);
    req.session.user = currentUser;
    req.session.csrf = crypto.randomBytes(24).toString('hex');
    audit(req, 'PASSWORD_CHANGE', 'SUCCESS');
    res.json({ ok: true, csrfToken: req.session.csrf });
  } catch (error) { next(error); }
});

app.get('/api/genesys/regions', requireAuth, requireAdmin, (_req, res) => res.json({ regions: getRegions() }));
app.put('/api/genesys/regions', requireAuth, requireAdmin, requireCsrf, (req, res, next) => {
  try {
    const regions = z.array(z.object({
      id: z.string().trim().min(2).max(64).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
      name: z.string().trim().min(2).max(120),
      api: z.string().url().max(256),
      oauth: z.string().url().max(256),
    })).max(100).parse(req.body.regions) as GenesysRegion[];
    const ids = new Set<string>();
    const endpoints = new Set<string>();
    const oldRegions = getRegions();
    for (const region of regions) {
      if (ids.has(region.id)) throw httpError(400, `Duplicate region ID: ${region.id}.`);
      ids.add(region.id);
      let validated: { api: string; oauth: string };
      try { validated = validateRegionEndpoints(region.api, region.oauth); }
      catch { throw httpError(400, `Region "${region.name}" must use matching trusted Genesys Cloud API and OAuth URLs.`); }
      if (endpoints.has(validated.api) || endpoints.has(validated.oauth)) throw httpError(400, 'Each region must use unique API and OAuth URLs.');
      endpoints.add(validated.api);
      endpoints.add(validated.oauth);
      region.api = validated.api;
      region.oauth = validated.oauth;
    }
    const transaction = db.transaction(() => {
      const nextRegions = new Map(regions.map(region => [region.id, region]));
      const updateConnection = db.prepare('UPDATE connections SET api_base_url=?,oauth_base_url=?,last_success_at=NULL,last_error=NULL,updated_at=? WHERE id=?');
      for (const connection of db.prepare('SELECT id,region_id,api_base_url,oauth_base_url FROM connections').all() as { id: string; region_id: string; api_base_url: string; oauth_base_url: string }[]) {
        const previous = oldRegions.find(region => region.id === connection.region_id);
        const replacement = nextRegions.get(connection.region_id);
        if (!replacement) {
          throw httpError(409, `Region ${connection.region_id} is still used by a saved connection. Update its endpoints or remove that connection before deleting the region.`);
        }
        if(!previous)throw httpError(409, `Saved connection ${connection.id} references an unknown region. Reassign it before updating region configuration.`);
        const endpointsChanged=connection.api_base_url!==replacement.api||connection.oauth_base_url!==replacement.oauth;
        if(endpointsChanged)updateConnection.run(replacement.api, replacement.oauth, new Date().toISOString(), connection.id);
      }
      saveRegions(regions);
    });
    transaction();
    audit(req, 'GENESYS_REGIONS_UPDATE', 'SUCCESS', undefined, undefined, undefined, { regionCount: regions.length });
    res.json({ regions: getRegions() });
  } catch (error) { next(error); }
});
app.get('/api/genesys/connections', requireAuth, (req, res) => {
  const isAdministrator=req.session.user!.role==='administrator',canManageLibrary=hasAccessPermission(req.session.user!.role,'libraryAdmin');
  const rows = isAdministrator
    ? (process.env.MOCK_MODE === 'true' ? [] : db.prepare("SELECT id,name,organization_label,region_id,api_base_url,oauth_base_url,enabled,is_default,last_success_at,CASE WHEN last_error IS NULL THEN NULL ELSE 'Connection check failed. Review administrator logs.' END AS last_error,client_id,CASE WHEN client_secret_enc='' THEN 0 ELSE 1 END AS secret_configured FROM connections ORDER BY name").all())
    : (process.env.MOCK_MODE === 'true' ? [] : canManageLibrary?db.prepare("SELECT c.id,c.name,c.organization_label,c.region_id,c.api_base_url,c.oauth_base_url,c.enabled,c.is_default,NULL AS last_success_at,NULL AS last_error,'' AS client_id,0 AS secret_configured FROM connections c WHERE c.enabled=1 ORDER BY c.name").all():db.prepare('SELECT c.id,c.name,c.organization_label,c.region_id,c.api_base_url,c.oauth_base_url,c.enabled,c.is_default,c.last_success_at,c.last_error,c.client_id,1 AS secret_configured FROM connections c JOIN user_connection_access a ON a.connection_id=c.id WHERE a.user_id=? AND c.enabled=1 ORDER BY c.name').all(req.session.user!.id));
  const values = process.env.MOCK_MODE === 'true' ? [{ id: 'mock', name: 'Synthetic Demo Organization', organization_label: 'Mock Mode · Synthetic data', region_id: 'ap-southeast-1', enabled: 1, is_default: 1, last_success_at: null, last_error: null, client_id: '', secret_configured: 0, mock: true }] : [];
  const validRows=(rows as any[])
    .filter(connection=>getRegions().some(region=>region.id===connection.region_id&&region.api===connection.api_base_url&&region.oauth===connection.oauth_base_url))
    .map(({api_base_url,oauth_base_url,...connection})=>connection);
  res.json({ connections: [...values, ...validRows] });
});
app.get('/api/s3/sources',requireAuth,(req,res)=>{const admin=req.session.user!.role==='administrator';if(!admin&&!hasAccessPermission(req.session.user!.role,'realtimePlayback'))throw httpError(403,'Realtime Playback permission is required to use AWS S3 recording sources.');const rows=db.prepare(`SELECT * FROM s3_sources ${admin?'':'WHERE enabled=1 AND genesys_connection_id IS NOT NULL'} ORDER BY name COLLATE NOCASE`).all() as S3SourceRow[],sources=rows.filter(row=>admin||canUseS3Source(row,req.session.user!.id,req.session.user!.role)).map(publicS3Source);res.json({sources});});
app.post('/api/s3/sources/test',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{try{const input=s3SourceSchema.parse(req.body);if(!input.accessKeyId||!input.secretAccessKey)throw httpError(400,'Enter both AWS Access Key ID and Secret Access Key.');const connection=await verifyS3GenesysConnection(input.genesysConnectionId,input.organizationId,req.session.user!.id,req.session.user!.role);const result=await testS3Source({...input,accessKeyId:input.accessKeyId,secretAccessKey:input.secretAccessKey});audit(req,'S3_SOURCE_TEST','SUCCESS',undefined,undefined,undefined,{bucket:input.bucket,region:input.region,genesysConnectionId:connection.id});res.json(result);}catch(error){audit(req,'S3_SOURCE_TEST','FAILED');next(error instanceof GenesysError||Number((error as {status?:number})?.status)>0?error:httpError(502,'AWS S3 source test failed. Check the source configuration, Genesys organization link, and IAM access.'));}});
app.post('/api/s3/sources/:id/test',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{try{const id=String(req.params.id),row=db.prepare('SELECT * FROM s3_sources WHERE id=?').get(id) as S3SourceRow|undefined;if(!row)throw httpError(404,'AWS S3 source not found.');const input=s3SourceSchema.partial().parse(req.body);if(Boolean(input.accessKeyId)!==Boolean(input.secretAccessKey))throw httpError(400,'Enter both AWS Access Key ID and Secret Access Key when testing rotated credentials.');const previous=decryptS3Source(row),config={name:input.name??previous.name,bucket:input.bucket??previous.bucket,region:input.region??previous.region,prefix:input.prefix??previous.prefix,organizationId:input.organizationId??previous.organizationId,enabled:input.enabled??previous.enabled,accessKeyId:input.accessKeyId??previous.accessKeyId,secretAccessKey:input.secretAccessKey??previous.secretAccessKey,sessionToken:input.sessionToken??(input.accessKeyId?undefined:previous.sessionToken)},connection=await verifyS3GenesysConnection(input.genesysConnectionId??(row.genesys_connection_id||undefined),config.organizationId,req.session.user!.id,req.session.user!.role);const result=await testS3Source(config);audit(req,'S3_SOURCE_TEST','SUCCESS',id,undefined,undefined,{bucket:config.bucket,region:config.region,genesysConnectionId:connection.id});res.json(result);}catch(error){audit(req,'S3_SOURCE_TEST','FAILED',String(req.params.id));next(error instanceof GenesysError||Number((error as {status?:number})?.status)>0?error:httpError(502,'AWS S3 source test failed. Check the source IAM permissions, Genesys organization link, and bucket configuration.'));}});
app.post('/api/s3/sources',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{try{const input=s3SourceSchema.parse(req.body);if(!input.accessKeyId||!input.secretAccessKey)throw httpError(400,'Enter both AWS Access Key ID and Secret Access Key.');const genesysConnection=await verifyS3GenesysConnection(input.genesysConnectionId,input.organizationId,req.session.user!.id,req.session.user!.role);await testS3Source({...input,accessKeyId:input.accessKeyId,secretAccessKey:input.secretAccessKey});const id=crypto.randomUUID(),now=new Date().toISOString(),encrypted=s3SourceConfigJson({...input,accessKeyId:input.accessKeyId,secretAccessKey:input.secretAccessKey}),row={id,name:input.name,bucket:input.bucket,region:input.region,prefix:input.prefix,organization_id:input.organizationId,genesys_connection_id:genesysConnection.id,access_key_id_enc:encrypted.accessKeyId,secret_access_key_enc:encrypted.secretAccessKey,session_token_enc:encrypted.sessionToken,enabled:Number(input.enabled),created_at:now,updated_at:now};db.prepare('INSERT INTO s3_sources(id,name,bucket,region,prefix,organization_id,genesys_connection_id,access_key_id_enc,secret_access_key_enc,session_token_enc,enabled,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,row.name,row.bucket,row.region,row.prefix,row.organization_id,row.genesys_connection_id,row.access_key_id_enc,row.secret_access_key_enc,row.session_token_enc,row.enabled,req.session.user!.id,now,now);audit(req,'S3_SOURCE_CREATE','SUCCESS',id,undefined,undefined,{bucket:input.bucket,region:input.region,genesysConnectionId:genesysConnection.id});res.status(201).json({source:publicS3Source(row)});}catch(error){next(error);}});
app.put('/api/s3/sources/:id',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{try{const id=String(req.params.id),existing=db.prepare('SELECT * FROM s3_sources WHERE id=?').get(id) as S3SourceRow|undefined;if(!existing)throw httpError(404,'AWS S3 source not found.');const input=s3SourceSchema.partial().parse(req.body);if(Boolean(input.accessKeyId)!==Boolean(input.secretAccessKey))throw httpError(400,'Enter both AWS Access Key ID and Secret Access Key when rotating credentials.');const previous=decryptS3Source(existing),config={name:input.name??previous.name,bucket:input.bucket??previous.bucket,region:input.region??previous.region,prefix:input.prefix??previous.prefix,organizationId:input.organizationId??previous.organizationId,enabled:input.enabled??previous.enabled,accessKeyId:input.accessKeyId??previous.accessKeyId,secretAccessKey:input.secretAccessKey??previous.secretAccessKey,sessionToken:input.sessionToken??(input.accessKeyId?undefined:previous.sessionToken)},connection=await verifyS3GenesysConnection(input.genesysConnectionId??(existing.genesys_connection_id||undefined),config.organizationId,req.session.user!.id,req.session.user!.role);const changedConnectionConfig=input.accessKeyId!==undefined||input.secretAccessKey!==undefined||input.sessionToken!==undefined||input.bucket!==undefined||input.region!==undefined||input.prefix!==undefined||input.organizationId!==undefined||input.genesysConnectionId!==undefined;if(config.enabled&&changedConnectionConfig)await testS3Source(config);const encrypted=s3SourceConfigJson(config),now=new Date().toISOString();db.prepare('UPDATE s3_sources SET name=?,bucket=?,region=?,prefix=?,organization_id=?,genesys_connection_id=?,access_key_id_enc=?,secret_access_key_enc=?,session_token_enc=?,enabled=?,updated_at=? WHERE id=?').run(config.name,config.bucket,config.region,config.prefix,config.organizationId,connection.id,encrypted.accessKeyId,encrypted.secretAccessKey,encrypted.sessionToken,Number(config.enabled),now,id);const saved=db.prepare('SELECT * FROM s3_sources WHERE id=?').get(id) as S3SourceRow;audit(req,'S3_SOURCE_UPDATE','SUCCESS',id,undefined,undefined,{bucket:config.bucket,region:config.region,enabled:config.enabled,genesysConnectionId:connection.id});res.json({source:publicS3Source(saved)});}catch(error){next(error);}});
app.delete('/api/s3/sources/:id',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{try{const id=String(req.params.id),result=db.prepare('DELETE FROM s3_sources WHERE id=?').run(id);if(!result.changes)throw httpError(404,'AWS S3 source not found.');audit(req,'S3_SOURCE_DELETE','SUCCESS',id);res.status(204).end();}catch(error){next(error);}});
app.post('/api/s3/sources/:id/export',requireAuth,requireRealtimeDownload,requireLibraryAdmin,requireCsrf,async(req,res,next)=>{
  let tempDir='';let written:string[]=[];let persisted=false;let exportDestination:DestinationRow|undefined;let sourceId=String(req.params.id),conversationId='',recordingId='';
  try{
    const source=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(sourceId) as S3SourceRow|undefined;
    if(!source||!hasS3SourceGrant(source,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');
    const input=z.object({conversationId:z.string().min(1).max(128),recordingId:z.string().min(1).max(128),metadataKey:z.string().min(1).max(2048),destinationId:z.string().uuid().optional()}).parse(req.body);
    conversationId=input.conversationId;recordingId=input.recordingId;
    const destinationId=input.destinationId||((db.prepare("SELECT value_json FROM application_settings WHERE key='library_default_destination_id'").get() as {value_json:string}|undefined)?.value_json||'');
    if(!destinationId)throw httpError(400,'Choose a default Library Destination or select one for this export.');
    const destination=db.prepare('SELECT * FROM library_destinations WHERE id=?').get(destinationId) as DestinationRow|undefined;
    if(!destination)throw httpError(400,'Choose an existing Library Destination.');
    exportDestination=destination;
    if(!source.genesys_connection_id)throw httpError(409,'AWS S3 source is not linked to a Genesys Connection.');
    const genesys=connectionById(source.genesys_connection_id,req.session.user!.id,req.session.user!.role),config=decryptS3Source(source);
    const already=db.prepare('SELECT id,file_name AS fileName,destination_id AS destinationId FROM archived_recordings WHERE connection_id=? AND conversation_id=? AND recording_id=?').get(genesys.id,conversationId,recordingId) as {id:string;fileName:string;destinationId:string}|undefined;
    if(already){audit(req,'S3_LIBRARY_EXPORT','SUCCESS',`s3:${sourceId}`,conversationId,recordingId,{destinationId:already.destinationId,alreadyArchived:true});return res.json({ok:true,alreadyArchived:true,...already});}
     let metadataKey=input.metadataKey;
     try{await resolveS3Recording(config,metadataKey,conversationId,recordingId);}catch{metadataKey=await findS3RecordingMetadataKey(config,conversationId,recordingId,metadataKey)||'';}
     if(!metadataKey)throw httpError(404,'Recording metadata was not found in the configured Genesys S3 layout.');
    const associated=await resolveAuthorizedS3Recording(source,config,metadataKey,conversationId,recordingId,req.session.user!.id,req.session.user!.role,'library-export'),resolved=associated,client=new GenesysClient(genesys),conversation=associated.conversation,recordings=associated.genesysRecordings,recording=associated.recording;
    if(!recording)throw httpError(404,'Genesys does not associate this S3 recording ID with the linked conversation.');
    const named=await mapParticipantUserNames(client,conversation),queueNames=await mapConversationQueueNames(client,named),summary={...summarizeConversation(named),queues:conversationQueueNames(named,queueNames)},screen=resolved.mediaType==='screen';
    if(screen!==isScreenRecording(recording))throw httpError(409,'S3 media type does not match the linked Genesys recording metadata.');
    const media=await getS3RecordingAudio(config,resolved.audioKey);if('invalidRange'in media)throw httpError(416,'Recording media range is invalid.');
    let bytes:Buffer,mimeType=media.contentType,extension=path.extname(resolved.audioKey).slice(1).toLowerCase()||'opus';
    try{bytes=await readAwsS3Body(media.body as AsyncIterable<Uint8Array>,screen?128*1024*1024:256*1024*1024);}finally{media.close();}
    if(mimeType==='application/octet-stream')mimeType=extension==='opus'||extension==='ogg'?'audio/ogg':extension==='wav'?'audio/wav':extension==='mp3'?'audio/mpeg':extension==='zip'?'application/zip':extension==='webm'?'video/webm':mimeType;
    let converted:{bytes:Buffer;mimeType:string;extension:string;format:string};
    if(screen){const tracks=tracksFromBytes(bytes,path.basename(resolved.audioKey));if(!tracks.length)throw httpError(409,'Screen recording archive contains no validated WebM monitor tracks.');converted={bytes,mimeType:extension==='zip'?'application/zip':'video/webm',extension,format:'original'};}
    else{if(!mimeType.startsWith('audio/')&&!isZipMediaContentType(mimeType))throw httpError(409,'The selected S3 object is not voice audio.');if(isZipMediaContentType(mimeType))bytes=extractSingleAudioFromZip(bytes).audio;converted=await convertAudio(bytes,getRecordingOutputFormat(),Number(resolved.durationMs)||undefined);}
    const now=new Date().toISOString(),formatDate=String(summary.conversationStart||conversation.conversationStart||now).slice(0,10),safeId=recordingId.replace(/[^a-zA-Z0-9_-]/g,'_'),fileName=`${safeId}.${converted.extension}`,relativePath=`${formatDate}/${conversationId}/${fileName}`,archiveId=crypto.randomUUID(),destinationConfig=decryptDestination(destination),expiresAt=new Date(Date.parse(now)+destinationConfig.retentionDays*86400000).toISOString();
    const metadata={conversationId,connectionId:genesys.id,sourceType:'aws-s3',sourceId,recordingId,conversation:{...summary,conversationEnd:conversation.conversationEnd||'',participants:withParticipantLines(named).participants},genesysConversation:redactSensitiveMetadata(conversation),recording:redactSensitiveMetadata(recording),s3Recording:redactSensitiveMetadata(resolved.metadata),conversion:{format:converted.format,sourceMimeType:mimeType,sourceExtension:extension},archivedAt:now};
    tempDir=await fs.mkdtemp(path.join(os.tmpdir(),'mfec-s3-export-'));const mediaPath=path.join(tempDir,fileName),metadataPath=path.join(tempDir,`${fileName}.json`);await fs.writeFile(mediaPath,converted.bytes,{mode:0o600});await fs.writeFile(metadataPath,JSON.stringify(metadata,null,2),{mode:0o600});
    await writeDestinationFile(destinationConfig,relativePath,mediaPath);written.push(relativePath);await writeDestinationFile(destinationConfig,`${relativePath}.json`,metadataPath);written.push(`${relativePath}.json`);
    const [storedMedia,storedMetadata]=await Promise.all([readDestinationFileBuffer(destinationConfig,relativePath,screen?128*1024*1024:256*1024*1024),readDestinationFileBuffer(destinationConfig,`${relativePath}.json`)]);
    if(!crypto.timingSafeEqual(crypto.createHash('sha256').update(storedMedia).digest(),crypto.createHash('sha256').update(converted.bytes).digest())||!storedMetadata.equals(Buffer.from(JSON.stringify(metadata,null,2))))throw httpError(502,'Library destination failed export integrity verification.');
    const persist=db.transaction(()=>{db.prepare('INSERT INTO archived_recordings(id,connection_id,conversation_id,recording_id,destination_id,relative_path,file_name,mime_type,media_type,size_bytes,sha256,conversation_start,conversation_end,direction,ani,dnis,agent_names,flows,queues,interaction_type,duration_ms,metadata_json,archived_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(archiveId,genesys.id,conversationId,recordingId,destination.id,relativePath,fileName,converted.mimeType,screen?'screen':'audio',converted.bytes.length,crypto.createHash('sha256').update(converted.bytes).digest('hex'),summary.conversationStart||now,conversation.conversationEnd||null,summary.direction||'',summary.ani||'',summary.dnis||'',JSON.stringify(summary.agents||[]),JSON.stringify(summary.flows||[]),JSON.stringify(summary.queues||[]),summary.interactionType||'Unknown',summary.durationSeconds===null?resolved.durationMs||null:summary.durationSeconds*1000,JSON.stringify(metadata),now,expiresAt);db.prepare('INSERT INTO conversation_metadata_index(connection_id,conversation_id,indexed_at,expires_at,metadata_json) VALUES(?,?,?,?,?) ON CONFLICT(connection_id,conversation_id) DO UPDATE SET indexed_at=excluded.indexed_at,expires_at=excluded.expires_at,metadata_json=excluded.metadata_json').run(genesys.id,conversationId,now,expiresAt,JSON.stringify(redactSensitiveMetadata({conversation,recordings,sourceId})));db.prepare("INSERT OR IGNORE INTO library_metadata_backfill(archive_id,status,updated_at) VALUES(?,'pending',?)").run(archiveId,now);});persist();persisted=true;
    audit(req,'S3_LIBRARY_EXPORT','SUCCESS',`s3:${sourceId}`,conversationId,recordingId,{destinationId:destination.id,mediaType:screen?'screen':'audio',sizeBytes:converted.bytes.length});res.status(201).json({ok:true,id:archiveId,fileName,destinationName:destination.name,mediaType:screen?'screen':'audio',sizeBytes:converted.bytes.length});
   }catch(error){if(exportDestination&&!persisted)for(const name of written)await deleteDestinationFile(decryptDestination(exportDestination),name).catch(()=>{});audit(req,'S3_LIBRARY_EXPORT','FAILED',`s3:${sourceId}`,conversationId||undefined,recordingId||undefined);next(error);}finally{if(tempDir)await fs.rm(tempDir,{recursive:true,force:true});}
});

app.get('/api/library/destinations',requireAuth,requireLibraryAdmin,async(req,res,next)=>{
  try{const rows=db.prepare('SELECT d.*,COALESCE(SUM(a.size_bytes),0) AS archived_bytes FROM library_destinations d LEFT JOIN archived_recordings a ON a.destination_id=d.id GROUP BY d.id ORDER BY d.created_at').all() as (DestinationRow&{archived_bytes:number})[];const destinations=await Promise.all(rows.map(async row=>{const value=publicDestination(row),capacity=value.type==='local'?await localFilesystemCapacity(value.path):null;return {...value,storageTotalBytes:capacity?.totalBytes??null,storageFreeBytes:capacity?.freeBytes??null,archivedBytes:Number(row.archived_bytes)||0};}));const defaultSetting=db.prepare("SELECT value_json FROM application_settings WHERE key='library_default_destination_id'").get() as {value_json:string}|undefined,defaultDestinationId=defaultSetting?.value_json||'';res.json({destinations,defaultDestinationId:destinations.some(item=>item.id===defaultDestinationId)?defaultDestinationId:'',defaultLocalPath:DEFAULT_LIBRARY_PATH,recordingOutputFormat:getRecordingOutputFormat()});}catch(error){next(error);}
});
app.get('/api/library/destination-options',requireAuth,requireLibraryPlayback,(req,res,next)=>{
  try{const user=req.session.user!,all=user.role==='administrator'||hasAccessPermission(user.role,'libraryAdmin');let rows:{id:string;name:string;type:string}[];if(all)rows=db.prepare('SELECT DISTINCT d.id,d.name,d.type FROM library_destinations d LEFT JOIN archived_recordings a ON a.destination_id=d.id ORDER BY d.name COLLATE NOCASE').all() as typeof rows;else{const access=db.prepare('SELECT connection_id FROM user_connection_access WHERE user_id=?').all(user.id) as {connection_id:string}[];if(!access.length)rows=[];else rows=db.prepare('SELECT DISTINCT d.id,d.name,d.type FROM library_destinations d JOIN archived_recordings a ON a.destination_id=d.id WHERE a.connection_id IN ('+access.map(()=>'?').join(',')+') ORDER BY d.name COLLATE NOCASE').all(...access.map(row=>row.connection_id)) as typeof rows;}const defaultSetting=db.prepare("SELECT value_json FROM application_settings WHERE key='library_default_destination_id'").get() as {value_json:string}|undefined;let defaultDestinationId=defaultSetting?String(defaultSetting.value_json):'';if(!rows.some(row=>row.id===defaultDestinationId))defaultDestinationId='';res.json({destinations:rows,defaultDestinationId});}catch(error){next(error);}
});
app.put('/api/library/destinations/default',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const input=z.object({destinationId:z.string().max(128)}).parse(req.body);if(input.destinationId&&!db.prepare('SELECT id FROM library_destinations WHERE id=?').get(input.destinationId))throw httpError(400,'Choose an existing Library Destination.');const previousSetting=db.prepare("SELECT value_json FROM application_settings WHERE key='library_default_destination_id'").get() as {value_json:string}|undefined,previous=previousSetting?.value_json||'';if(input.destinationId)db.prepare("INSERT INTO application_settings(key,value_json) VALUES('library_default_destination_id',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json").run(input.destinationId);else db.prepare("DELETE FROM application_settings WHERE key='library_default_destination_id'").run();audit(req,'LIBRARY_DEFAULT_DESTINATION_UPDATE','SUCCESS',undefined,undefined,undefined,{previous,destinationId:input.destinationId});res.json({defaultDestinationId:input.destinationId});}catch(error){next(error);}
});
app.get('/api/library/recording-format',requireAuth,requireLibraryAdmin,async(_req,res,next)=>{
  try{res.json({format:getRecordingOutputFormat(),formats:RECORDING_OUTPUT_FORMATS,conversionAvailable:await checkAudioConverter()});}catch(error){next(error);}
});
app.put('/api/library/recording-format',requireAuth,requireLibraryAdmin,requireCsrf,async(req,res,next)=>{
  try{const input=z.object({format:z.enum(RECORDING_OUTPUT_FORMATS)}).parse(req.body),previous=getRecordingOutputFormat();if(!await checkAudioConverter())throw httpError(503,'Audio conversion is unavailable. Install FFmpeg and ensure it is available to the application service.');db.prepare("INSERT INTO application_settings(key,value_json) VALUES('recording_output_format',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json").run(JSON.stringify(input.format));audit(req,'LIBRARY_RECORDING_FORMAT_UPDATE','SUCCESS',undefined,undefined,undefined,{previous,format:input.format});res.json({format:input.format,mimeType:recordingOutputInfo(input.format).mimeType,extension:recordingOutputInfo(input.format).extension});}catch(error){next(error);}
});
app.post('/api/library/destinations/test',requireAuth,requireLibraryAdmin,requireCsrf,async(req,res,next)=>{
  try{const input=destinationSchema.parse(req.body);await testDestination(input);audit(req,'LIBRARY_DESTINATION_TEST','SUCCESS',undefined,undefined,undefined,{type:input.type,name:input.name});res.json({ok:true,message:'Destination test succeeded.'});}catch(error){audit(req,'LIBRARY_DESTINATION_TEST','FAILED',undefined,undefined,undefined,{type:req.body?.type});next(error instanceof GenesysError&&error.status===429?httpError(503,'Genesys API rate limit reached; retry after the current cooldown.'):error);}
});
app.post('/api/library/destinations',requireAuth,requireLibraryAdmin,requireCsrf,async(req,res,next)=>{
  try{const input=destinationSchema.parse(req.body);await testDestination(input);const id=crypto.randomUUID(),now=new Date().toISOString();const configEnc=destinationConfigJson(input);db.prepare('INSERT INTO library_destinations(id,name,type,config_enc,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').run(id,input.name,input.type,configEnc,req.session.user!.id,now,now);audit(req,'LIBRARY_DESTINATION_CREATE','SUCCESS',undefined,undefined,undefined,{destinationId:id,type:input.type,name:input.name});res.status(201).json({destination:publicDestination({id,name:input.name,type:input.type,config_enc:configEnc,created_at:now,updated_at:now})});}catch(error){next(error);}
});
app.put('/api/library/destinations/:id',requireAuth,requireLibraryAdmin,requireCsrf,async(req,res,next)=>{
  try{const id=String(req.params.id),existing=db.prepare('SELECT * FROM library_destinations WHERE id=?').get(id) as DestinationRow|undefined;if(!existing)throw httpError(404,'Destination not found.');const input=destinationInputSchema.parse(req.body);const previous=decryptDestination(existing);const config=destinationSchema.parse({...previous,...input,password:input.password||('password' in previous?previous.password:undefined)});await testDestination(config);const now=new Date().toISOString(),enc=destinationConfigJson(config);db.prepare('UPDATE library_destinations SET name=?,type=?,config_enc=?,updated_at=? WHERE id=?').run(config.name,config.type,enc,now,id);audit(req,'LIBRARY_DESTINATION_UPDATE','SUCCESS',undefined,undefined,undefined,{destinationId:id,type:config.type,name:config.name});res.json({destination:publicDestination({id,name:config.name,type:config.type,config_enc:enc,created_at:existing.created_at,updated_at:now})});}catch(error){next(error);}
});
app.delete('/api/library/destinations/:id',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id);if(db.prepare('SELECT id FROM library_schedules WHERE destination_id=? LIMIT 1').get(id)||db.prepare('SELECT id FROM archived_recordings WHERE destination_id=? LIMIT 1').get(id))throw httpError(409,'This destination is used by an archive schedule or archived recordings. Disable its schedules and remove/archive the files first.');const result=db.prepare('DELETE FROM library_destinations WHERE id=?').run(id);if(!result.changes)throw httpError(404,'Destination not found.');db.prepare("DELETE FROM application_settings WHERE key='library_default_destination_id' AND value_json=?").run(id);audit(req,'LIBRARY_DESTINATION_DELETE','SUCCESS',undefined,undefined,undefined,{destinationId:id});res.status(204).end();}catch(error){next(error);}
});
app.get('/api/library/schedules',requireAuth,requireLibraryAdmin,(req,res,next)=>{
  try{const schedules=db.prepare('SELECT s.*,c.name AS connection_name,d.name AS destination_name,(SELECT COUNT(*) FROM library_archive_queue q WHERE q.schedule_id=s.id AND q.status=\'pending\') AS pending_count,(SELECT COUNT(*) FROM library_archive_queue q WHERE q.schedule_id=s.id AND q.status=\'failed\') AS failed_count FROM library_schedules s JOIN connections c ON c.id=s.connection_id JOIN library_destinations d ON d.id=s.destination_id ORDER BY s.created_at').all();res.json({schedules});}catch(error){next(error);}
});
app.get('/api/library/worker-status',requireAuth,requireLibraryAdmin,(req,res)=>res.json(libraryArchiveWorker.status()));
app.get('/api/library/schedules/:id',requireAuth,requireLibraryAdmin,(req,res,next)=>{try{const schedule=db.prepare('SELECT * FROM library_schedules WHERE id=?').get(String(req.params.id));if(!schedule)throw httpError(404,'Schedule not found.');res.json({schedule});}catch(error){next(error);}});
app.post('/api/library/schedules',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const input=scheduleSchema.parse(req.body),connection=connectionById(input.connectionId,req.session.user!.id,req.session.user!.role);if(!db.prepare('SELECT id FROM library_destinations WHERE id=?').get(input.destinationId))throw httpError(400,'Choose an existing destination.');const now=new Date(),id=crypto.randomUUID(),cursor=initialArchiveCursor(now,input.lookbackDays),nextRun=nextScheduleTime({cadence:input.cadence,day_of_week:input.dayOfWeek??null,day_of_month:input.dayOfMonth??null,run_time:input.runTime,time_zone:input.timeZone},now);db.prepare("INSERT INTO library_schedules(id,name,connection_id,destination_id,cadence,day_of_week,day_of_month,run_time,time_zone,lookback_days,enabled,cursor_at,backfill_complete,next_run_at,run_status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,0,?,'queued',?,?,?)").run(id,input.name,connection.id,input.destinationId,input.cadence,input.dayOfWeek??null,input.dayOfMonth??null,input.runTime,input.timeZone,input.lookbackDays,cursor,nextRun,req.session.user!.id,now.toISOString(),now.toISOString());audit(req,'LIBRARY_SCHEDULE_CREATE','SUCCESS',connection.id,undefined,undefined,{scheduleId:id,cadence:input.cadence,lookbackDays:input.lookbackDays});void libraryArchiveWorker.tick();res.status(201).json({ok:true,id,cursorAt:cursor,lookbackDays:input.lookbackDays});}catch(error){next(error);}
});
app.put('/api/library/schedules/:id',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id),existing=db.prepare('SELECT * FROM library_schedules WHERE id=?').get(id) as any;if(!existing)throw httpError(404,'Schedule not found.');const input=scheduleSchema.parse(req.body);const connection=connectionById(input.connectionId,req.session.user!.id,req.session.user!.role);if(!db.prepare('SELECT id FROM library_destinations WHERE id=?').get(input.destinationId))throw httpError(400,'Choose an existing destination.');const now=new Date(),nextRun=nextScheduleTime({cadence:input.cadence,day_of_week:input.dayOfWeek??null,day_of_month:input.dayOfMonth??null,run_time:input.runTime,time_zone:input.timeZone},now),lookbackChanged=Number(existing.lookback_days||550)!==input.lookbackDays,cursor=lookbackChanged?initialArchiveCursor(now,input.lookbackDays):existing.cursor_at;const save=db.transaction(()=>{db.prepare("UPDATE library_schedules SET name=?,connection_id=?,destination_id=?,cadence=?,day_of_week=?,day_of_month=?,run_time=?,time_zone=?,lookback_days=?,cursor_at=?,backfill_complete=CASE WHEN ? THEN 0 ELSE backfill_complete END,run_status=CASE WHEN ? THEN CASE WHEN ? OR run_requested=1 THEN 'queued' ELSE 'idle' END ELSE run_status END,enabled=?,next_run_at=?,updated_at=? WHERE id=?").run(input.name,connection.id,input.destinationId,input.cadence,input.dayOfWeek??null,input.dayOfMonth??null,input.runTime,input.timeZone,input.lookbackDays,cursor,Number(lookbackChanged),Number(lookbackChanged),Number(input.enabled),Number(input.enabled),nextRun,now.toISOString(),id);if(lookbackChanged)db.prepare('DELETE FROM library_archive_queue WHERE schedule_id=? AND conversation_start<?').run(id,cursor);});save();audit(req,'LIBRARY_SCHEDULE_UPDATE','SUCCESS',connection.id,undefined,undefined,{scheduleId:id,enabled:input.enabled,lookbackDays:input.lookbackDays,backfillReset:lookbackChanged});void libraryArchiveWorker.tick();res.json({ok:true,backfillReset:lookbackChanged,lookbackDays:input.lookbackDays});}catch(error){next(error);}
});
app.post('/api/library/schedules/:id/retry',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id);if(!db.prepare('SELECT id FROM library_schedules WHERE id=?').get(id))throw httpError(404,'Schedule not found.');const retried=retryFailedArchive(id);db.prepare("UPDATE library_schedules SET run_status='queued',last_error=NULL,updated_at=? WHERE id=?").run(new Date().toISOString(),id);audit(req,'LIBRARY_SCHEDULE_RETRY','SUCCESS',undefined,undefined,undefined,{scheduleId:id,retried});void libraryArchiveWorker.tick();res.json({ok:true,retried});}catch(error){next(error);}
});
app.post('/api/library/schedules/:id/run-now',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id),now=new Date().toISOString();const result=db.prepare("UPDATE library_schedules SET run_requested=1,next_run_at=?,run_status='queued',last_error=NULL,updated_at=? WHERE id=?").run(now,now,id);if(!result.changes)throw httpError(404,'Schedule not found.');audit(req,'LIBRARY_SCHEDULE_RUN_NOW','SUCCESS',undefined,undefined,undefined,{scheduleId:id});void libraryArchiveWorker.tick();res.json({ok:true,queued:true});}catch(error){next(error);}
});
app.delete('/api/library/schedules/:id',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id);const result=db.prepare('DELETE FROM library_schedules WHERE id=?').run(id);if(!result.changes)throw httpError(404,'Schedule not found.');audit(req,'LIBRARY_SCHEDULE_DELETE','SUCCESS',undefined,undefined,undefined,{scheduleId:id});res.status(204).end();}catch(error){next(error);}
});
app.get('/api/library',requireAuth,requireLibraryPlayback,(req,res,next)=>{
  try{const query=String(req.query.q||'').trim().slice(0,128),page=Math.min(10000,Math.max(1,Number(req.query.page)||1)),pageSize=[25,50,100].includes(Number(req.query.pageSize))?Number(req.query.pageSize):25,showUnplayable=String(req.query.showUnplayable||'false')==='true',user=req.session.user!,parseDate=(value:unknown,end=false)=>{if(typeof value!=='string'||!value)return undefined;const time=Date.parse(value);if(!Number.isFinite(time))throw httpError(400,'Search dates must be valid.');const date=new Date(time);if(end)date.setUTCDate(date.getUTCDate()+1);return date.toISOString();};const filters={start:parseDate(req.query.start),end:parseDate(req.query.end,true),direction:['inbound','outbound'].includes(String(req.query.direction))?String(req.query.direction) as 'inbound'|'outbound':undefined,agentName:String(req.query.agentName||'').trim().slice(0,120)||undefined,queueName:String(req.query.queueName||'').trim().slice(0,120)||undefined,phone:String(req.query.phone||'').trim().slice(0,80)||undefined,dnis:String(req.query.dnis||'').trim().slice(0,80)||undefined,conversationId:String(req.query.conversationId||'').trim().slice(0,128)||undefined,destinationId:String(req.query.destinationId||'').trim().slice(0,128)||undefined};const connectionIds=user.role==='administrator'||hasAccessPermission(user.role,'libraryAdmin')?null:(db.prepare('SELECT connection_id FROM user_connection_access WHERE user_id=?').all(user.id) as {connection_id:string}[]).map(row=>row.connection_id);const result=listLibrary(query,pageSize,(page-1)*pageSize,connectionIds,showUnplayable,filters);audit(req,'LIBRARY_SEARCH','SUCCESS',undefined,undefined,undefined,{query:Boolean(query)||Object.values(filters).some(Boolean),results:result.total,page,showUnplayable});res.json({...result,page,pageSize,metadataBackfill:hasAccessPermission(user.role,'libraryAdmin')?libraryArchiveWorker.metadataStatus():null});}catch(error){next(error);}
});
app.post('/api/library/metadata-backfill/retry',requireAuth,requireLibraryAdmin,requireCsrf,(req,res,next)=>{try{const retried=libraryArchiveWorker.retryMetadataBackfill();audit(req,'LIBRARY_METADATA_BACKFILL_RETRY','SUCCESS',undefined,undefined,undefined,{retried});libraryArchiveWorker.wakeMetadataBackfill();res.json({ok:true,retried});}catch(error){next(error);}});
app.post('/api/library/:id/rearchive',requireAuth,requireLibraryAdmin,requireCsrf,async(req,res,next)=>{
  let row:Record<string,any>|undefined;
  try{row=archivedRecordingById(String(req.params.id));if(!row)throw httpError(404,'Archived recording not found.');if(!canAccessArchived(req,row))throw httpError(403,'You cannot access this archived recording.');const result=await libraryArchiveWorker.rearchive(row);audit(req,'LIBRARY_RECORDING_REARCHIVE','SUCCESS',row.connection_id,row.conversation_id,row.recording_id,{fileName:result.fileName,sizeBytes:result.sizeBytes});res.json({ok:true,...result});}catch(error){if(row)audit(req,'LIBRARY_RECORDING_REARCHIVE','FAILED',row.connection_id,row.conversation_id,row.recording_id);next(error);}
});
app.get('/api/library/:id/metadata',requireAuth,requireLibraryPlayback,async(req,res,next)=>{
  try{const row=archivedRecordingById(String(req.params.id));if(!row)throw httpError(404,'Archived recording not found.');if(!canAccessArchived(req,row))throw httpError(403,'You cannot access this archived recording.');audit(req,'LIBRARY_METADATA_VIEW','SUCCESS',row.connection_id,row.conversation_id,row.recording_id);const metadata=await archivedRecordingMetadata(row),backfill=db.prepare('SELECT status FROM library_metadata_backfill WHERE archive_id=?').get(row.id) as {status:string}|undefined;res.json({item:{id:row.id,conversationId:row.conversation_id,recordingId:row.recording_id,destinationId:row.destination_id,destinationName:row.destination_name,relativePath:row.relative_path,fileName:row.file_name,mimeType:row.mime_type,mediaType:row.media_type,sizeBytes:row.size_bytes,conversationStart:row.conversation_start,conversationEnd:row.conversation_end,direction:row.direction,ani:row.ani,dnis:row.dnis,agentNames:row.agent_names,queues:row.queues,durationMs:row.duration_ms,archivedAt:row.archived_at,expiresAt:row.expires_at,metadata,metadataStatus:backfill?.status||'pending'}});}catch(error){next(error);}
});
app.get('/api/library/:id/audio',requireAuth,requireLibraryPlayback,async(req,res,next)=>{
  try{const row=archivedRecordingById(String(req.params.id));if(!row)throw httpError(404,'Archived recording not found.');if(row.media_type==='screen')throw httpError(409,'This is a screen recording. Use its secure screen playback route.');if(!canAccessArchived(req,row))throw httpError(403,'You cannot access this archived recording.');const range=parseByteRange(typeof req.headers.range==='string'?req.headers.range:undefined,Number(row.size_bytes));if(range==='unsatisfiable'||range==='invalid'){res.setHeader('Content-Range',`bytes */${row.size_bytes}`);res.setHeader('Accept-Ranges','bytes');res.status(416).end();return;}const stream=await archivedRecordingStream(row,range||undefined);res.setHeader('Content-Type',row.mime_type);res.setHeader('Content-Disposition',`inline; filename="${String(row.file_name).replace(/[^a-zA-Z0-9._-]/g,'_')}"`);res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Accept-Ranges','bytes');if(range){res.status(206);res.setHeader('Content-Range',`bytes ${range.start}-${range.end}/${row.size_bytes}`);res.setHeader('Content-Length',String(range.end-range.start+1));}else res.setHeader('Content-Length',String(row.size_bytes));stream.on('error',()=>{if(!res.headersSent)next(httpError(502,'Archived audio could not be read from its destination.'));else res.destroy();});stream.pipe(res);audit(req,'LIBRARY_PLAYBACK','SUCCESS',row.connection_id,row.conversation_id,row.recording_id);}catch(error){next(error);}
});
app.get('/api/library/:id/screens',requireAuth,requireLibraryPlayback,async(req,res,next)=>{
  try{const row=archivedRecordingById(String(req.params.id));if(!row)throw httpError(404,'Archived recording not found.');if(!canAccessArchived(req,row))throw httpError(403,'You cannot access this archived recording.');const related=db.prepare("SELECT a.*,d.name AS name,d.type,d.config_enc FROM archived_recordings a JOIN library_destinations d ON d.id=a.destination_id WHERE a.connection_id=? AND a.conversation_id=? AND a.media_type='screen' ORDER BY a.archived_at,a.recording_id").all(row.connection_id,row.conversation_id) as (Record<string,any>&DestinationRow)[];const tracks=[] as {id:string;name:string;bytes:Buffer;mimeType:'video/webm'}[];for(const screenRow of related){if(!canAccessArchived(req,screenRow))continue;const bytes=await readDestinationFileBuffer(decryptDestination(screenRow),String(screenRow.relative_path),128*1024*1024);for(const track of tracksFromBytes(bytes,String(screenRow.file_name)))tracks.push({...track,id:`${screenRow.id}-${track.id}`,name:`${screenRow.file_name} · ${track.name}`});}const voice=db.prepare("SELECT id FROM archived_recordings WHERE connection_id=? AND conversation_id=? AND media_type='audio' ORDER BY archived_at,recording_id LIMIT 1").get(row.connection_id,row.conversation_id) as {id:string}|undefined,cachedOwner=`library:${req.session.user!.id}:${row.connection_id}:${row.conversation_id}`;if(!tracks.length)return res.json({tracks:[],audioUrl:voice?`/api/library/${encodeURIComponent(voice.id)}/audio`:undefined});const cacheId=cacheScreenTracks(cachedOwner,tracks);if(!cacheId)throw httpError(413,'Screen recording cannot be cached safely for playback.');audit(req,'LIBRARY_PLAYBACK','SUCCESS',row.connection_id,row.conversation_id,row.recording_id,{mediaType:'screen',monitorCount:tracks.length});res.setHeader('Cache-Control','private, no-store');res.json({audioUrl:voice?`/api/library/${encodeURIComponent(voice.id)}/audio`:undefined,tracks:tracks.map(track=>({id:track.id,name:track.name,mimeType:track.mimeType,url:`/api/library/${encodeURIComponent(row.id)}/screens/${encodeURIComponent(track.id)}/stream?cacheId=${encodeURIComponent(cacheId)}`}))});}catch(error){next(error);}
});
app.get('/api/library/:id/screens/:trackId/stream',requireAuth,requireLibraryPlayback,async(req,res,next)=>{
  try{const row=archivedRecordingById(String(req.params.id));if(!row)throw httpError(404,'Archived recording not found.');if(!canAccessArchived(req,row))throw httpError(403,'You cannot access this archived recording.');const cachedOwner=`library:${req.session.user!.id}:${row.connection_id}:${row.conversation_id}`,track=getCachedScreenTrack(String(req.query.cacheId||''),cachedOwner,String(req.params.trackId));if(!track)throw httpError(404,'Screen media session expired. Reopen the player to load this monitor.');audit(req,'LIBRARY_PLAYBACK','SUCCESS',row.connection_id,row.conversation_id,row.recording_id,{mediaType:'screen',trackId:track.id});serveAudioBuffer(req,res,track.bytes,track.mimeType);}catch(error){next(error);}
});
app.post('/api/genesys/connections', requireAuth, requireAdmin, requireCsrf, (req, res, next) => {
  try {
    const input = connectionSchema.parse(req.body);
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Disable Mock Mode and restart the application before saving live Genesys credentials.');
    const region = getRegions().find(r => r.id === input.regionId); if (!region) throw httpError(400, 'Unknown Genesys region.');
    let apiUrl:string,oauthUrl:string;try{apiUrl=trustedBaseUrl(input.apiBaseUrl || region.api, 'api',getRegions());oauthUrl=trustedBaseUrl(input.oauthBaseUrl || region.oauth, 'oauth',getRegions());}catch{throw httpError(400,'The endpoint must exactly match a configured Genesys Cloud region URL.');}
    if(apiUrl!==region.api||oauthUrl!==region.oauth)throw httpError(400,'API and OAuth base URLs must match the selected official region.');
    const id = crypto.randomUUID(), now = new Date().toISOString();
    const transaction = db.transaction(() => {
      if (input.isDefault) db.prepare('UPDATE connections SET is_default=0').run();
      db.prepare('INSERT INTO connections(id,name,organization_label,region_id,api_base_url,oauth_base_url,client_id,client_secret_enc,enabled,is_default,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(id,input.name,input.organizationLabel,input.regionId,apiUrl,oauthUrl,input.clientId,encrypt(input.clientSecret),Number(input.enabled),Number(input.isDefault),now,now);
      // Organization access is granted deliberately by an administrator; no broad default grants.
    }); transaction();
    audit(req,'CONNECTION_CREATE','SUCCESS',id);
    res.status(201).json({ id, name: input.name });
  } catch (error) { next(error); }
});
app.put('/api/genesys/connections/:id', requireAuth, requireAdmin, requireCsrf, (req, res, next) => {
  try {
    const existing = db.prepare('SELECT * FROM connections WHERE id=?').get(req.params.id) as Connection | undefined;
    if (!existing) throw httpError(404,'Connection not found.');
    if(!getRegions().some(value=>value.id===existing.region_id&&value.api===existing.api_base_url&&value.oauth===existing.oauth_base_url))throw httpError(409,'The stored connection endpoints are not trusted. Reconfigure this connection to a configured region.');
    const input = connectionSchema.partial({ clientSecret: true }).parse(req.body);
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Disable Mock Mode and restart the application before updating live Genesys credentials.');
    const region = getRegions().find(r => r.id === (input.regionId || existing.region_id)); if (!region) throw httpError(400,'Unknown Genesys region.');
    let apiUrl:string,oauthUrl:string;try{apiUrl=trustedBaseUrl(input.apiBaseUrl || region.api,'api',getRegions());oauthUrl=trustedBaseUrl(input.oauthBaseUrl || region.oauth,'oauth',getRegions());}catch{throw httpError(400,'The endpoint must exactly match a configured Genesys Cloud region URL.');}
    if(apiUrl!==region.api||oauthUrl!==region.oauth)throw httpError(400,'API and OAuth base URLs must match the selected official region.');
    const nextEnabled=Boolean(input.enabled ?? Boolean(existing.enabled));
    const nextClientId=input.clientId ?? existing.client_id;
    const nextSecret=input.clientSecret ? encrypt(input.clientSecret) : existing.client_secret_enc;
    const nextDefault=Boolean(input.isDefault ?? Boolean(existing.is_default));
    const regionChanged=(input.regionId||existing.region_id)!==existing.region_id;
    const clientChanged=(input.clientId&&input.clientId!==existing.client_id)||Boolean(input.clientSecret);
    const transaction=db.transaction(()=>{if(nextDefault)db.prepare('UPDATE connections SET is_default=0').run();db.prepare('UPDATE connections SET name=?,organization_label=?,region_id=?,api_base_url=?,oauth_base_url=?,client_id=?,client_secret_enc=?,enabled=?,is_default=?,updated_at=?,last_error=NULL WHERE id=?').run(input.name ?? existing.name,input.organizationLabel ?? existing.organization_label,input.regionId ?? existing.region_id,apiUrl,oauthUrl,nextClientId,nextSecret,Number(nextEnabled),Number(nextDefault),new Date().toISOString(),existing.id);if(!nextEnabled||regionChanged||clientChanged)db.prepare('DELETE FROM user_connection_access WHERE connection_id=?').run(existing.id);});transaction();
    new GenesysClient(existing).clearCachedToken();
    audit(req,'CONNECTION_UPDATE','SUCCESS',existing.id); res.json({ ok:true });
  } catch(error) { next(error); }
});
app.delete('/api/genesys/connections/:id', requireAuth, requireAdmin, requireCsrf, (req,res,next) => {
    try { const id=String(req.params.id);const connection=db.prepare('SELECT * FROM connections WHERE id=?').get(id) as Connection|undefined;if(!connection)throw httpError(404,'Connection not found.');if(process.env.MOCK_MODE==='true')throw httpError(409,'Disable Mock Mode and restart the application before changing live connections.');db.prepare('DELETE FROM connections WHERE id=?').run(id);new GenesysClient(connection).clearCachedToken();audit(req,'CONNECTION_DELETE','SUCCESS',id);res.status(204).end(); }
  catch(error) { next(error); }
});
app.post('/api/genesys/connections/test', requireAuth, requireAdmin, requireCsrf, async (req,res,next) => {
  try {
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Mock Mode is active. Live Genesys connectivity tests are disabled.');
    const input=connectionTestSchema.parse(req.body);
    const region=getRegions().find(value=>value.id===input.regionId);
    if(!region)throw httpError(400,'Unknown Genesys region.');
    let apiUrl:string,oauthUrl:string;
    try{apiUrl=trustedBaseUrl(input.apiBaseUrl||region.api,'api',getRegions());oauthUrl=trustedBaseUrl(input.oauthBaseUrl||region.oauth,'oauth',getRegions());}
    catch{throw httpError(400,'The endpoint must exactly match an official Genesys Cloud region URL.');}
    if(apiUrl!==region.api||oauthUrl!==region.oauth)throw httpError(400,'API and OAuth base URLs must match the selected official region.');
    let secretEnc:string;
    if(input.clientSecret)secretEnc=encrypt(input.clientSecret);
    else {
      if(!input.existingConnectionId)throw httpError(400,'Enter the OAuth client secret to test this connection.');
      const existing=db.prepare('SELECT * FROM connections WHERE id=?').get(input.existingConnectionId) as Connection|undefined;
      if(!existing)throw httpError(404,'Saved connection not found.');
      if(input.clientId!==existing.client_id)throw httpError(400,'Enter the client secret when changing the OAuth Client ID.');
      if(input.regionId!==existing.region_id)throw httpError(400,'Enter the client secret when changing the Genesys region.');
      secretEnc=existing.client_secret_enc;
    }
    const client=new GenesysClient({id:`draft-${crypto.randomUUID()}`,name:input.name,organization_label:input.organizationLabel,region_id:input.regionId,api_base_url:apiUrl,oauth_base_url:oauthUrl,client_id:input.clientId,client_secret_enc:secretEnc,enabled:1,is_default:0});
    let organization:{id?:string;name?:string};
    try { await client.accessToken(); organization=await verifyGenesysApiAccess(client); }
    finally { client.clearCachedToken(); }
    audit(req,'CONNECTION_TEST','SUCCESS',input.existingConnectionId,undefined,undefined,{draft:true,regionId:input.regionId});
    res.json({ok:true,message:`OAuth authentication and Genesys organization API access succeeded${organization.name?` for "${organization.name}"`:''}.`});
  } catch(error) { audit(req,'CONNECTION_TEST','FAILED',undefined,undefined,undefined,{draft:true}); next(error); }
});
app.post('/api/genesys/connections/:id/test', requireAuth, requireAdmin, requireCsrf, async (req,res,next) => {
  try {
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Mock Mode is active. Live Genesys connectivity tests are disabled.');
    const id=String(req.params.id); const connection = db.prepare('SELECT * FROM connections WHERE id=?').get(id) as Connection | undefined;
    if (!connection) throw httpError(404,'Connection not found.');
    if(!connection.enabled)throw httpError(409,'Enable the connection before testing it.');
    if(!getRegions().some(value=>value.id===connection.region_id&&value.api===connection.api_base_url&&value.oauth===connection.oauth_base_url))throw httpError(409,'The connection endpoints are not trusted.');
    const client = new GenesysClient(connection); client.clearCachedToken();
    let organization:{id?:string;name?:string};
    try { await client.accessToken(); organization=await verifyGenesysApiAccess(client); }
    finally { client.clearCachedToken(); }
    const now = new Date().toISOString(); db.prepare('UPDATE connections SET last_success_at=?,last_error=NULL WHERE id=?').run(now,connection.id);
    audit(req,'CONNECTION_TEST','SUCCESS',connection.id); res.json({ ok:true,message:`OAuth authentication and Genesys organization API access succeeded${organization.name?` for "${organization.name}"`:''}.` });
  } catch(error) { const safe = publicError(error); const id=String(req.params.id); if(id) db.prepare('UPDATE connections SET last_error=? WHERE id=?').run(safe,id); audit(req,'CONNECTION_TEST','FAILED',id); next(error); }
});
app.get('/api/genesys/connections/:id/permissions', requireAuth, requireAdmin, (req,res,next) => {
  try { if(process.env.MOCK_MODE==='true')throw httpError(409,'Mock Mode is active. No live Genesys permissions are configured.');connectionById(String(req.params.id),req.session.user!.id,req.session.user!.role); res.json({ permissions:[{ name:'analytics:conversationDetail:view', purpose:'Search conversation details'},{name:'recording:recording:view', purpose:'Discover and play recordings'}], verified:false, note:'Permission availability must be verified against the configured Genesys organization; this screen does not infer delegated user permissions.' }); }
  catch(error) { next(error); }
});
app.get('/api/admin/smtp',requireAuth,requireAdmin,(req,res,next)=>{
  try { const stored=getStoredSmtpSettings();res.json({settings:publicSmtpSettings(stored.settings,stored.passwordConfigured)}); }
  catch(error){next(error);}
});
app.put('/api/admin/smtp',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try {
    const passwordInput=typeof req.body?.password==='string'?req.body.password:'';
    const previous=getStoredSmtpSettings();
    const candidate={...req.body,password:passwordInput||previous.settings.password};
    let settings:SmtpSettings;
    try{settings=parseSmtpSettings(candidate);}catch(error){if(!passwordInput&&!previous.passwordConfigured)throw httpError(400,'Enter the SMTP password or app password before saving.');throw httpError(400,error instanceof Error?error.message:'SMTP settings are invalid.');}
    if(!settings.password)throw httpError(400,'Enter the SMTP password or app password before saving.');
    const value={...settings,passwordEnc:encrypt(settings.password)};
    delete (value as Partial<typeof value>).password;
    db.prepare("INSERT INTO application_settings(key,value_json) VALUES('smtp_settings',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json").run(JSON.stringify(value));
    audit(req,'SMTP_SETTINGS_UPDATE','SUCCESS');
    res.json({settings:publicSmtpSettings(settings,true)});
  } catch(error){next(error);}
});
app.post('/api/admin/smtp/test',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{
  try {
    const stored=getStoredSmtpSettings();
    if(!stored.passwordConfigured)throw httpError(409,'Save SMTP credentials before sending a test email.');
    const recipient=z.string().trim().email().max(320).parse(req.body?.to);
    let info;
    try{info=await sendConfiguredEmail(stored.settings,{to:recipient,subject:'MFEC Recording Explorer SMTP test',text:'This is a test email confirming that the configured SMTP server can send mail.'});}
    catch{throw httpError(502,'SMTP test email could not be sent. Verify the host, port, TLS settings, credentials, and server outbound mail access.');}
    audit(req,'SMTP_TEST_EMAIL','SUCCESS',undefined,undefined,undefined,{recipient});
    res.json({ok:true,messageId:info.messageId});
  } catch(error){audit(req,'SMTP_TEST_EMAIL','FAILED');next(error);}
});
app.get('/api/admin/roles',requireAuth,requireAdmin,(_req,res)=>res.json({roles:listAccessRoles()}));
app.post('/api/admin/roles',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try{const name=validateRoleName(req.body?.name);if(!name)throw httpError(400,'Role name must be 2–64 characters and cannot contain markup or control characters.');if(db.prepare('SELECT 1 FROM access_roles WHERE name=? COLLATE NOCASE').get(name))throw httpError(409,'A role with this name already exists.');const permissions=normalizeRolePermissions(req.body?.permissions);const id=crypto.randomUUID();const now=new Date().toISOString();db.prepare('INSERT INTO access_roles(id,name,permissions_json,built_in,created_at,updated_at) VALUES(?,?,?,0,?,?)').run(id,name,JSON.stringify(permissions),now,now);audit(req,'ACCESS_ROLE_CREATE','SUCCESS',undefined,undefined,undefined,{roleId:id,name});res.status(201).json({role:{id,name,permissions,builtIn:false,userCount:0}});}catch(error){next(error);}
});
app.put('/api/admin/roles/:id',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id);if(isBuiltInRole(id))throw httpError(409,'Built-in roles cannot be edited. Create a custom role instead.');const name=validateRoleName(req.body?.name);if(!name)throw httpError(400,'Role name must be 2–64 characters and cannot contain markup or control characters.');if(db.prepare('SELECT 1 FROM access_roles WHERE name=? COLLATE NOCASE AND id<>?').get(name,id))throw httpError(409,'A role with this name already exists.');const permissions=normalizeRolePermissions(req.body?.permissions);const result=db.prepare('UPDATE access_roles SET name=?,permissions_json=?,updated_at=? WHERE id=?').run(name,JSON.stringify(permissions),new Date().toISOString(),id);if(!result.changes)throw httpError(404,'Role not found.');revokeRoleSessions(id);audit(req,'ACCESS_ROLE_UPDATE','SUCCESS',undefined,undefined,undefined,{roleId:id,name});res.json({role:{id,name,permissions,builtIn:false}});}catch(error){next(error);}
});
app.delete('/api/admin/roles/:id',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try{const id=String(req.params.id);if(isBuiltInRole(id))throw httpError(409,'Built-in roles cannot be deleted.');const count=Number((db.prepare('SELECT COUNT(*) AS n FROM users WHERE access_role_id=?').get(id) as {n:number}).n);if(count)throw httpError(409,`This role is assigned to ${count} user${count===1?'':'s'}. Reassign those users before deleting it.`);const result=db.prepare('DELETE FROM access_roles WHERE id=?').run(id);if(!result.changes)throw httpError(404,'Role not found.');audit(req,'ACCESS_ROLE_DELETE','SUCCESS',undefined,undefined,undefined,{roleId:id});res.status(204).end();}catch(error){next(error);}
});
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>{
  const users=db.prepare('SELECT id,username,COALESCE(access_role_id,role) AS role,enabled,created_at AS createdAt,email,phone,first_name AS firstName,last_name AS lastName,nickname,job_title AS jobTitle,division,department FROM users ORDER BY username').all() as {id:string;username:string;role:string;enabled:number;createdAt:string}[];
  const grants=db.prepare('SELECT user_id AS userId,connection_id AS connectionId FROM user_connection_access').all() as {userId:string;connectionId:string}[];
  res.json({users:users.map(user=>({...user,connections:grants.filter(grant=>grant.userId===user.id).map(grant=>grant.connectionId)}))});
});
app.post('/api/admin/users',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{
  try { const input=z.object({username:z.string().trim().min(2).max(128).regex(/^[\p{L}\p{N}._@-]+$/u),password:z.string().min(8).max(256),role:z.string().min(1).max(64),connectionIds:z.array(z.string()).max(100).default([]),profile:profileSchema.default(emptyProfile)}).parse(req.body);if(!db.prepare('SELECT id FROM access_roles WHERE id=?').get(input.role))throw httpError(400,'Choose an existing access role.'); if(!isPasswordPolicySatisfied(input.password))throw httpError(400,'Password must be at least 8 characters and include a letter plus a number or special character.');for(const connectionId of input.connectionIds)if(!db.prepare('SELECT id FROM connections WHERE id=? AND enabled=1').get(connectionId))throw httpError(400,'An enabled organization connection is required.'); const id=crypto.randomUUID(),legacyRole=input.role==='administrator'?'administrator':'viewer';
    const transaction=db.transaction(()=>{db.prepare('INSERT INTO users(id,username,password_hash,role,access_role_id,created_at,email,phone,first_name,last_name,nickname,job_title,division,department) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,input.username,awaitHash(input.password),legacyRole,input.role,new Date().toISOString(),input.profile.email,input.profile.phone,input.profile.firstName,input.profile.lastName,input.profile.nickname,input.profile.jobTitle,input.profile.division,input.profile.department);const grant=db.prepare('INSERT INTO user_connection_access(user_id,connection_id) VALUES(?,?)');for(const connectionId of input.connectionIds)grant.run(id,connectionId);}); transaction(); audit(req,'USER_CREATE','SUCCESS'); res.status(201).json({id,username:input.username});
  } catch(error){next(error);}
});
app.put('/api/admin/users/:id/profile',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const id=String(req.params.id),profile=profileSchema.parse(req.body);if(!db.prepare('SELECT id FROM users WHERE id=?').get(id))throw httpError(404,'User not found.');db.prepare('UPDATE users SET email=?,phone=?,first_name=?,last_name=?,nickname=?,job_title=?,division=?,department=? WHERE id=?').run(profile.email,profile.phone,profile.firstName,profile.lastName,profile.nickname,profile.jobTitle,profile.division,profile.department,id);audit(req,'USER_PROFILE_UPDATE','SUCCESS',undefined,undefined,undefined,{userId:id});res.json({profile}); }
  catch(error){next(error);}
});
app.post('/api/admin/users/:id/password',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{
  try { const id=String(req.params.id),{password}=z.object({password:z.string().min(8).max(256)}).parse(req.body);if(id===req.session.user!.id)throw httpError(400,'Use Change password in Settings to update your own password.');if(!isPasswordPolicySatisfied(password))throw httpError(400,'Password must be at least 8 characters and include a letter plus a number or special character.');const target=db.prepare('SELECT id FROM users WHERE id=?').get(id);if(!target)throw httpError(404,'User not found.');const hash=await bcrypt.hash(password,12);db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash,id);revokeUserSessions(id);audit(req,'USER_PASSWORD_RESET','SUCCESS',undefined,undefined,undefined,{userId:id});res.json({ok:true}); }
  catch(error){next(error);}
});
app.put('/api/admin/users/:id/access',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const input=z.object({connectionIds:z.array(z.string()).max(100)}).parse(req.body),id=String(req.params.id);if(!db.prepare('SELECT id FROM users WHERE id=?').get(id))throw httpError(404,'User not found.');for(const connectionId of input.connectionIds)if(!db.prepare('SELECT id FROM connections WHERE id=? AND enabled=1').get(connectionId))throw httpError(400,'An enabled organization connection is required.');const transaction=db.transaction(()=>{db.prepare('DELETE FROM user_connection_access WHERE user_id=?').run(id);const insert=db.prepare('INSERT INTO user_connection_access(user_id,connection_id) VALUES(?,?)');for(const connectionId of input.connectionIds)insert.run(id,connectionId);});transaction();audit(req,'USER_ACCESS_UPDATE','SUCCESS',undefined,undefined,undefined,{userId:id,connectionCount:input.connectionIds.length});res.json({ok:true}); }
  catch(error){next(error);}
});
app.put('/api/admin/users/:id/role',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const {role}=z.object({role:z.string().min(1).max(64)}).parse(req.body),id=String(req.params.id);if(!db.prepare('SELECT id FROM access_roles WHERE id=?').get(role))throw httpError(400,'Choose an existing access role.');if(id===req.session.user!.id&&role!=='administrator')throw httpError(400,'Administrators cannot remove their own administrator role.');const target=db.prepare('SELECT u.role,COALESCE(u.access_role_id,u.role) AS accessRoleId FROM users u WHERE id=?').get(id) as {role:string;accessRoleId:string}|undefined;if(!target)throw httpError(404,'User not found.');if(target.accessRoleId===role)return res.json({ok:true});if(target.accessRoleId==='administrator'&&role!=='administrator'&&Number((db.prepare("SELECT COUNT(*) AS n FROM users u WHERE u.enabled=1 AND COALESCE(u.access_role_id,u.role)='administrator'").get() as {n:number}).n)<=1)throw httpError(409,'The last enabled administrator cannot be demoted.');db.prepare('UPDATE users SET access_role_id=?,role=? WHERE id=?').run(role,role==='administrator'?'administrator':'viewer',id);revokeUserSessions(id);audit(req,'USER_ROLE_UPDATE','SUCCESS',undefined,undefined,undefined,{userId:id,role});res.json({ok:true}); }
  catch(error){next(error);}
});
app.put('/api/admin/users/:id/enabled',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const {enabled}=z.object({enabled:z.boolean()}).parse(req.body),id=String(req.params.id);if(id===req.session.user!.id&&!enabled)throw httpError(400,'Administrators cannot disable their own account.');const target=db.prepare('SELECT u.role,COALESCE(u.access_role_id,u.role) AS accessRoleId,u.enabled FROM users u WHERE id=?').get(id) as {role:string;accessRoleId:string;enabled:number}|undefined;if(!target)throw httpError(404,'User not found.');if(Boolean(target.enabled)===enabled)return res.json({ok:true});if(target.accessRoleId==='administrator'&&target.enabled&&!enabled&&Number((db.prepare("SELECT COUNT(*) AS n FROM users u WHERE u.enabled=1 AND COALESCE(u.access_role_id,u.role)='administrator'").get() as {n:number}).n)<=1)throw httpError(409,'The last enabled administrator cannot be disabled.');db.prepare('UPDATE users SET enabled=? WHERE id=?').run(Number(enabled),id);revokeUserSessions(id);audit(req,'USER_STATUS_UPDATE','SUCCESS',undefined,undefined,undefined,{userId:id,enabled});res.json({ok:true}); }
  catch(error){next(error);}
});
app.delete('/api/admin/users/:id',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const id=String(req.params.id);if(id===req.session.user!.id)throw httpError(400,'You cannot delete your own account.');const target=db.prepare('SELECT u.username,u.role,COALESCE(u.access_role_id,u.role) AS accessRoleId,u.enabled FROM users u WHERE id=?').get(id) as {username:string;role:string;accessRoleId:string;enabled:number}|undefined;if(!target)throw httpError(404,'User not found.');if(target.accessRoleId==='administrator'&&target.enabled&&Number((db.prepare("SELECT COUNT(*) AS n FROM users u WHERE u.enabled=1 AND COALESCE(u.access_role_id,u.role)='administrator'").get() as {n:number}).n)<=1)throw httpError(409,'The last enabled administrator cannot be deleted.');revokeUserSessions(id);db.prepare('DELETE FROM users WHERE id=?').run(id);audit(req,'USER_DELETE','SUCCESS',undefined,undefined,undefined,{userId:id,username:target.username});res.status(204).end(); }
  catch(error){next(error);}
});

app.get('/api/genesys/directory',requireAuth,requireRecordingSearch,rateLimit({windowMs:60*1000,limit:60,standardHeaders:'draft-7',legacyHeaders:false}),async(req,res,next)=>{
  try{
    const input=z.object({connectionId:z.string().min(1),type:z.enum(['agent','group','queue']),q:z.string().trim().min(2).max(120)}).parse(req.query);
    let connectionId=input.connectionId;
    if(connectionId.startsWith('s3:')){
      const sourceId=connectionId.slice(3),source=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(sourceId) as S3SourceRow|undefined;
      if(!source||!canUseS3Source(source,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');
      if(!source.genesys_connection_id)throw httpError(404,'AWS S3 source is not linked to a Genesys Connection.');
      connectionId=source.genesys_connection_id;
    }
    if(connectionId==='mock'&&process.env.MOCK_MODE==='true'){
      const needle=input.q.toLocaleLowerCase();
      return res.json({suggestions:MOCK_DIRECTORY[input.type].filter(item=>item.name.toLocaleLowerCase().includes(needle)).sort((a,b)=>Number(!a.name.toLocaleLowerCase().startsWith(needle))-Number(!b.name.toLocaleLowerCase().startsWith(needle))||a.name.localeCompare(b.name)).slice(0,10)});
    }
    const connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role),client=new GenesysClient(connection);
    res.setHeader('Cache-Control','private, max-age=30');
    res.json({suggestions:await searchDirectory(client,input.type,input.q)});
  }catch(error){next(error);}
});

app.post('/api/recordings/search', requireAuth, requireRecordingSearch, requireCsrf, rateLimit({windowMs:60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false}), async (req,res,next) => {
  try {
    const input = searchSchema.parse(req.body); const user = req.session.user!;
     if(input.connectionId.startsWith('s3:')){
      try{
        if(input.groupName)throw httpError(400,'Group search is not supported for AWS S3 recordings.');
         const id=input.connectionId.slice(3),row=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(id) as S3SourceRow|undefined;if(!row||!canUseS3Source(row,user.id,user.role))throw httpError(404,'AWS S3 source not found or access denied.');
        const from=Date.parse(input.intervalStart),to=Date.parse(input.intervalEnd);if(!Number.isFinite(from)||!Number.isFinite(to)||from>=to)throw httpError(400,'Choose a valid start and end time.');if(to-from>90*86400000)throw httpError(400,'Search intervals are limited to 90 days. Narrow the date range to continue.');
          const config=decryptS3Source(row),genesys=connectionById(row.genesys_connection_id!,user.id,user.role),client=new GenesysClient(genesys),result=await searchS3Recordings(config,{start:input.intervalStart,end:input.intervalEnd,direction:input.direction,agentName:input.agentName,queueName:input.queueName,phone:input.phone,dnis:input.dnis,conversationId:input.conversationId,pageNumber:input.pageNumber,pageSize:input.pageSize},undefined,async record=>{try{const conversation=await getCachedGenesysConversation(client,genesys.id,record.conversationId),geneSysRecordings=listPlayableRecordings(await listConversationRecordings(client,record.conversationId),conversation);if(!geneSysRecordings.length)return undefined;const exportedById=new Map(record.recordings.map(exported=>[exported.id,exported])),matched=geneSysRecordings.filter(item=>exportedById.has(String(item.id||item.recordingId)));if(!matched.length)return undefined;const mapped=await mapParticipantUserNames(client,conversation),queueNames=await mapConversationQueueNames(client,mapped),summary=summarizeConversation(mapped),normalizedRecordings=matched.map(item=>{const recordingId=String(item.id||item.recordingId),exported=exportedById.get(recordingId)!;return {id:recordingId,startTime:item.startTime||item.recordingStartTime||exported.startTime,status:item.status||item.recordingState||'AVAILABLE',media:isScreenRecording(item)?'screen':item.media||'audio',mediaType:item.mediaType||item.mediaSubtype||(isScreenRecording(item)?'screenRecording':'voice'),durationMs:item.durationMs||exported.durationMs,hasMedia:true,metadataKey:exported.metadataKey};});const cached={conversation,recordings:geneSysRecordings};db.prepare('INSERT INTO conversation_metadata_index(connection_id,conversation_id,indexed_at,expires_at,metadata_json) VALUES(?,?,?,?,?) ON CONFLICT(connection_id,conversation_id) DO UPDATE SET indexed_at=excluded.indexed_at,expires_at=excluded.expires_at,metadata_json=excluded.metadata_json').run(genesys.id,record.conversationId,new Date().toISOString(),new Date(Date.now()+30*86400000).toISOString(),JSON.stringify(redactSensitiveMetadata(cached)));return {...record,...summary,conversationId:record.conversationId,recordingCount:normalizedRecordings.length,agents:summary.agents,queues:conversationQueueNames(mapped,queueNames),flows:summary.flows,wrapUp:conversationWrapUpCodeNames(conversation).join(', '),recordings:normalizedRecordings};}catch(error){if(error instanceof GenesysError&&[403,404].includes(error.status))return undefined;throw error;}});audit(req,'SEARCH',result.partial?'PARTIAL':'SUCCESS',`s3:${id}`,undefined,undefined,{sourceType:'aws-s3',genesysConnectionId:genesys.id,page:input.pageNumber,recordingsFound:result.results.reduce((sum,item)=>sum+item.recordingCount,0),partial:result.partial});return res.json(result);
      }catch(error){if(![400,404].includes(Number((error as {status?:number}).status)))throw httpError(502,'AWS S3 metadata search failed. Check the source IAM permissions and bucket configuration.');throw error;}
    }
    const connection = input.connectionId === 'mock' ? null : connectionById(input.connectionId,user.id,user.role);
    if (!connection && !(input.connectionId === 'mock' && process.env.MOCK_MODE === 'true')) throw httpError(404,'Connection not found or access denied.');
    const from = Date.parse(input.intervalStart), to = Date.parse(input.intervalEnd);
    if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) throw httpError(400,'Choose a valid start and end time.');
    if (to - from > 90 * 86400000) throw httpError(400,'Search intervals are limited to 90 days. Narrow the date range to continue.');
    const client = connection ? new GenesysClient(connection) : null;
    let conversations: any[] = [], totalHits: number | null = null, partial = false;
    let selectedAgent: {id:string;name:string}|undefined,selectedQueue: {id:string;name:string}|undefined;
    if (!client) {
      conversations = MOCK_CONVERSATIONS.filter(c => Date.parse(c.conversationStart) >= from && Date.parse(c.conversationStart) <= to && mockMatches(c,input) && (!input.conversationId||c.conversationId===input.conversationId));
      if(input.agentName)conversations=conversations.filter(c=>summarizeConversation(c).agents.some((name:string)=>name.toLocaleLowerCase()===input.agentName!.toLocaleLowerCase()));
      if(input.queueName)conversations=conversations.filter(c=>conversationQueueNames(c).some((name:string)=>name.toLocaleLowerCase()===input.queueName!.toLocaleLowerCase()));
      if(input.groupName){const groupMembers=new Set(MOCK_GROUP_MEMBERS[MOCK_DIRECTORY.group.find(group=>group.name.toLocaleLowerCase()===input.groupName!.toLocaleLowerCase())?.id||'']||[]);conversations=conversations.filter(c=>(c.participants||[]).some((participant:any)=>groupMembers.has(participant.userId)));}
      totalHits = conversations.length;
    } else {
      const segmentPredicates: any[] = [...VOICE_RECORDING_FILTERS.segmentFilters[0].predicates];
      const [agentMatches,queueMatches,groupMatches]=await Promise.all([
        input.agentName?resolveDirectorySelection(client,'agent',input.agentName):Promise.resolve([]),
        input.queueName?resolveDirectorySelection(client,'queue',input.queueName):Promise.resolve([]),
        input.groupName?resolveDirectorySelection(client,'group',input.groupName):Promise.resolve([]),
      ]);
      const missingDirectoryMatch=Boolean((input.agentName&&!agentMatches.length)||(input.queueName&&!queueMatches.length)||(input.groupName&&!groupMatches.length));
      if(input.agentName&&agentMatches.length){selectedAgent=agentMatches[0];segmentPredicates.push({type:'dimension',dimension:'userId',operator:'matches',value:selectedAgent.id});}
      if(input.queueName&&queueMatches.length){selectedQueue=queueMatches[0];segmentPredicates.push({type:'dimension',dimension:'queueId',operator:'matches',value:selectedQueue.id});}
      const analyticsFilters: Record<string,unknown> = {};
      if(input.direction) analyticsFilters.conversationFilters=[{type:'and',predicates:[{type:'dimension',dimension:'originatingDirection',operator:'matches',value:input.direction}]}];
      if(segmentPredicates.length) analyticsFilters.segmentFilters=[{type:'and',predicates:segmentPredicates}];
      let selectedGroupMembers:Set<string>|undefined;
      if(input.groupName&&groupMatches.length)selectedGroupMembers=await groupMemberUserIds(client,groupMatches[0].id);

      if(input.conversationId) {
        const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(input.conversationId)}/details`);
        conversations=conversation?.conversationId===input.conversationId && Date.parse(conversation.conversationStart)>=from && Date.parse(conversation.conversationStart)<=to ? [conversation] : [];
        if(missingDirectoryMatch)conversations=[];
        if(selectedAgent)conversations=conversations.filter(item=>(item?.participants||[]).some((participant:any)=>participantUserLookupId(participant)===selectedAgent!.id));
        if(selectedQueue)conversations=conversations.filter(item=>(item?.participants||[]).some((participant:any)=>(participant?.sessions||[]).some((session:any)=>session?.queueId===selectedQueue!.id||(session?.segments||[]).some((segment:any)=>segment?.queueId===selectedQueue!.id))));
        if(selectedGroupMembers)conversations=conversations.filter(item=>(item?.participants||[]).some((participant:any)=>selectedGroupMembers!.has(participantUserLookupId(participant))));
        totalHits=conversations.length;
      } else {
        if(missingDirectoryMatch){conversations=[];totalHits=0;}
        else {
        if(to-from<=7*86400000){
          const response=await queryAllConversations(client,`${new Date(from).toISOString()}/${new Date(to).toISOString()}`,analyticsFilters);
          conversations=response.conversations;totalHits=response.totalHits;partial=response.partial;
        }else{
          const unique=new Map<string,any>();
          for(let chunkStart=from;chunkStart<to;){
            const chunkEnd=Math.min(to,chunkStart+7*86400000);
            const remaining=MAX_ANALYTICS_CONVERSATIONS-unique.size;
            if(remaining<=0){partial=true;break;}
            const response=await queryAllConversations(client,`${new Date(chunkStart).toISOString()}/${new Date(chunkEnd).toISOString()}`,analyticsFilters,remaining);
            for(const conversation of response.conversations)if(conversation?.conversationId&&!unique.has(conversation.conversationId))unique.set(conversation.conversationId,conversation);
            partial||=response.partial;
            if(unique.size>=MAX_ANALYTICS_CONVERSATIONS){partial=true;break;}
            chunkStart=chunkEnd;
          }
          conversations=[...unique.values()].filter(conversation=>{const start=Date.parse(conversation.conversationStart);return start>=from&&start<to;});
          totalHits=partial?null:conversations.length;
        }
        }
      }
      if(selectedGroupMembers)conversations=conversations.filter(conversation=>(conversation?.participants||[]).some((participant:any)=>selectedGroupMembers!.has(participantUserLookupId(participant))));
      // Apply ANI/DNIS only after paging the entire Analytics query, otherwise
      // matching conversations beyond the first page would be silently lost.
      if(input.phone || input.dnis) conversations=conversations.filter(conversation=>matchesPhone(conversation,input));
    }
    conversations.sort((a,b)=>Date.parse(b.conversationStart||'')-Date.parse(a.conversationStart||''));
    const clientUserNames=new Map<string,string>();
    const enriched = await mapWithConcurrency(conversations,5,async c => {
        let recordings: any[] = [],recordingListAvailable=true;
      const users:Record<string,string>={};
      for(const participant of c.participants||[]){
        const participantName=typeof participant?.participantName==='string'?participant.participantName:'';
        const userId=typeof participant?.userId==='string'?participant.userId:'';
        const isAgent=String(participant?.purpose||'').toLowerCase()==='agent';
        const unknownName=isAgent&&(!participantName||/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(participantName));
        const lookupId=participantUserLookupId(participant)||(isAgent&&unknownName?participantName:'');
        if(client&&lookupId){
          let name=clientUserNames.get(lookupId);
          if(name===undefined){
            try{const user=await client.get<any>(`/api/v2/users/${encodeURIComponent(lookupId)}`);name=typeof user?.name==='string'?user.name.trim():[user?.firstName,user?.lastName].filter(Boolean).join(' ').trim();}
            catch(error){if(error instanceof GenesysError&&[403,404].includes(error.status))name='';else throw error;}
            clientUserNames.set(lookupId,name||'');
          }
          if(name)users[lookupId]=name;
          if(unknownName&&name)users[participantName]=name;
          if(unknownName&&name)users[participantName]=name;
        }
      }
      try {
        if(client) recordings = listPlayableRecordings(await listConversationRecordings(client,c.conversationId),c);
        else recordings = ((MOCK_RECORDINGS[c.conversationId] as any[]) || []).filter(recording => isVoiceRecording(recording,c));
      } catch (error) { if(error instanceof GenesysError && (error.status === 404 || error.status === 403)){recordingListAvailable=false;recordings=[];} else throw error; }
        const summary=summarizeConversation(c,users);
        if(selectedAgent&&!summary.agents.some((name:string)=>name.toLocaleLowerCase()===selectedAgent!.name.toLocaleLowerCase()))summary.agents.push(selectedAgent.name);
        if(selectedQueue&&!summary.queues.some((name:string)=>name.toLocaleLowerCase()===selectedQueue!.name.toLocaleLowerCase()))summary.queues.push(selectedQueue.name);
       return { ...summary, recordingCount:recordings.length, recordingListAvailable, recordings:recordings.map(recording=>safeRecording(recording,c)) };
    });
    const enrichedWithPlayability=withRecordingsPlayability(input.connectionId,enriched.map((result:any)=>({conversationId:result.conversationId,recordings:result.recordings})),input.showUnplayable);
    const enrichedWithMarks=enriched.map((result:any,index:number)=>({...result,recordings:enrichedWithPlayability[index].recordings,recordingCount:enrichedWithPlayability[index].recordings.length}));
    const recordingListsIncomplete=enriched.some(result=>!result.recordingListAvailable);
    partial||=recordingListsIncomplete;
      const matchesRecordingFilter=(result:any)=>result.recordingCount>0;
    const normalized=(value:string)=>value.trim().toLocaleLowerCase();
    const visibleResults=enrichedWithMarks.filter((result,index)=>matchesRecordingFilter(result)&&(!input.agentName||result.agents.some((name:string)=>normalized(name)===normalized(input.agentName!)))&&(!input.queueName||result.queues.some((name:string)=>normalized(name)===normalized(input.queueName!)))&&(!input.phone||phoneSearchMatches(result.ani,input.phone)||phoneSearchMatches(result.callbackNumber,input.phone)||conversationHasPhoneMatch(conversations[index],input.phone,'phone'))&&(!input.dnis||phoneSearchMatches(result.dnis,input.dnis)||conversationHasPhoneMatch(conversations[index],input.dnis,'dnis')));
    totalHits=partial?null:visibleResults.length;
    const pageStart=(input.pageNumber-1)*input.pageSize;
    const pageResults=visibleResults.slice(pageStart,pageStart+input.pageSize);
    audit(req,'SEARCH','SUCCESS',connection?.id || 'mock',undefined,undefined,{page:input.pageNumber,voiceRecordingOnly:true,conversationsScanned:conversations.length,recordingsFound:visibleResults.reduce((count,result)=>count+result.recordingCount,0),partial});
     const scopeNote=recordingListsIncomplete?'Genesys did not return recording metadata for some conversations (404 or permission denied). Only verified voice and screen recordings are shown; results may be incomplete.':partial?'Results were capped at 1,000 conversations or an Analytics page could not be verified; narrow the time range to confirm completeness.':'Only voice interactions are searched; verified voice and associated screen recordings are shown. Message recordings and non-voice interactions are excluded.';
    res.json({ results:pageResults, page:input.pageNumber,pageSize:input.pageSize,totalHits,partial,scope:scopeNote, mock:!client });
  } catch(error) { audit(req,'SEARCH','FAILED'); next(error); }
});
app.get('/api/recordings/conversations/:conversationId', requireAuth, requireRecordingSearch, async (req,res,next) => {
   try { const conversationId=String(req.params.conversationId);if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');if(String(req.query.connectionId||'')==='mock'&&process.env.MOCK_MODE==='true'){const mock=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId);return mock?res.json({...withParticipantLines(mock),queues:conversationQueueNames(mock),wrapUpCodes:conversationWrapUpCodeNames(mock),wrapUpNotes:collectAfterCallNotes(mock)}):res.status(404).json({error:'Conversation not found.'});}const connectionId=String(req.query.connectionId||'');let connection:Connection;if(connectionId.startsWith('s3:')){const source=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(connectionId.slice(3)) as S3SourceRow|undefined;if(!source||!canUseS3Source(source,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');connection=connectionById(source.genesys_connection_id||'',req.session.user!.id,req.session.user!.role);}else connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role);const client=new GenesysClient(connection),conversation=await getCachedGenesysConversation(client,connection.id,conversationId),mapped=await mapWrapUpNames(client,conversation);const queueNames=await mapConversationQueueNames(client,mapped),named=await mapParticipantUserNames(client,mapped),display=withParticipantLines(named);audit(req,'DETAILS_VIEW','SUCCESS',connectionId||connection.id,conversationId);res.json({...redactSensitiveMetadata(display),queues:conversationQueueNames(named,queueNames),wrapUpCodes:conversationWrapUpCodeNames(mapped),wrapUpNotes:collectAfterCallNotes(mapped)}); }
  catch(error) { next(error); }
});
 app.get('/api/recordings/conversations/:conversationId/recordings', requireAuth, requireRealtimePlayback, async (req,res,next) => {
  try {
    const id=String(req.query.connectionId||''),conversationId=String(req.params.conversationId);
     const showUnplayable=String(req.query.showUnplayable||'false')==='true';
     if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');
      if(id.startsWith('s3:'))return res.json([]);
    if(id==='mock'&&process.env.MOCK_MODE==='true'){
      const conversation=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId);
       const recordings=((MOCK_RECORDINGS[conversationId]||[]) as any[]).filter(recording=>isVoiceRecording(recording,conversation)).map(recording=>safeRecording(recording,conversation));
      return res.json(withRecordingsPlayability(id,[{conversationId,recordings}],showUnplayable)[0].recordings);
    }
     const connection=connectionById(id,req.session.user!.id,req.session.user!.role),client=new GenesysClient(connection);
    const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);
      const allItems=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation),playability=withRecordingsPlayability(id,[{conversationId,recordings:allItems.map((item:any)=>({id:String(item.id||item.recordingId)})) as any[]}],true)[0].recordings,unplayableIds=new Set(playability.filter((item:any)=>item.unplayable).map((item:any)=>item.id)),items=allItems.filter((item:any)=>showUnplayable||!unplayableIds.has(String(item.id||item.recordingId)));
    const enriched=await mapWithConcurrency(items,4,async recording=>{
      const recordingId=recording.id||recording.recordingId;
      if(!recordingId)return safeRecording(recording,conversation);
      try{return safeRecording({...recording,...await client.get<any>(recordingMediaRequestPath(conversationId,recordingId))},conversation);}
      catch(error){if(error instanceof GenesysError&&error.status===429)throw error;return safeRecording(recording,conversation);}
    });
    res.json(withRecordingsPlayability(id,[{conversationId,recordings:enriched}],showUnplayable)[0].recordings);
  }catch(error){next(error);}
});
app.get('/api/recordings/:recordingId/metadata', requireAuth, requireRealtimePlayback, async (req,res,next) => {
        try { const cId=String(req.query.connectionId||''), conversationId=String(req.query.conversationId||''),recordingId=String(req.params.recordingId);if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.'); if(cId==='mock'&&process.env.MOCK_MODE==='true') { const conversation=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId),r=((MOCK_RECORDINGS[conversationId] as any[])||[]).find(recording=>recording.id===recordingId&&isVoiceRecording(recording,conversation)); return r?res.json(withRecordingsPlayability(cId,[{conversationId,recordings:[safeRecording(r,conversation)]}],true)[0].recordings[0]):res.status(404).json({error:'Voice recording not found.'}); } const c=connectionById(cId,req.session.user!.id,req.session.user!.role),client=new GenesysClient(c),conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);const items=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation);if(!items.some(item=>String(item.id||item.recordingId)===recordingId))throw httpError(404,'Recording not found.');const item=await client.get<any>(recordingMediaRequestPath(conversationId,recordingId));if(!item)throw httpError(409,'Genesys did not return recording metadata.');if(!listPlayableRecordings([{...items.find(metadata=>String(metadata.id||metadata.recordingId)===recordingId),...item}],conversation).length)throw httpError(404,'Recording not found.');audit(req,'RECORDING_METADATA_VIEW','SUCCESS',c.id,conversationId,recordingId); res.json(withRecordingsPlayability(cId,[{conversationId,recordings:[safeRecording({...items.find(metadata=>String(metadata.id||metadata.recordingId)===recordingId),...item},conversation)]}],true)[0].recordings[0]); }
  catch(error) { next(error); }
  });
app.put('/api/recordings/playability',requireAuth,requirePlayabilityAccess,requireCsrf,async(req,res,next)=>{
  try{
    const input=playabilitySchema.parse(req.body),user=req.session.user!;
    if(input.archiveId){
      const row=archivedRecordingById(input.archiveId||'');
      if(!row||row.connection_id!==input.connectionId||row.conversation_id!==input.conversationId||row.recording_id!==input.recordingId)throw httpError(404,'Archived recording not found.');
      if(!hasAccessPermission(user.role,'libraryPlayback')&&!hasAccessPermission(user.role,'libraryAdmin'))throw httpError(403,'Library Playback permission is required to update archived recordings.');
      if(!canAccessArchived(req,row))throw httpError(403,'You cannot access this archived recording.');
    }else if(!canUseRecordingSearch(user.role))throw httpError(403,'Realtime Playback permission is required to mark Genesys recordings.');
    else if(input.connectionId==='mock'&&process.env.MOCK_MODE==='true'){
      const conversation=MOCK_CONVERSATIONS.find(item=>item.conversationId===input.conversationId);
      if(!conversation||!((MOCK_RECORDINGS[input.conversationId]||[]) as any[]).some(recording=>recording.id===input.recordingId&&isVoiceRecording(recording,conversation)))throw httpError(404,'Voice recording not found.');
    }else{
      const connection=connectionById(input.connectionId,user.id,user.role),client=new GenesysClient(connection),conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(input.conversationId)}/details`),recordings=await listVoiceRecordings(client,input.conversationId,conversation);
      if(!recordings.some(item=>String(item.id||item.recordingId)===input.recordingId))throw httpError(404,'Voice recording not found.');
    }
    setRecordingUnplayable(input,input.unplayable,user.id);
    audit(req,'RECORDING_PLAYABILITY_UPDATE','SUCCESS',input.connectionId,input.conversationId,input.recordingId,{unplayable:input.unplayable,source:input.source,archiveId:input.archiveId||null});
    res.json({connectionId:input.connectionId,conversationId:input.conversationId,recordingId:input.recordingId,unplayable:input.unplayable});
  }catch(error){next(error);}
});
app.get('/api/recordings/conversations/:conversationId/summaries', requireAuth, requireRealtimePlayback, async (req,res,next) => {
  try {
    const conversationId=String(req.params.conversationId||''),connectionId=String(req.query.connectionId||'');
    if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');
    if(connectionId==='mock'&&process.env.MOCK_MODE==='true')throw httpError(501,'Synthetic Mock Mode does not include live Genesys summaries.');
    const connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role),client=new GenesysClient(connection);
    const summaries=await fetchConversationSummaryArtifacts(client,conversationId);
    audit(req,'CONVERSATION_SUMMARY_VIEW','SUCCESS',connection.id,conversationId);
    res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');
    res.json({conversationId,avaSummary:redactSensitiveMetadata(summaries.avaSummary),aiSummary:redactSensitiveMetadata(summaries.aiSummary)});
  } catch(error) { next(error); }
});
app.get('/api/recordings/conversations/:conversationId/transcription', requireAuth, requireRealtimePlayback, async (req,res,next) => {
  try {
    const conversationId=String(req.params.conversationId||''),connectionId=String(req.query.connectionId||'');
    if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');
    if(connectionId==='mock'&&process.env.MOCK_MODE==='true')throw httpError(501,'Synthetic Mock Mode does not include transcription data.');
    const connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role),client=new GenesysClient(connection);
    const conversation=await client.get<any>(analyticsConversationDetailsPath(conversationId));
    const transcripts=await fetchConversationTranscriptions(client,connection,conversationId,conversation);
    if(!transcripts.length)throw httpError(404,'Genesys has no transcription available for this conversation. Check that transcription is enabled and the service account has Speech and Text Analytics permissions.');
    const available=transcripts.map(item=>({...item,transcript:redactSensitiveMetadata(item.transcript)}));
    if(!available.length)throw httpError(404,'Genesys has no transcription available for this conversation. Check that transcription is enabled and the service account has Speech and Text Analytics permissions.');
    audit(req,'TRANSCRIPTION_DOWNLOAD','SUCCESS',connection.id,conversationId);
    res.setHeader('Content-Type','application/json; charset=utf-8');
    res.setHeader('Content-Disposition',`attachment; filename="transcription-${conversationId.replace(/[^a-zA-Z0-9_-]/g,'_')}.json"`);
    res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.json({conversationId,generatedAt:new Date().toISOString(),transcriptions:available});
  } catch(error) {
    const normalized=normalizeTranscriptionError(error),status=Number((normalized as {status?:unknown}|null)?.status)||500;
    if(status>=500&&status!==501)console.error('Transcription request failed:',error);
    next(normalized);
  }
});
app.get('/api/recordings/:recordingId/stream', requireAuth, requirePlaybackSourceAccess, async (req,res,next) => {
  let playbackConnection:Connection|undefined;
   try {
     const cId=String(req.query.connectionId||''), conversationId=String(req.query.conversationId||'');
     if(!conversationId||conversationId.length>128||String(req.params.recordingId).length>128)throw httpError(400,'Valid conversation and recording IDs are required.');
     if(cId==='mock'&&process.env.MOCK_MODE==='true') return res.status(501).json({error:'Synthetic demo recordings include metadata only; real audio playback requires an authorized Genesys recording.'});
       if(cId.startsWith('s3:')){const sourceId=cId.slice(3),sourceRow=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(sourceId) as S3SourceRow|undefined;if(!sourceRow||!canUseS3Source(sourceRow,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');const metadataKey=String(req.query.metadataKey||'');if(!metadataKey||metadataKey.length>2048)throw httpError(400,'A valid AWS recording metadata reference is required.');const config=decryptS3Source(sourceRow),resolved=await resolveAuthorizedS3Recording(sourceRow,config,metadataKey,conversationId,String(req.params.recordingId),req.session.user!.id,req.session.user!.role);if(resolved.mediaType==='screen')throw httpError(409,'This is a screen recording. Use the secure screen playback route.');const media=await getS3RecordingAudio(config,resolved.audioKey,typeof req.headers.range==='string'?req.headers.range:undefined);if('invalidRange'in media){res.setHeader('Content-Range',`bytes */${media.contentLength}`);res.setHeader('Accept-Ranges','bytes');return res.status(416).end();}const extension=resolved.audioKey.split('.').pop()?.toLowerCase(),sourceMimeType=media.contentType==='application/octet-stream'?(extension==='opus'?'audio/ogg':extension==='ogg'?'audio/ogg':extension==='wav'?'audio/wav':extension==='mp3'?'audio/mpeg':extension==='zip'?'application/zip':media.contentType):media.contentType;if(isZipMediaContentType(sourceMimeType)){try{const zip=await readAwsS3Body(media.body as AsyncIterable<Uint8Array>,128*1024*1024),audio=extractSingleAudioFromZip(zip);media.close();const converted=await convertAudio(audio.audio,'ogg_opus',Number(resolved.metadata.durationMs)||undefined);serveAudioBuffer(req,res,converted.bytes,converted.mimeType);}catch(error){media.close();throw error instanceof Error&&Number((error as {status?:number}).status)>=400?error:httpError(409,error instanceof Error?error.message:'AWS S3 ZIP does not contain supported voice audio.');}}else if(sourceMimeType.startsWith('video/')){media.close();throw httpError(502,'AWS S3 returned video media instead of voice audio.');}else if(['audio/ogg','audio/wav','audio/mpeg'].includes(sourceMimeType)){res.status(media.status);res.setHeader('Content-Type',sourceMimeType);res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Accept-Ranges',media.acceptRanges);if(media.range)res.setHeader('Content-Range',media.range);if(media.contentLength!==undefined)res.setHeader('Content-Length',String(media.contentLength));const stream=Readable.from(media.body as AsyncIterable<Uint8Array>);stream.once('end',media.close);stream.once('error',media.close);res.once('close',media.close);stream.pipe(res);}else{try{const audio=await readAwsS3Body(media.body as AsyncIterable<Uint8Array>,256*1024*1024);media.close();const converted=await convertAudio(audio,'ogg_opus',Number(resolved.metadata.durationMs)||undefined);serveAudioBuffer(req,res,converted.bytes,converted.mimeType);}catch(error){media.close();throw error;}}audit(req,'PLAYBACK','SUCCESS',cId,conversationId,String(req.params.recordingId));return;}
      const c=connectionById(cId,req.session.user!.id,req.session.user!.role);playbackConnection=c; const client=new GenesysClient(c);
      const recordingId=String(req.params.recordingId),conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);
      const eligibleRecordings=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation);
      if(!eligibleRecordings.some(item=>String(item.id||item.recordingId)===recordingId))throw httpError(404,'Recording not found.');
      const playable=await getRecordingMedia(client,conversationId,recordingId);
      if(!playable) throw httpError(409,'Genesys has not made playable media available yet. Confirm the recording is finalized and that the service account has permission to download recordings in the conversation’s division; then retry.');
      const isScreen=isScreenRecording(playable.metadata)||eligibleRecordings.some(item=>String(item.id||item.recordingId)===recordingId&&isScreenRecording(item));
      if(isScreen){const tracks=await fetchGenesysScreenTracks(client,c,conversationId,recordingId);if(!tracks.length)throw httpError(409,'Genesys did not return screen video tracks.');const scope=[req.session.user!.id,cId,conversationId].join(':'),cacheId=cacheScreenTracks(scope,tracks.map(track=>({...track,id:`${recordingId}-${track.id}`})));if(!cacheId)throw httpError(413,'Screen recording cannot be cached safely for playback.');const saved=getCachedScreenTrack(cacheId,scope,`${recordingId}-${tracks[0].id}`);if(!saved)throw httpError(500,'Screen media cache could not be created.');res.setHeader('Cache-Control','private, no-store');res.redirect(307,`/api/recordings/conversations/${encodeURIComponent(conversationId)}/screens/${encodeURIComponent(saved.id)}/stream?connectionId=${encodeURIComponent(cId)}&cacheId=${encodeURIComponent(cacheId)}`);audit(req,'SCREEN_PLAYBACK','SUCCESS',c.id,conversationId,recordingId,{monitorCount:tracks.length});return;}
      if(!isVoiceRecording(playable.metadata,conversation)&&!eligibleRecordings.some(item=>String(item.id||item.recordingId)===recordingId&&isVoiceRecording(item,conversation)))throw httpError(409,'Only voice and verified screen recordings can be played.');
    const uri=playable.mediaUri;
    const headers: Record<string,string>={}; if(req.headers.range) headers.Range=req.headers.range;
    let media=await fetchTrustedMedia(uri,c,headers);
    if(isZipMediaContentType(media.headers.get('content-type'))){
      await media.body?.cancel().catch(()=>{});
      media=await fetchTrustedMedia(uri,c,{});
      const zip=await readBoundedBody(media,128*1024*1024);
      let playableAudio:{audio:Buffer;mimeType:string;filename:string};
      try { playableAudio=extractSingleAudioFromZip(zip); }
      catch(error) { throw httpError(409,error instanceof Error?error.message:'Genesys ZIP archive does not contain playable audio.'); }
      serveAudioBuffer(req,res,playableAudio.audio,playableAudio.mimeType);
    } else {
      if(isMessageRecording(playable.metadata)){await media.body?.cancel().catch(()=>{});throw httpError(409,'This is a Genesys message recording (not voice audio), so it cannot play in the audio player. Use Download to retrieve the message archive.');}
      await pipeMedia(req,res,media);
    }
    audit(req,'PLAYBACK','SUCCESS',c.id,conversationId,recordingId);
  } catch(error) { if(!res.headersSent){audit(req,'PLAYBACK','FAILED',playbackConnection?.id,String(req.query.conversationId||''),String(req.params.recordingId||''));next(error);} }
});
 app.get('/api/recordings/conversations/:conversationId/screens',requireAuth,requireRealtimePlayback,async(req,res,next)=>{
  let client:GenesysClient|undefined;
  try{
    const connectionId=String(req.query.connectionId||''),conversationId=String(req.params.conversationId||'');
    if(!connectionId||!conversationId||conversationId.length>128)throw httpError(400,'A valid connection and conversation ID are required.');
    let tracks:{id:string;name:string;bytes:Buffer;mimeType:'video/webm'}[]=[],audioMetadataKey:string|undefined,sourceRow:S3SourceRow|undefined;
    if(connectionId.startsWith('s3:')){
      sourceRow=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(connectionId.slice(3)) as S3SourceRow|undefined;
      if(!sourceRow||!canUseS3Source(sourceRow,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');
      const metadataKey=String(req.query.metadataKey||''),recordingId=String(req.query.recordingId||'');
      if(!metadataKey||metadataKey.length>2048)throw httpError(400,'A valid AWS recording metadata reference is required.');
      if(!recordingId||recordingId.length>128)throw httpError(400,'A valid screen recording ID is required.');
      const associated=await resolveAuthorizedS3Recording(sourceRow,decryptS3Source(sourceRow),metadataKey,conversationId,recordingId,req.session.user!.id,req.session.user!.role);
      if(associated.mediaType!=='screen')throw httpError(404,'Screen recording not found.');
      const voice=associated.genesysRecordings.find(item=>!isScreenRecording(item));
      if(voice)audioMetadataKey=await findS3RecordingMetadataKey(decryptS3Source(sourceRow),conversationId,String(voice.id||voice.recordingId),metadataKey);
      const media=await getS3RecordingAudio(decryptS3Source(sourceRow),associated.audioKey);
      if('invalidRange'in media)throw httpError(416,'Screen recording range is invalid.');
      let bytes:Buffer;try{bytes=await readAwsS3Body(media.body as AsyncIterable<Uint8Array>,128*1024*1024);}finally{media.close();}
      tracks=tracksFromBytes(bytes,associated.audioKey.split('/').pop()||recordingId);
    }else{
      const connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role);client=new GenesysClient(connection);
      const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`),items=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation),screens=items.filter(isScreenRecording),byRecording=await mapWithConcurrency(screens,2,async item=>{const recordingId=String(item.id||item.recordingId),screenTracks=await fetchGenesysScreenTracks(client!,connection,conversationId,recordingId);return screenTracks.map(track=>({...track,id:`${recordingId}-${track.id}`}));});tracks=byRecording.flat();
    }
    const genesys=connectionById(sourceRow?.genesys_connection_id||connectionId,req.session.user!.id,req.session.user!.role);client=client||new GenesysClient(genesys);
    const conversation=await getCachedGenesysConversation(client,genesys.id,conversationId),items=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation),voice=items.find(item=>!isScreenRecording(item)&&(!sourceRow||audioMetadataKey));
    const audioRecordingId=voice?String(voice.id||voice.recordingId):undefined;
    if(!tracks.length){res.setHeader('Cache-Control','private, no-store');return res.json({tracks:[],audioRecordingId,audioMetadataKey});}
    const scope=[req.session.user!.id,connectionId,conversationId].join(':'),cacheId=cacheScreenTracks(scope,tracks);
    if(!cacheId)throw httpError(413,'Screen recordings cannot be cached safely for playback.');
    audit(req,'SCREEN_PLAYBACK','SUCCESS',connectionId,conversationId,undefined,{monitorCount:tracks.length,genesysConnectionId:genesys.id});
    res.setHeader('Cache-Control','private, no-store');
    res.json({audioRecordingId,audioMetadataKey,tracks:tracks.map(track=>({id:track.id,name:track.name,mimeType:track.mimeType,url:`/api/recordings/conversations/${encodeURIComponent(conversationId)}/screens/${encodeURIComponent(track.id)}/stream?connectionId=${encodeURIComponent(connectionId)}&cacheId=${encodeURIComponent(cacheId)}`}))});
  }catch(error){next(error);}finally{client?.clearCachedToken();}
});
app.get('/api/recordings/conversations/:conversationId/screens/:trackId/stream',requireAuth,requireRealtimePlayback,async(req,res,next)=>{
   try{const connectionId=String(req.query.connectionId||''),conversationId=String(req.params.conversationId||'');if(connectionId.startsWith('s3:')){const source=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(connectionId.slice(3)) as S3SourceRow|undefined;if(!source||!canUseS3Source(source,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');connectionById(source.genesys_connection_id||'',req.session.user!.id,req.session.user!.role);}else connectionById(connectionId,req.session.user!.id,req.session.user!.role);const scope=[req.session.user!.id,connectionId,conversationId].join(':'),track=getCachedScreenTrack(String(req.query.cacheId||''),scope,String(req.params.trackId));if(!track)throw httpError(404,'Screen media session expired. Reopen playback to load this monitor.');audit(req,'SCREEN_PLAYBACK','SUCCESS',connectionId,conversationId,undefined,{trackId:track.id});serveAudioBuffer(req,res,track.bytes,track.mimeType);}catch(error){next(error);}
});
app.get('/api/recordings/conversations/:conversationId/voice/:recordingId/stream',requireAuth,requireRealtimePlayback,async(req,res,next)=>{
  let connection:Connection|undefined;
  try{const connectionId=String(req.query.connectionId||''),conversationId=String(req.params.conversationId||''),recordingId=String(req.params.recordingId||'');if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.');if(connectionId.startsWith('s3:'))throw httpError(409,'AWS S3 voice media must use its source recording playback URL.');connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role);const client=new GenesysClient(connection),conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`),recordings=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation),recording=recordings.find(item=>String(item.id||item.recordingId)===recordingId);if(!recording||isScreenRecording(recording))throw httpError(404,'Associated voice recording not found.');const playable=await getRecordingMedia(client,conversationId,recordingId);if(!playable||!isVoiceRecording(playable.metadata,conversation)&&!isVoiceRecording(recording,conversation))throw httpError(409,'Associated voice recording is not playable.');const media=await fetchTrustedMedia(playable.mediaUri,connection,req.headers.range?{Range:req.headers.range}:{});if(isZipMediaContentType(media.headers.get('content-type'))){await media.body?.cancel().catch(()=>{});const full=await fetchTrustedMedia(playable.mediaUri,connection,{}),zip=await readBoundedBody(full,128*1024*1024),audio=extractSingleAudioFromZip(zip);serveAudioBuffer(req,res,audio.audio,audio.mimeType);}else await pipeMedia(req,res,media);audit(req,'PLAYBACK','SUCCESS',connection.id,conversationId,recordingId);}catch(error){next(error);}
});
app.get('/api/playback-history',requireAuth,(req,res)=>{
  const user=req.session.user!,page=Math.max(1,Number.parseInt(String(req.query.page||'1'),10)||1),pageSize=15;
  const administrator=user.role==='administrator';
   const where=administrator?"a.action IN ('PLAYBACK','SCREEN_PLAYBACK','LIBRARY_PLAYBACK')":"a.user_id=? AND a.action IN ('PLAYBACK','SCREEN_PLAYBACK','LIBRARY_PLAYBACK')";
  const scopeValues:unknown[]=administrator?[]:[user.id];
  const total=Number((db.prepare(`SELECT COUNT(*) AS n FROM audit_logs a WHERE ${where}`).get(...scopeValues) as {n:number}).n);
  const pages=Math.max(1,Math.ceil(total/pageSize)),safePage=Math.min(page,pages);
  const logs=db.prepare(`SELECT a.id,a.action,a.result,a.connection_id AS connectionId,COALESCE(c.name,a.connection_id,'—') AS connectionName,a.username AS playedBy,a.conversation_id AS conversationId,a.recording_id AS recordingId,a.created_at AS createdAt FROM audit_logs a LEFT JOIN connections c ON c.id=a.connection_id WHERE ${where} ORDER BY a.created_at DESC,a.id DESC LIMIT ? OFFSET ?`).all(...scopeValues,pageSize,(safePage-1)*pageSize);
  res.json({items:logs,total,page:safePage,pageSize,totalPages:pages});
});
app.get('/api/recordings/:recordingId/download', requireAuth, requireDownloadSourceAccess, async (req,res,next) => {
  let connection:Connection|undefined,conversationId='',recordingId='';
    try { conversationId=String(req.query.conversationId||'');recordingId=String(req.params.recordingId);if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.');const sourceId=String(req.query.connectionId||'');if(sourceId.startsWith('s3:')){const id=sourceId.slice(3),sourceRow=db.prepare('SELECT * FROM s3_sources WHERE id=? AND enabled=1').get(id) as S3SourceRow|undefined;if(!sourceRow||!hasS3SourceGrant(sourceRow,req.session.user!.id,req.session.user!.role))throw httpError(404,'AWS S3 source not found or access denied.');const metadataKey=String(req.query.metadataKey||'');if(!metadataKey||metadataKey.length>2048)throw httpError(400,'A valid AWS recording metadata reference is required.');const config=decryptS3Source(sourceRow),resolved=await resolveAuthorizedS3Recording(sourceRow,config,metadataKey,conversationId,recordingId,req.session.user!.id,req.session.user!.role,'download');if(resolved.mediaType==='screen'){const screenMedia=await getS3RecordingAudio(config,resolved.audioKey);if('invalidRange'in screenMedia)throw httpError(416,'Screen recording range is invalid.');let screenBytes:Buffer;try{screenBytes=await readAwsS3Body(screenMedia.body as AsyncIterable<Uint8Array>,128*1024*1024);}finally{screenMedia.close();}tracksFromBytes(screenBytes,path.basename(resolved.audioKey));const screenZip=resolved.audioKey.toLowerCase().endsWith('.zip')||screenBytes.subarray(0,2).equals(Buffer.from([0x50,0x4b]));res.setHeader('Content-Type',screenZip?'application/zip':'video/webm');res.setHeader('Content-Disposition',`attachment; filename="recording-${recordingId.replace(/[^a-zA-Z0-9_-]/g,'_')}.${screenZip?'zip':'webm'}"`);res.setHeader('Content-Length',String(screenBytes.length));res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('X-Content-Type-Options','nosniff');res.status(200).end(screenBytes);audit(req,'DOWNLOAD','SUCCESS',sourceId,conversationId,recordingId,{sourceType:'aws-s3',mediaType:'screen'});return;}const media=await getS3RecordingAudio(config,resolved.audioKey);if('invalidRange'in media)throw httpError(416,'Recording range is invalid.');const extension=resolved.audioKey.split('.').pop()?.toLowerCase()||'opus';let body:Buffer,sourceMimeType:string;try{body=await readAwsS3Body(media.body as AsyncIterable<Uint8Array>,256*1024*1024);sourceMimeType=media.contentType==='application/octet-stream'?(extension==='opus'?'audio/ogg':extension==='ogg'?'audio/ogg':extension==='wav'?'audio/wav':extension==='mp3'?'audio/mpeg':extension==='zip'?'application/zip':'application/octet-stream'):media.contentType;if(sourceMimeType.startsWith('video/'))throw httpError(502,'AWS S3 returned video media instead of voice audio.');if(isZipMediaContentType(sourceMimeType))body=extractSingleAudioFromZip(body).audio;}finally{media.close();}const outputFormat=getRecordingOutputFormat(),converted=await convertAudio(body!,outputFormat,resolved.durationMs||undefined);res.setHeader('Content-Type',converted.mimeType);res.setHeader('Content-Disposition',`attachment; filename="recording-${recordingId.replace(/[^a-zA-Z0-9_-]/g,'_')}.${converted.extension}"`);res.setHeader('Content-Length',String(converted.bytes.length));res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('X-Content-Type-Options','nosniff');res.status(200).end(converted.bytes);audit(req,'DOWNLOAD','SUCCESS',sourceId,conversationId,recordingId,{sourceType:'aws-s3',format:outputFormat,sourceMimeType});return;}connection=connectionById(sourceId,req.session.user!.id,req.session.user!.role);const client=new GenesysClient(connection),conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`),voiceRecordings=await listVoiceRecordings(client,conversationId,conversation);if(!voiceRecordings.some(item=>String(item.id||item.recordingId)===recordingId))throw httpError(404,'Voice recording not found.');const outputFormat=getRecordingOutputFormat(),inputFormat=preferredGenesysInputFormat(outputFormat),playable=await getRecordingMedia(client,conversationId,recordingId,undefined,inputFormat);if(!playable)throw httpError(409,'Genesys has not made downloadable media available yet. Confirm the recording is finalized and that the service account has permission to download recordings in the conversation’s division; then retry.');if(!isVoiceRecording(playable.metadata,conversation)&&!voiceRecordings.some(item=>String(item.id||item.recordingId)===recordingId&&isVoiceRecording(item,conversation)))throw httpError(409,'Only voice recordings can be downloaded.');if(isMessageRecording(playable.metadata))throw httpError(409,'Only voice recordings can be downloaded as audio.');const response=await fetchTrustedMedia(playable.mediaUri,connection,{});const sourceMimeType=(response.headers.get('content-type')||'application/octet-stream').split(';')[0].toLowerCase();const source=await readBoundedBody(response,256*1024*1024);let audio=source;if(isZipMediaContentType(sourceMimeType)){try{audio=extractSingleAudioFromZip(source).audio;}catch(error){throw httpError(409,error instanceof Error?error.message:'Genesys ZIP archive does not contain playable voice audio.');}}else {const metadataFormat=playable.metadata?.mediaFormat||playable.metadata?.formatId;if(metadataFormat&&genesysMediaFormatKey(metadataFormat)!==genesysMediaFormatKey(inputFormat))throw httpError(502,'Genesys returned an unexpected media format.');if(sourceMimeType.startsWith('video/'))throw httpError(502,'Genesys returned a video stream instead of audio. Retry the download or contact an administrator.');}const expectedDurationMs=Number(voiceRecordings.find(item=>String(item.id||item.recordingId)===recordingId)?.durationMs||0)||Math.max(0,Date.parse(conversation.conversationEnd||'')-Date.parse(conversation.conversationStart||''))||undefined;const converted=await convertAudio(audio,outputFormat,expectedDurationMs);res.setHeader('Content-Type',converted.mimeType);res.setHeader('Content-Disposition',`attachment; filename="recording-${recordingId.replace(/[^a-zA-Z0-9_-]/g,'_')}.${converted.extension}"`);res.setHeader('Content-Length',String(converted.bytes.length));res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('X-Content-Type-Options','nosniff');res.status(200).end(converted.bytes);audit(req,'DOWNLOAD','SUCCESS',connection.id,conversationId,recordingId);}
   catch(error) { audit(req,'DOWNLOAD','FAILED',connection?.id,conversationId||undefined,recordingId||undefined);next(error); }
});
app.get('/api/dashboard/summary', requireAuth, requireRealtimePlayback, async (req,res,next) => {
  try {
    const connectionId=String(req.query.connectionId||''),startRaw=String(req.query.start||''),endRaw=String(req.query.end||'');
    const from=Date.parse(startRaw),to=Date.parse(endRaw);
    if(!connectionId||!Number.isFinite(from)||!Number.isFinite(to)||from>=to)throw httpError(400,'Choose an organization and a valid dashboard date range.');
    if(to-from>30*86400000)throw httpError(400,'Dashboard date range cannot exceed 30 days.');
    let conversations:any[]=[];
    let partial=false;
    let connection:Connection|undefined;
    let client:GenesysClient|undefined;
    if(connectionId==='mock'&&process.env.MOCK_MODE==='true'){
      conversations=MOCK_CONVERSATIONS.filter(item=>{const time=Date.parse(item.conversationStart);return time>=from&&time<to;});
    }else{
      connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role);
      client=new GenesysClient(connection);
      const unique=new Map<string,any>();
      for(let chunkStart=from;chunkStart<to;){
        const chunkEnd=Math.min(to,chunkStart+7*86400000);
        let pageNumber=1,totalHits:number|undefined;
        let chunkHits=0;
        while(pageNumber<=10&&unique.size<1000){
          const response=await client.post<{conversations?:any[];totalHits?:number;totalCount?:number}>('/api/v2/analytics/conversations/details/query',{
            interval:`${new Date(chunkStart).toISOString()}/${new Date(chunkEnd).toISOString()}`,
            paging:{pageSize:100,pageNumber},order:'desc',orderBy:'conversationStart',
          });
          const page=response.conversations||[];
          for(const conversation of page)if(conversation?.conversationId&&!unique.has(conversation.conversationId)){unique.set(conversation.conversationId,conversation);chunkHits++;}
          totalHits=response.totalHits??response.totalCount??totalHits;
          if(page.length<100||(totalHits!==undefined&&chunkHits>=totalHits))break;
          pageNumber++;
        }
        if(pageNumber>10||unique.size>=1000)partial=true;
        if(unique.size>=1000)break;
        chunkStart=chunkEnd;
      }
      conversations=[...unique.values()].filter(item=>{const time=Date.parse(item.conversationStart);return time>=from&&time<to;});
    }
    let recordingsKnown=true;
    const enriched=await mapWithConcurrency(conversations,5,async conversation=>{
       let recordingCount=((MOCK_RECORDINGS[conversation.conversationId] as any[]||[]).filter(isVoiceRecording)).length;
       if(client){
         try{recordingCount=(await listVoiceRecordings(client,conversation.conversationId,conversation)).length;}
        catch(error){if(error instanceof GenesysError&&error.status===404)recordingCount=0;else if(error instanceof GenesysError&&error.status===403){recordingsKnown=false;partial=true;recordingCount=0;}else throw error;}
      }
      return {conversation,recordingCount};
    });
    const counts=new Map<string,number>();
    let recordingsAvailable=0,recordedConversations=0,durationTotal=0,durationCount=0;
    for(const {conversation,recordingCount} of enriched){
      const day=String(conversation.conversationStart||'').slice(0,10);
      if(day)counts.set(day,(counts.get(day)||0)+1);
      recordingsAvailable+=recordingCount;
      if(recordingCount>0)recordedConversations++;
      const start=Date.parse(conversation.conversationStart),end=Date.parse(conversation.conversationEnd);
      if(Number.isFinite(start)&&Number.isFinite(end)&&end>=start){durationTotal+=(end-start)/1000;durationCount++;}
    }
    const days=Array.from({length:Math.ceil((to-from)/86400000)},(_,index)=>{
      const date=new Date(from+index*86400000).toISOString().slice(0,10);
      return {date,count:counts.get(date)||0};
    });
    audit(req,'DASHBOARD_VIEW','SUCCESS',connection?.id||'mock',undefined,undefined,{start:new Date(from).toISOString(),end:new Date(to).toISOString(),conversations:conversations.length,partial});
    res.json({available:true,partial,mock:!client,connectionId,start:new Date(from).toISOString(),end:new Date(to).toISOString(),metrics:{totalConversations:conversations.length,recordingsAvailable,recordingCoverage:recordingsKnown?(conversations.length?recordedConversations/conversations.length*100:0):null,averageDurationSeconds:durationCount?durationTotal/durationCount:null},interactionsByDay:days});
  }catch(error){next(error);}
});
 app.get('/api/audit', requireAuth, requireRole('administrator'), (req,res,next) => { try {const pageSizeRaw=Number(req.query.pageSize)||25;const pageSize=[25,50,100,200].includes(pageSizeRaw)?pageSizeRaw:25;const filters={username:String(req.query.username||'').trim().slice(0,128),action:String(req.query.action||'').trim().slice(0,80),result:String(req.query.result||'').trim().slice(0,16),from:String(req.query.from||'').trim(),to:String(req.query.to||'').trim(),query:String(req.query.query||'').trim().slice(0,128)};if(filters.result&&!['SUCCESS','FAILED','DENIED'].includes(filters.result))throw httpError(400,'Audit result filter is invalid.');const conditions:string[]=[],values:unknown[]=[];if(filters.username){conditions.push('username LIKE ?');values.push(`%${escapeLike(filters.username)}%`);}if(filters.action){conditions.push('action=?');values.push(filters.action);}if(filters.result){conditions.push('result=?');values.push(filters.result);}if(filters.from){const from=Date.parse(filters.from);if(!Number.isFinite(from))throw httpError(400,'Start date filter is invalid.');conditions.push('created_at>=?');values.push(new Date(from).toISOString());}if(filters.to){const to=Date.parse(filters.to);if(!Number.isFinite(to))throw httpError(400,'End date filter is invalid.');conditions.push('created_at<?');values.push(new Date(to+86400000).toISOString());}if(filters.query){const pattern=`%${escapeLike(filters.query)}%`;conditions.push('(username LIKE ? ESCAPE \'\\\' OR action LIKE ? ESCAPE \'\\\' OR connection_id LIKE ? ESCAPE \'\\\' OR conversation_id LIKE ? ESCAPE \'\\\' OR recording_id LIKE ? ESCAPE \'\\\' OR source_ip LIKE ? ESCAPE \'\\\')');values.push(pattern,pattern,pattern,pattern,pattern,pattern);}const where=conditions.length?`WHERE ${conditions.join(' AND ')}`:'';const total=Number((db.prepare(`SELECT COUNT(*) AS n FROM audit_logs ${where}`).get(...values) as {n:number}).n);const pages=Math.max(1,Math.ceil(total/pageSize));const page=Math.min(pages,Math.max(1,Number(req.query.page)||1));const logs=db.prepare(`SELECT id,username,action,result,connection_id AS connectionId,conversation_id AS conversationId,recording_id AS recordingId,source_ip AS sourceIp,created_at AS createdAt FROM audit_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...values,pageSize,(page-1)*pageSize);res.json({logs,page,pageSize,total,totalPages:pages,filters});}catch(error){next(error);} });
app.get('/api/admin/audit-retention',requireAuth,requireRole('administrator'),(_req,res)=>res.json({days:getAuditRetentionDays(),defaultDays:35}));
app.put('/api/admin/audit-retention',requireAuth,requireRole('administrator'),requireCsrf,(req,res,next)=>{try{const {days}=z.object({days:z.number().int().min(1).max(3650)}).parse(req.body);db.prepare(`INSERT INTO application_settings(key,value_json) VALUES('audit_retention_days',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json`).run(JSON.stringify(days));const deleted=purgeExpiredAuditLogs();audit(req,'AUDIT_RETENTION_UPDATE','SUCCESS',undefined,undefined,undefined,{days,deleted});res.json({days,deleted});}catch(error){next(error);}});
app.post('/api/audit/list-export',requireAuth,requireRole('administrator'),requireCsrf,(req,res,next)=>{try{const input=z.object({rows:z.number().int().min(0).max(200)}).parse(req.body);audit(req,'AUDIT_LOG_EXPORT','SUCCESS',undefined,undefined,undefined,{rows:input.rows});res.json({ok:true});}catch(error){next(error);}});
app.post('/api/audit/export',requireAuth,requireCsrf,(req,res,next)=>{try{const input=z.object({exportType:z.enum(['search-results','audit-log']),connectionId:z.string().optional(),rows:z.number().int().min(0).max(10000)}).parse(req.body);if(input.exportType==='audit-log'){if(req.session.user!.role!=='administrator')throw httpError(403,'Administrator role required to export audit logs.');}else{if(!hasAccessPermission(req.session.user!.role,'realtimePlayback'))throw httpError(403,'Realtime Playback permission is required to export search results.');if(!input.connectionId)throw httpError(400,'Connection is required for a search-result export.');if(input.connectionId!=='mock')connectionById(input.connectionId,req.session.user!.id,req.session.user!.role);}audit(req,input.exportType==='audit-log'?'AUDIT_LOG_EXPORT':'METADATA_EXPORT','SUCCESS',input.connectionId||undefined,undefined,undefined,{rows:input.rows,exportType:input.exportType});res.json({ok:true});}catch(error){next(error);}});

function bootstrapUser() {
  const username=process.env.INITIAL_ADMIN_USERNAME, password=process.env.INITIAL_ADMIN_PASSWORD;
  if(!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
    if(!username||!password) { if(process.env.NODE_ENV==='production') throw new Error('Set INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD for first production startup.'); return; }
    if(!isPasswordPolicySatisfied(password)) throw new Error('INITIAL_ADMIN_PASSWORD must be at least 8 characters and include a letter plus a number or special character.');
    const normalized=username.trim();if(!/^[\p{L}\p{N}._@-]{2,128}$/u.test(normalized))throw new Error('INITIAL_ADMIN_USERNAME contains unsupported characters.');
    db.prepare('INSERT INTO users(id,username,password_hash,role,access_role_id,created_at) VALUES(?,?,?,?,?,?)').run(crypto.randomUUID(),normalized,bcrypt.hashSync(password,12),'administrator','administrator',new Date().toISOString());
    console.warn(`Initial administrator "${username}" created. Change the password after first login.`);
  }
  delete process.env.INITIAL_ADMIN_PASSWORD;
}
function awaitHash(password:string){return bcrypt.hashSync(password,12);}
const emptyProfile={email:'',phone:'',firstName:'',lastName:'',nickname:'',jobTitle:'',division:'',department:''};
const profileSchema=z.object({email:z.string().trim().max(320).refine(value=>!value||/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),'Enter a valid email address.'),phone:z.string().trim().max(40),firstName:z.string().trim().max(100),lastName:z.string().trim().max(100),nickname:z.string().trim().max(100),jobTitle:z.string().trim().max(120),division:z.string().trim().max(120),department:z.string().trim().max(120)});
function getStoredSmtpSettings():{settings:SmtpSettings;passwordConfigured:boolean}{
  const row=db.prepare("SELECT value_json FROM application_settings WHERE key='smtp_settings'").get() as {value_json:string}|undefined;
  if(!row)return {settings:{host:'smtp.gmail.com',port:587,secure:false,username:'',password:'',fromName:'MFEC Recording Explorer',fromEmail:'',rejectUnauthorized:true},passwordConfigured:false};
  const value=JSON.parse(row.value_json) as Record<string,unknown>;
  const passwordEnc=typeof value.passwordEnc==='string'?value.passwordEnc:'';
  const password=passwordEnc?decrypt(passwordEnc):'';
  const {passwordEnc:_passwordEnc,...fields}=value;
  return {settings:parseSmtpSettings({...fields,password}),passwordConfigured:Boolean(passwordEnc)};
}
const connectionSchema=z.object({name:z.string().trim().min(1).max(120),organizationLabel:z.string().trim().min(1).max(120),regionId:z.string().min(1).max(64),apiBaseUrl:z.string().url().optional(),oauthBaseUrl:z.string().url().optional(),clientId:z.string().trim().min(1).max(256),clientSecret:z.string().min(1).max(1024),enabled:z.boolean().default(true),isDefault:z.boolean().default(false)});
const connectionTestSchema=connectionSchema.partial({clientSecret:true}).extend({clientSecret:z.string().max(1024).optional(),existingConnectionId:z.string().uuid().optional()});
const searchSchema=z.object({connectionId:z.string().min(1),intervalStart:z.string().datetime({offset:true}),intervalEnd:z.string().datetime({offset:true}),pageNumber:z.number().int().min(1).default(1),pageSize:z.number().int().min(1).max(100).default(25),agentName:z.string().trim().max(120).optional(),groupName:z.string().trim().max(120).optional(),queueName:z.string().trim().max(120).optional(),direction:z.enum(['inbound','outbound']).optional(),phone:z.string().max(80).optional(),dnis:z.string().max(80).optional(),conversationId:z.string().max(128).optional(),showUnplayable:z.boolean().default(false)});
const playabilitySchema=z.object({connectionId:z.string().min(1).max(128),conversationId:z.string().min(1).max(128),recordingId:z.string().min(1).max(128),unplayable:z.boolean(),source:z.enum(['manual','playback','archive']).default('manual'),archiveId:z.string().max(128).optional()});
function publicUser(user:{id:string;username:string;role:string}){const permissions=getRolePermissions(user.role);return {...user,roleName:roleName(user.role),permissions:{...permissions,libraryPlayback:hasAccessPermission(user.role,'libraryPlayback')},isAdministrator:user.role==='administrator'};}
function requireAuth(req:Request,res:ExpressResponse,next:NextFunction){const sessionUser=req.session.user;if(!sessionUser)return res.status(401).json({error:'Sign in required.'});const account=db.prepare('SELECT username,role,access_role_id AS accessRoleId,enabled FROM users WHERE id=?').get(sessionUser.id) as {username:string;role:string;accessRoleId:string|null;enabled:number}|undefined;if(!account||!account.enabled){req.session.destroy(()=>{});return res.status(401).json({error:'Your account is disabled or no longer exists.'});}req.session.user={id:sessionUser.id,username:account.username,role:account.accessRoleId||account.role};next();}
function requireAdmin(req:Request,res:ExpressResponse,next:NextFunction){if(req.session.user?.role!=='administrator')return res.status(403).json({error:'Administrator role required.'});next();}
function requirePermission(permission:'realtimePlayback'|'realtimeDownload'|'libraryPlayback'|'libraryAdmin'){return(req:Request,res:ExpressResponse,next:NextFunction)=>hasAccessPermission(req.session.user?.role||'',permission)?next():res.status(403).json({error:'Your role does not have permission to access this feature.'});}
function requireRecordingSearch(req:Request,res:ExpressResponse,next:NextFunction){return canUseRecordingSearch(req.session.user?.role||'')?next():res.status(403).json({error:'Realtime Playback permission is required to use Recording Search.'});}
function requireRealtimePlayback(req:Request,res:ExpressResponse,next:NextFunction){return requirePermission('realtimePlayback')(req,res,next);}
function requireRealtimeDownload(req:Request,res:ExpressResponse,next:NextFunction){return requirePermission('realtimeDownload')(req,res,next);}
function requireDownloadSourceAccess(req:Request,res:ExpressResponse,next:NextFunction){return requireRealtimeDownload(req,res,next);}
function requirePlaybackSourceAccess(req:Request,res:ExpressResponse,next:NextFunction){return requireRealtimePlayback(req,res,next);}
function requireLibraryPlayback(req:Request,res:ExpressResponse,next:NextFunction){return requirePermission('libraryPlayback')(req,res,next);}
function requirePlayabilityAccess(req:Request,res:ExpressResponse,next:NextFunction){const role=req.session.user?.role||'';return canUseRecordingSearch(role)||hasAccessPermission(role,'libraryPlayback')||hasAccessPermission(role,'libraryAdmin')?next():res.status(403).json({error:'Recording Playback permission is required.'});}
function requireLibraryAdmin(req:Request,res:ExpressResponse,next:NextFunction){return requirePermission('libraryAdmin')(req,res,next);}
function requireRole(...roles:string[]){return(req:Request,res:ExpressResponse,next:NextFunction)=>roles.includes(req.session.user?.role||'')?next():res.status(403).json({error:'Your role cannot perform this action.'});}
function requireCsrf(req:Request,res:ExpressResponse,next:NextFunction){const sent=req.get('x-csrf-token')||'';if(!req.session.csrf||!safeEqual(sent,req.session.csrf))return res.status(403).json({error:'CSRF validation failed.'});next();}
async function verifyS3GenesysConnection(id:string|undefined,organizationId:string,userId:string,role:string){if(!id)throw httpError(400,'Select a Genesys Connection for conversation metadata.');if(process.env.MOCK_MODE==='true')throw httpError(409,'Mock Mode is active. Live Genesys connections cannot be linked to AWS S3 sources.');const row=db.prepare('SELECT * FROM connections WHERE id=? AND enabled=1').get(id) as Connection|undefined;if(!row)throw httpError(400,'Select an enabled Genesys Connection for this AWS S3 source.');const connection=connectionById(row.id,userId,role),client=new GenesysClient(connection);try{const organization=await verifyGenesysApiAccess(client);if(!organization.id||organization.id!==organizationId)throw httpError(400,'The selected Genesys Connection belongs to a different organization than the S3 export organization ID.');return connection;}finally{client.clearCachedToken();}}
function hasS3SourceGrant(source:S3SourceRow,userId:string,role:string){if(!source.genesys_connection_id)return false;if(role==='administrator'||hasAccessPermission(role,'libraryAdmin'))return true;return Boolean(db.prepare('SELECT 1 FROM user_connection_access WHERE user_id=? AND connection_id=?').get(userId,source.genesys_connection_id));}
function canUseS3Source(source:S3SourceRow,userId:string,role:string){return hasAccessPermission(role,'realtimePlayback')&&hasS3SourceGrant(source,userId,role);}
async function resolveAuthorizedS3Recording(source:S3SourceRow,config:ReturnType<typeof decryptS3Source>,metadataKey:string,conversationId:string,recordingId:string,userId:string,role:string,operation:'playback'|'download'|'library-export'='playback'){
  const permission=operation==='playback'?'realtimePlayback':operation==='download'?'realtimeDownload':'libraryAdmin';
  if(!hasAccessPermission(role,permission)||!hasS3SourceGrant(source,userId,role))throw httpError(404,'AWS S3 source not found or access denied.');
  if(!source.genesys_connection_id)throw httpError(404,'AWS S3 source is not linked to a Genesys Connection.');
  const connection=connectionById(source.genesys_connection_id,userId,role),client=new GenesysClient(connection);
  try{
    const resolved=await resolveS3Recording(config,metadataKey,conversationId,recordingId),conversation=await getCachedGenesysConversation(client,connection.id,conversationId),recordings=listPlayableRecordings(await listConversationRecordings(client,conversationId),conversation),recording=recordings.find(item=>String(item.id||item.recordingId)===recordingId);
    if(!recording)throw httpError(404,'Genesys does not associate this S3 recording ID with the linked conversation.');
    if((resolved.mediaType==='screen')!==isScreenRecording(recording))throw httpError(409,'S3 media type does not match the linked Genesys recording metadata.');
     return {...resolved,recording,conversation,connection,genesysRecordings:recordings};
   }finally{client.clearCachedToken();}
}
async function getCachedGenesysConversation(client:GenesysClient,connectionId:string,conversationId:string){const cached=db.prepare('SELECT metadata_json FROM conversation_metadata_index WHERE connection_id=? AND conversation_id=? AND expires_at>?').get(connectionId,conversationId,new Date().toISOString()) as {metadata_json:string}|undefined;if(cached){try{const value=JSON.parse(cached.metadata_json),conversation=value.conversation||value;if(conversation?.conversationId===conversationId)return conversation;}catch{/* Refresh an expired or invalid cache entry below. */}}const conversation=await client.get<any>(analyticsConversationDetailsPath(conversationId));if(!conversation||conversation.conversationId!==conversationId)throw httpError(404,'Genesys conversation was not found.');db.prepare('INSERT INTO conversation_metadata_index(connection_id,conversation_id,indexed_at,expires_at,metadata_json) VALUES(?,?,?,?,?) ON CONFLICT(connection_id,conversation_id) DO UPDATE SET indexed_at=excluded.indexed_at,expires_at=excluded.expires_at,metadata_json=excluded.metadata_json').run(connectionId,conversationId,new Date().toISOString(),new Date(Date.now()+30*86400000).toISOString(),JSON.stringify(redactSensitiveMetadata({conversation})));return conversation;}
function audit(req:Request,action:string,result:string,connectionId?:string,conversationId?:string,recordingId?:string,detail:Record<string,unknown>={}){const u=req.session.user;const address=req.ip||'';const ip=address.includes(':')?address.split(':').slice(0,4).join(':')+'::/64':address.split('.').slice(0,3).join('.')+'.0/24';db.prepare('INSERT INTO audit_logs(user_id,username,action,result,connection_id,conversation_id,recording_id,source_ip,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(u?.id||null,u?.username||'anonymous',action,result,connectionId||null,conversationId||null,recordingId||null,ip,JSON.stringify(detail),new Date().toISOString());}
function getAuditRetentionDays(){const row=db.prepare("SELECT value_json FROM application_settings WHERE key='audit_retention_days'").get() as {value_json:string}|undefined;if(!row)return 35;try{const days=JSON.parse(row.value_json);return Number.isInteger(days)&&days>=1&&days<=3650?days:35;}catch{return 35;}}
function purgeExpiredAuditLogs(){const cutoff=new Date(Date.now()-getAuditRetentionDays()*86400000).toISOString();return Number(db.prepare('DELETE FROM audit_logs WHERE created_at<?').run(cutoff).changes);}
function escapeLike(value:string){return value.replace(/[\\%_]/g,'\\$&');}
function redactSensitiveMetadata(value:any):any{if(Array.isArray(value))return value.map(redactSensitiveMetadata);if(value&&typeof value==='object'){const safe:Record<string,unknown>={};for(const [key,item] of Object.entries(value)){if(/token|secret|authorization|mediaUri|signed|url/i.test(key))safe[key]='[REDACTED]';else safe[key]=redactSensitiveMetadata(item);}return safe;}return value;}
async function mapWrapUpNames(client:GenesysClient,conversation:any){const ids=collectWrapUpCodeIds(conversation);if(!ids.length)return conversation;const entries=await mapWithConcurrency(ids,4,async id=>{try{const code=await client.get<{id?:string;name?:string}>(`/api/v2/routing/wrapupcodes/${encodeURIComponent(id)}`);return [id,typeof code?.name==='string'&&code.name.trim()?code.name:undefined] as const;}catch(error){if(error instanceof GenesysError&&[403,404].includes(error.status))return [id,undefined] as const;throw error;}});return withWrapUpCodeNames(conversation,Object.fromEntries(entries.filter((entry):entry is readonly [string,string]=>Boolean(entry[1]))));}
async function mapConversationQueueNames(client:GenesysClient,conversation:any){const ids=collectQueueIds(conversation);if(!ids.length)return {};const entries=await mapWithConcurrency(ids,4,async id=>{try{const queue=await client.get<{id?:string;name?:string}>(`/api/v2/routing/queues/${encodeURIComponent(id)}`);return [id,typeof queue?.name==='string'&&queue.name.trim()?queue.name:undefined] as const;}catch(error){if(error instanceof GenesysError&&[403,404].includes(error.status))return [id,undefined] as const;throw error;}});return Object.fromEntries(entries.filter((entry):entry is readonly [string,string]=>Boolean(entry[1])));}
function publicError(error:unknown){if(error instanceof Error)return error.message.slice(0,200);return 'Connection test failed.';}
function httpError(status:number,message:string){return Object.assign(new Error(message),{status});}
function getRecordingOutputFormat(){const row=db.prepare("SELECT value_json FROM application_settings WHERE key='recording_output_format'").get() as {value_json:string}|undefined;if(!row)return DEFAULT_RECORDING_OUTPUT_FORMAT;try{return parseRecordingOutputFormat(JSON.parse(row.value_json));}catch{return DEFAULT_RECORDING_OUTPUT_FORMAT;}}
async function convertAudio(audio:Buffer,format:ReturnType<typeof parseRecordingOutputFormat>,expectedDurationMs?:number){try{return await transcodeRecordingAudio(audio,format,undefined,expectedDurationMs);}catch(error){const message=error instanceof Error?error.message:'Audio conversion failed.';throw httpError(/install FFmpeg|conversion is unavailable|conversion is busy/i.test(message)?503:422,message);}}
function errorHandler(error:unknown,req:Request,res:ExpressResponse,_next:NextFunction){const status=Number((error as any)?.status)|| (error instanceof z.ZodError?400:500),s3Request=req.path.startsWith('/api/s3/')||String(req.query.connectionId||'').startsWith('s3:');if(status===500&&!s3Request)console.error('Request failed:',error);res.status(status).json({error:status===500?'Request failed. Check server logs using the correlation time.':publicError(error),...(error instanceof z.ZodError?{issues:error.issues.map(i=>({path:i.path,message:i.message}))}:{})});}
function mockMatches(c:any,input:z.infer<typeof searchSchema>){return matchesConversationFilters(c,input);}
function matchesConversationFilters(c:any,input:z.infer<typeof searchSchema>){const all=c.participants||[];if(input.agentName&&!summarizeConversation(c).agents.some((name:string)=>name.toLocaleLowerCase()===input.agentName!.toLocaleLowerCase()))return false;if(input.queueName&&!conversationQueueNames(c).some((name:string)=>name.toLocaleLowerCase()===input.queueName!.toLocaleLowerCase()))return false;if(input.groupName){const groupMembers=new Set(MOCK_GROUP_MEMBERS[MOCK_DIRECTORY.group.find(group=>group.name.toLocaleLowerCase()===input.groupName!.toLocaleLowerCase())?.id||'']||[]);if(!all.some((p:any)=>groupMembers.has(p.userId)))return false;}if(input.direction&&c.originatingDirection!==input.direction)return false;if(input.phone&&!conversationHasPhoneMatch(c,input.phone,'phone'))return false;if(input.dnis&&!conversationHasPhoneMatch(c,input.dnis,'dnis'))return false;return true;}
function matchesPhone(c:any,input:z.infer<typeof searchSchema>){return (!input.phone||conversationHasPhoneMatch(c,input.phone,'phone'))&&(!input.dnis||conversationHasPhoneMatch(c,input.dnis,'dnis'));}
function validateMediaUrl(value:string,connection:Connection){try{return validateRecordingMediaUrl(value,connection);}catch(error){throw httpError(502,error instanceof Error?error.message:'Genesys returned an invalid recording media URL.');}}
async function pipeMedia(_req:Request,res:ExpressResponse,response:globalThis.Response,options:{allowZip?:boolean}={}){if(!response.ok&&response.status!==206){throw httpError(response.status===403?410:502,response.status===403?'Recording media URL has expired. Retry playback to obtain a fresh URL.':'Recording media could not be retrieved.');}const type=response.headers.get('content-type')||'';if(isZipMediaContentType(type)&&!options.allowZip){await response.body?.cancel().catch(()=>{});throw httpError(409,'Genesys returned a ZIP message recording archive, not playable audio. This recording cannot play in the audio player; use Download to retrieve the archive.');}if(!/^audio\//i.test(type)&&!/^video\/webm/i.test(type)&&!/^application\/octet-stream/i.test(type)&&!(options.allowZip&&isZipMediaContentType(type)))throw httpError(502,'Genesys returned an unsupported media content type.');res.status(response.status);res.setHeader('Content-Type',type);res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('Accept-Ranges',response.headers.get('accept-ranges')||'bytes');const length=response.headers.get('content-length'),range=response.headers.get('content-range');if(length)res.setHeader('Content-Length',length);if(range)res.setHeader('Content-Range',range);if(!response.body)throw httpError(502,'Recording media response was empty.');const stream=Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);const onClose=()=>{if(!res.writableEnded)stream.destroy(new Error('Downstream playback client disconnected.'));};res.once('close',onClose);try{await new Promise<void>((resolve,reject)=>{stream.once('error',reject);res.once('error',reject);res.once('finish',resolve);stream.pipe(res);});}finally{res.off('close',onClose);}}
function canAccessArchived(req:Request,row:Record<string,any>){if(req.session.user?.role==='administrator'||hasAccessPermission(req.session.user?.role||'','libraryAdmin'))return true;return Boolean(db.prepare('SELECT 1 FROM user_connection_access WHERE user_id=? AND connection_id=?').get(req.session.user!.id,row.connection_id));}
async function readBoundedBody(response:globalThis.Response,limit:number):Promise<Buffer>{if(!response.ok){await response.body?.cancel().catch(()=>{});throw httpError(response.status===403?410:502,'Recording media could not be retrieved.');}const declared=Number(response.headers.get('content-length')||0);if(declared>limit){await response.body?.cancel().catch(()=>{});throw httpError(413,'Recording media exceeds the safe size limit.');}if(!response.body)throw httpError(502,'Recording media response was empty.');const reader=response.body.getReader(),chunks:Buffer[]=[];let total=0;try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>limit||chunks.length>=Math.ceil(limit/65536)+1){await reader.cancel();throw httpError(413,'Recording media exceeds the safe size limit.');}chunks.push(Buffer.from(value));}}finally{reader.releaseLock();}return Buffer.concat(chunks,total);}
async function readAwsS3Body(body:AsyncIterable<Uint8Array>,limit:number):Promise<Buffer>{const stream=body as unknown as {destroy?:()=>void},chunks:Buffer[]=[];let total=0;for await(const chunk of body){const value=Buffer.from(chunk);total+=value.byteLength;if(total>limit){stream.destroy?.();throw httpError(413,'Recording media exceeds the safe size limit.');}chunks.push(value);}return Buffer.concat(chunks,total);}
function serveAudioBuffer(req:Request,res:ExpressResponse,audio:Buffer,mimeType:string){const match=/^bytes=(\d*)-(\d*)$/.exec(req.headers.range||'');let start=0,end=audio.length-1;if(match){if(!match[1]&&!match[2])throw httpError(416,'Requested audio range is invalid.');if(!match[1]){const suffix=Number(match[2]);if(!Number.isSafeInteger(suffix)||suffix<=0)throw httpError(416,'Requested audio range is invalid.');start=Math.max(0,audio.length-suffix);}else{start=Number(match[1]);if(match[2])end=Number(match[2]);}if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||start>=audio.length||end<start){res.status(416).setHeader('Content-Range',`bytes */${audio.length}`).end();return;}end=Math.min(end,audio.length-1);}res.status(match?206:200);res.setHeader('Content-Type',mimeType);res.setHeader('Content-Length',String(end-start+1));res.setHeader('Accept-Ranges','bytes');if(match)res.setHeader('Content-Range',`bytes ${start}-${end}/${audio.length}`);res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('X-Content-Type-Options','nosniff');res.end(audio.subarray(start,end+1));}
function safeRecording(r:any,conversation?:any){return safeRecordingMetadata(r,conversation);}
function withRecordingsPlayability<T extends {conversationId:string;recordings:any[]}>(connectionId:string,items:T[],showUnplayable=true):T[]{const statuses=getUnplayableRecordingKeys(connectionId,items.map(item=>item.conversationId));return items.map(item=>({...item,recordings:item.recordings.map((recording:any)=>({...recording,unplayable:statuses.has(`${item.conversationId}\u0000${recording.id}`)})).filter((recording:any)=>showUnplayable||!recording.unplayable)}));}
async function fetchTrustedMedia(value:string,connection:Connection,headers:Record<string,string>){let url=validateMediaUrl(value,connection);for(let redirects=0;redirects<=2;redirects++){let response:globalThis.Response;try{response=await fetch(url,{headers,signal:AbortSignal.timeout(30000),redirect:'manual'});}catch{throw httpError(502,'Recording media could not be reached. Retry playback.');}if(response.status<300||response.status>=400)return response;const location=response.headers.get('location');if(!location)throw httpError(502,'Recording media redirect was invalid.');if(redirects===2)throw httpError(502,'Recording media returned too many redirects.');let next:URL;try{next=new URL(location,url);}catch{throw httpError(502,'Recording media redirect was invalid.');}url=validateMediaUrl(next.toString(),connection);}throw httpError(502,'Recording media redirect was invalid.');}
async function mapWithConcurrency<T,R>(items:T[],limit:number,work:(item:T)=>Promise<R>):Promise<R[]>{const output=new Array<R>(items.length);let cursor=0;async function worker(){while(true){const index=cursor++;if(index>=items.length)return;output[index]=await work(items[index]);}}await Promise.all(Array.from({length:Math.min(limit,items.length)},worker));return output;}
function rejectCrossOrigin(req:Request,res:ExpressResponse,next:NextFunction){const origin=req.get('origin'),fetchSite=req.get('sec-fetch-site');if(fetchSite==='cross-site')return res.status(403).json({error:'Cross-site API requests are not allowed.'});if(origin){try{const expected=new URL(process.env.APP_ORIGIN||'http://localhost:5173').origin;if(new URL(origin).origin!==expected)return res.status(403).json({error:'Request origin is not allowed.'});}catch{return res.status(403).json({error:'Request origin is not allowed.'});}}next();}
function revokeUserSessions(userId:string){const rows=db.prepare('SELECT sid,sess FROM sessions').all() as {sid:string;sess:string}[];const remove=db.prepare('DELETE FROM sessions WHERE sid=?');for(const row of rows){try{if(JSON.parse(row.sess)?.user?.id===userId)remove.run(row.sid);}catch{remove.run(row.sid);}}}
function revokeRoleSessions(roleId:string){const rows=db.prepare('SELECT sid,sess FROM sessions').all() as {sid:string;sess:string}[];const remove=db.prepare('DELETE FROM sessions WHERE sid=?');for(const row of rows){try{if(JSON.parse(row.sess)?.user?.role===roleId)remove.run(row.sid);}catch{remove.run(row.sid);}}}
function validateProductionConfig(){if(process.env.NODE_ENV!=='production')return;let origin:URL;try{origin=new URL(process.env.APP_ORIGIN||'');}catch{throw new Error('APP_ORIGIN must be set to the public HTTPS application origin in production.');}if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new Error('APP_ORIGIN must be a bare HTTPS origin in production.');if((process.env.SESSION_SECRET||'').length<48||/replace|change.?me|example|development/i.test(process.env.SESSION_SECRET||''))throw new Error('Set a unique production SESSION_SECRET with at least 48 characters.');if(process.env.MOCK_MODE!=='false')throw new Error('Set MOCK_MODE=false explicitly for authorized production use.');const key=process.env.MASTER_ENCRYPTION_KEY||'';if(Buffer.from(key,'base64').length!==32||Buffer.from(key,'base64').toString('base64').replace(/=+$/,'')!==key.replace(/=+$/,''))throw new Error('MASTER_ENCRYPTION_KEY must be a base64-encoded 32-byte key in production.');if(process.env.TRUST_PROXY!=='true')throw new Error('Set TRUST_PROXY=true only when the app is reachable solely through one trusted HTTPS reverse proxy.');}
function regenerate(req:Request){return new Promise<void>((resolve,reject)=>req.session.regenerate(error=>error?reject(error):resolve()));}
app.use(errorHandler);
if(process.env.NODE_ENV==='production'){const fs=await import('node:fs');const path=await import('node:path');const root=path.resolve('dist');app.use(express.static(root));app.get(/^(?!\/api\/).*/,(_req,res)=>res.sendFile(path.join(root,'index.html')));}
const server=app.listen(port,host,()=>console.log(`MFEC Recording Explorer API listening on ${host}:${port} (${process.env.MOCK_MODE==='true'?'Mock Mode':'Genesys mode'})`));
server.once('listening',()=>libraryArchiveWorker.start());
function shutdown(){libraryArchiveWorker.stop();server.close(()=>{try{sessionStore.close();db.close();}finally{process.exit(0);}});}
shutdownServer=shutdown;
process.once('SIGTERM',shutdown);
process.once('SIGINT',shutdown);
