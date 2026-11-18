import 'dotenv/config';
import express, { type Request, type Response as ExpressResponse, type NextFunction } from 'express';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { z } from 'zod';
import { extractSingleAudioFromZip } from './zip-audio.js';
import { conversationCommunicationIds, transcriptionRequestPath, validateTranscriptUrl } from './transcription.js';
import { collectAfterCallNotes, collectWrapUpCodeIds, withWrapUpCodeNames } from './wrapup.js';
import { db, migrate } from './db/index.js';
import { clearUserAppearance, getDefaultAppearance, getUserAppearance, parseAppearance, saveDefaultAppearance, saveUserAppearance } from './appearance.js';
import { conversationHasVoiceSession, getRecordingMedia, isMessageRecording, isVoiceRecording, isZipMediaContentType, recordingMediaRequestPath, recordingMediaUri, validateRecordingMediaUrl } from './recording-media.js';
import { MAX_ANALYTICS_CONVERSATIONS, queryAllConversations } from './conversation-query.js';
import { BetterSqliteSessionStore } from './session-store.js';
import { decrypt, encrypt, safeEqual } from './security.js';
import { isPasswordPolicySatisfied } from './password-policy.js';
import { parseSmtpSettings, publicSmtpSettings, sendConfiguredEmail, type SmtpSettings } from './mailer.js';
import { getRegions, saveRegions, trustedBaseUrl, validateRegionEndpoints, type GenesysRegion } from './regions.js';
import { connectionById, type Connection } from './genesys.js';
import { GenesysClient, GenesysError, verifyGenesysApiAccess } from './genesys-client.js';
import { MOCK_CONVERSATIONS, MOCK_RECORDINGS } from './mock.js';

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
bootstrapUser();
purgeExpiredAuditLogs();
const auditRetentionTimer=setInterval(purgeExpiredAuditLogs,24*60*60*1000);
auditRetentionTimer.unref();

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
  res.json({ user: req.session.user, csrfToken: req.session.csrf });
});
app.get('/api/user/appearance', requireAuth, (req, res) => {
  const userAppearance = getUserAppearance(req.session.user!.id);
  const defaultAppearance = getDefaultAppearance();
  res.json({
    appearance: userAppearance ?? defaultAppearance,
    userOverride: userAppearance !== null,
    defaultAppearance,
    canSetDefault: req.session.user!.role === 'administrator',
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
    req.session.user = { id: user.id, username: user.username, role: user.role };
    req.session.csrf = crypto.randomBytes(24).toString('hex');
    audit(req, 'LOGIN', 'SUCCESS');
    res.json({ user: req.session.user, csrfToken: req.session.csrf });
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

app.get('/api/genesys/regions', requireAuth, (_req, res) => res.json({ regions: getRegions() }));
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
  const rows = req.session.user!.role === 'administrator'
    ? (process.env.MOCK_MODE === 'true' ? [] : db.prepare("SELECT id,name,organization_label,region_id,api_base_url,oauth_base_url,enabled,is_default,last_success_at,CASE WHEN last_error IS NULL THEN NULL ELSE 'Connection check failed. Review administrator logs.' END AS last_error,client_id,CASE WHEN client_secret_enc='' THEN 0 ELSE 1 END AS secret_configured FROM connections ORDER BY name").all())
    : (process.env.MOCK_MODE === 'true' ? [] : db.prepare('SELECT c.id,c.name,c.organization_label,c.region_id,c.api_base_url,c.oauth_base_url,c.enabled,c.is_default,c.last_success_at,c.last_error,c.client_id,1 AS secret_configured FROM connections c JOIN user_connection_access a ON a.connection_id=c.id WHERE a.user_id=? AND c.enabled=1 ORDER BY c.name').all(req.session.user!.id));
  const values = process.env.MOCK_MODE === 'true' ? [{ id: 'mock', name: 'Synthetic Demo Organization', organization_label: 'Mock Mode · Synthetic data', region_id: 'ap-southeast-1', enabled: 1, is_default: 1, last_success_at: null, last_error: null, client_id: '', secret_configured: 0, mock: true }] : [];
  const validRows=(rows as any[])
    .filter(connection=>getRegions().some(region=>region.id===connection.region_id&&region.api===connection.api_base_url&&region.oauth===connection.oauth_base_url))
    .map(({api_base_url,oauth_base_url,...connection})=>connection);
  res.json({ connections: [...values, ...validRows] });
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
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>{
  const users=db.prepare('SELECT id,username,role,enabled,created_at AS createdAt,email,phone,first_name AS firstName,last_name AS lastName,nickname,job_title AS jobTitle,division,department FROM users ORDER BY username').all() as {id:string;username:string;role:string;enabled:number;createdAt:string}[];
  const grants=db.prepare('SELECT user_id AS userId,connection_id AS connectionId FROM user_connection_access').all() as {userId:string;connectionId:string}[];
  res.json({users:users.map(user=>({...user,connections:grants.filter(grant=>grant.userId===user.id).map(grant=>grant.connectionId)}))});
});
app.post('/api/admin/users',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{
  try { const input=z.object({username:z.string().trim().min(2).max(128).regex(/^[\p{L}\p{N}._@-]+$/u),password:z.string().min(8).max(256),role:z.enum(['administrator','supervisor','quality_analyst','viewer']),connectionIds:z.array(z.string()).max(100).default([]),profile:profileSchema.default(emptyProfile)}).parse(req.body); if(!isPasswordPolicySatisfied(input.password))throw httpError(400,'Password must be at least 8 characters and include a letter plus a number or special character.');for(const connectionId of input.connectionIds)if(!db.prepare('SELECT id FROM connections WHERE id=? AND enabled=1').get(connectionId))throw httpError(400,'An enabled organization connection is required.'); const id=crypto.randomUUID();
    const transaction=db.transaction(()=>{db.prepare('INSERT INTO users(id,username,password_hash,role,created_at,email,phone,first_name,last_name,nickname,job_title,division,department) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,input.username,awaitHash(input.password),input.role,new Date().toISOString(),input.profile.email,input.profile.phone,input.profile.firstName,input.profile.lastName,input.profile.nickname,input.profile.jobTitle,input.profile.division,input.profile.department);const grant=db.prepare('INSERT INTO user_connection_access(user_id,connection_id) VALUES(?,?)');for(const connectionId of input.connectionIds)grant.run(id,connectionId);}); transaction(); audit(req,'USER_CREATE','SUCCESS'); res.status(201).json({id,username:input.username});
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
  try { const {role}=z.object({role:z.enum(['administrator','supervisor','quality_analyst','viewer'])}).parse(req.body),id=String(req.params.id);if(id===req.session.user!.id&&role!=='administrator')throw httpError(400,'Administrators cannot remove their own administrator role.');const target=db.prepare('SELECT role FROM users WHERE id=?').get(id) as {role:string}|undefined;if(!target)throw httpError(404,'User not found.');if(target.role===role)return res.json({ok:true});if(target.role==='administrator'&&role!=='administrator'&&Number((db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='administrator' AND enabled=1").get() as {n:number}).n)<=1)throw httpError(409,'The last enabled administrator cannot be demoted.');db.prepare('UPDATE users SET role=? WHERE id=?').run(role,id);revokeUserSessions(id);audit(req,'USER_ROLE_UPDATE','SUCCESS',undefined,undefined,undefined,{userId:id,role});res.json({ok:true}); }
  catch(error){next(error);}
});
app.put('/api/admin/users/:id/enabled',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const {enabled}=z.object({enabled:z.boolean()}).parse(req.body),id=String(req.params.id);if(id===req.session.user!.id&&!enabled)throw httpError(400,'Administrators cannot disable their own account.');const target=db.prepare('SELECT role,enabled FROM users WHERE id=?').get(id) as {role:string;enabled:number}|undefined;if(!target)throw httpError(404,'User not found.');if(Boolean(target.enabled)===enabled)return res.json({ok:true});if(target.role==='administrator'&&target.enabled&&!enabled&&Number((db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='administrator' AND enabled=1").get() as {n:number}).n)<=1)throw httpError(409,'The last enabled administrator cannot be disabled.');db.prepare('UPDATE users SET enabled=? WHERE id=?').run(Number(enabled),id);revokeUserSessions(id);audit(req,'USER_STATUS_UPDATE','SUCCESS',undefined,undefined,undefined,{userId:id,enabled});res.json({ok:true}); }
  catch(error){next(error);}
});
app.delete('/api/admin/users/:id',requireAuth,requireAdmin,requireCsrf,(req,res,next)=>{
  try { const id=String(req.params.id);if(id===req.session.user!.id)throw httpError(400,'You cannot delete your own account.');const target=db.prepare('SELECT username,role,enabled FROM users WHERE id=?').get(id) as {username:string;role:string;enabled:number}|undefined;if(!target)throw httpError(404,'User not found.');if(target.role==='administrator'&&target.enabled&&Number((db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='administrator' AND enabled=1").get() as {n:number}).n)<=1)throw httpError(409,'The last enabled administrator cannot be deleted.');revokeUserSessions(id);db.prepare('DELETE FROM users WHERE id=?').run(id);audit(req,'USER_DELETE','SUCCESS',undefined,undefined,undefined,{userId:id,username:target.username});res.status(204).end(); }
  catch(error){next(error);}
});

app.post('/api/recordings/search', requireAuth, requireCsrf, rateLimit({windowMs:60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false}), async (req,res,next) => {
  try {
    const input = searchSchema.parse(req.body); const user = req.session.user!;
    const connection = input.connectionId === 'mock' ? null : connectionById(input.connectionId,user.id,user.role);
    if (!connection && !(input.connectionId === 'mock' && process.env.MOCK_MODE === 'true')) throw httpError(404,'Connection not found or access denied.');
    const from = Date.parse(input.intervalStart), to = Date.parse(input.intervalEnd);
    if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) throw httpError(400,'Choose a valid start and end time.');
    if (to - from > 90 * 86400000) throw httpError(400,'Search intervals are limited to 90 days. Narrow the date range to continue.');
    const client = connection ? new GenesysClient(connection) : null;
    let conversations: any[] = [], totalHits: number | null = null, partial = false;
    if (!client) {
      conversations = MOCK_CONVERSATIONS.filter(c => Date.parse(c.conversationStart) >= from && Date.parse(c.conversationStart) <= to && mockMatches(c,input) && (!input.conversationId||c.conversationId===input.conversationId) && (input.includeNoRecording||(MOCK_RECORDINGS[c.conversationId] as any[]||[]).length>0));
      totalHits = conversations.length;
    } else {
      const segmentPredicates: any[] = [];
      if(input.agentId) segmentPredicates.push({type:'dimension',dimension:'userId',operator:'matches',value:input.agentId});
      if(input.queueId) segmentPredicates.push({type:'dimension',dimension:'queueId',operator:'matches',value:input.queueId});
      const analyticsFilters: Record<string,unknown> = {};
      if(input.direction) analyticsFilters.conversationFilters=[{type:'and',predicates:[{type:'dimension',dimension:'originatingDirection',operator:'matches',value:input.direction}]}];
      if(segmentPredicates.length) analyticsFilters.segmentFilters=[{type:'and',predicates:segmentPredicates}];

      if(input.conversationId) {
        const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(input.conversationId)}/details`);
        conversations=conversation?.conversationId===input.conversationId && Date.parse(conversation.conversationStart)>=from && Date.parse(conversation.conversationStart)<=to && matchesConversationFilters(conversation,input) ? [conversation] : [];
        totalHits=conversations.length;
      } else {
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
      // Apply ANI/DNIS only after paging the entire Analytics query, otherwise
      // matching conversations beyond the first page would be silently lost.
      if(input.phone || input.dnis) conversations=conversations.filter(conversation=>matchesPhone(conversation,input));
    }
    conversations.sort((a,b)=>Date.parse(b.conversationStart||'')-Date.parse(a.conversationStart||''));
    const enriched = await mapWithConcurrency(conversations,5,async c => {
      let recordings: any[] = [],recordingListAvailable=true;
      try {
        if(client) {
          const response = await client.get<unknown>(`/api/v2/conversations/${encodeURIComponent(c.conversationId)}/recordings`);
          recordings = Array.isArray(response) ? response.filter(recording => isVoiceRecording(recording,c)) : [];
        }
        else recordings = ((MOCK_RECORDINGS[c.conversationId] as any[]) || []).filter(recording => isVoiceRecording(recording,c));
      } catch (error) { if(error instanceof GenesysError && (error.status === 404 || error.status === 403)){recordingListAvailable=false;recordings=[];} else throw error; }
      return { ...summarize(c), recordingCount:recordings.length, recordingListAvailable, recordings:recordings.map(recording=>safeRecording(recording,c)) };
    });
    const recordingListsIncomplete=enriched.some(result=>!result.recordingListAvailable);
    partial||=recordingListsIncomplete;
    const matchesRecordingFilter=(result:any)=>input.includeNoRecording||result.recordingCount>0;
    const visibleResults=enriched.filter(result=>matchesRecordingFilter(result)&&(!input.phone||result.ani.includes(input.phone))&&(!input.dnis||result.dnis.includes(input.dnis)));
    totalHits=partial?null:visibleResults.length;
    const pageStart=(input.pageNumber-1)*input.pageSize;
    const pageResults=visibleResults.slice(pageStart,pageStart+input.pageSize);
    audit(req,'SEARCH','SUCCESS',connection?.id || 'mock',undefined,undefined,{page:input.pageNumber,includeNoRecording:input.includeNoRecording,conversationsScanned:conversations.length,recordingsFound:visibleResults.reduce((count,result)=>count+result.recordingCount,0),partial});
    const scopeNote=recordingListsIncomplete?'Genesys did not return recording lists for some conversations (404 or permission denied). Results may be incomplete; verify permissions and retry.':partial?'Results were capped at 1,000 conversations or an Analytics page could not be verified; narrow the time range to confirm completeness.':input.phone||input.dnis?'Every conversation in the time range was checked before ANI/DNIS filters were applied.':!input.includeNoRecording?'Every conversation in the selected time range was checked; only those with at least one Genesys voice recording are shown.':'Every conversation in the selected time range was checked; conversations without voice recordings are included.';
    res.json({ results:pageResults, page:input.pageNumber,pageSize:input.pageSize,totalHits,partial,scope:scopeNote, mock:!client });
  } catch(error) { audit(req,'SEARCH','FAILED'); next(error); }
});
app.get('/api/recordings/conversations/:conversationId', requireAuth, async (req,res,next) => {
  try { const conversationId=String(req.params.conversationId);if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');if(String(req.query.connectionId||'')==='mock'&&process.env.MOCK_MODE==='true'){const mock=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId);return mock?res.json({...mock,wrapUpNotes:collectAfterCallNotes(mock)}):res.status(404).json({error:'Conversation not found.'});}const connection = connectionById(String(req.query.connectionId||''),req.session.user!.id,req.session.user!.role); const client = new GenesysClient(connection); const conversation = await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`); const mapped=await mapWrapUpNames(client,conversation); audit(req,'DETAILS_VIEW','SUCCESS',connection.id,conversationId); res.json({...redactSensitiveMetadata(mapped),wrapUpNotes:collectAfterCallNotes(mapped)}); }
  catch(error) { next(error); }
});
 app.get('/api/recordings/conversations/:conversationId/recordings', requireAuth, async (req,res,next) => {
   try { const id=String(req.query.connectionId||''),conversationId=String(req.params.conversationId);if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.'); if(id==='mock'&&process.env.MOCK_MODE==='true') { const conversation=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId);return res.json(((MOCK_RECORDINGS[conversationId]||[]) as any[]).filter(recording=>isVoiceRecording(recording,conversation)).map(recording=>safeRecording(recording,conversation))); } const c=connectionById(id,req.session.user!.id,req.session.user!.role),client=new GenesysClient(c); const items=await client.get<any[]>(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings`); const needsConversationContext=items.some(recording=>typeof recording?.mediaType!=='string');const conversation=needsConversationContext?await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`):undefined;const voiceRecordings=items.filter(recording=>isVoiceRecording(recording,conversation));const enriched=await mapWithConcurrency(voiceRecordings,4,async recording=>{const recordingId=recording.id||recording.recordingId;if(!recordingId)return safeRecording(recording,conversation);try{const metadata=await client.get<any>(recordingMediaRequestPath(conversationId,recordingId));return safeRecording({...recording,...metadata},conversation);}catch{return safeRecording(recording,conversation);}});res.json(enriched); }
  catch(error) { next(error); }
});
app.get('/api/recordings/:recordingId/metadata', requireAuth, async (req,res,next) => {
  try { const cId=String(req.query.connectionId||''), conversationId=String(req.query.conversationId||''),recordingId=String(req.params.recordingId);if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.'); if(cId==='mock'&&process.env.MOCK_MODE==='true') { const conversation=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId),r=((MOCK_RECORDINGS[conversationId] as any[])||[]).find(recording=>recording.id===recordingId&&isVoiceRecording(recording,conversation)); return r?res.json(safeRecording(r,conversation)):res.status(404).json({error:'Voice recording not found.'}); } const c=connectionById(cId,req.session.user!.id,req.session.user!.role),client=new GenesysClient(c); const item=await client.get<any>(recordingMediaRequestPath(conversationId,recordingId));if(!item)throw httpError(409,'Genesys did not return recording metadata.');const conversation=typeof item.mediaType==='string'&&item.mediaType.toLowerCase()==='voice'?undefined:await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);if(!isVoiceRecording(item,conversation))throw httpError(404,'Voice recording not found.');audit(req,'RECORDING_METADATA_VIEW','SUCCESS',c.id,conversationId,recordingId); res.json(safeRecording(item,conversation)); }
  catch(error) { next(error); }
});
app.get('/api/recordings/conversations/:conversationId/transcription', requireAuth, requireRole('administrator','supervisor','quality_analyst'), async (req,res,next) => {
  try {
    const conversationId=String(req.params.conversationId||''),connectionId=String(req.query.connectionId||'');
    if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');
    if(connectionId==='mock'&&process.env.MOCK_MODE==='true')throw httpError(501,'Synthetic Mock Mode does not include transcription data.');
    const connection=connectionById(connectionId,req.session.user!.id,req.session.user!.role),client=new GenesysClient(connection);
    const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);
    const communicationIds=conversationCommunicationIds(conversation);
    if(!communicationIds.length)throw httpError(404,'No voice communication was found for this conversation.');
    const transcripts=await mapWithConcurrency(communicationIds,4,async communicationId=>{
      try {
        const value=await client.get<{url?:string}>(transcriptionRequestPath(conversationId,communicationId));
        if(!value?.url)return undefined;
        const transcriptUrl=validateTranscriptUrl(value.url);
        let response:globalThis.Response;
        try{response=await fetch(transcriptUrl,{signal:AbortSignal.timeout(20000),redirect:'manual'});}catch{throw httpError(502,'Genesys transcription could not be retrieved.');}
        if(response.status>=300&&response.status<400){await response.body?.cancel().catch(()=>{});throw httpError(502,'Genesys transcript storage returned an unexpected redirect.');}
        const body=await readBoundedBody(response,16*1024*1024);
        const contentType=response.headers.get('content-type')||'';
        let transcript:unknown;
        try { transcript=JSON.parse(body.toString('utf8')); }
        catch { if(/^text\/(?:plain|vtt)/i.test(contentType))transcript=body.toString('utf8');else throw httpError(502,'Genesys returned an invalid transcription document.'); }
        return {communicationId,transcript:redactSensitiveMetadata(transcript)};
      } catch(error) {
        if(error instanceof GenesysError&&[404,409,410].includes(error.status))return undefined;
        throw error;
      }
    });
    const available=transcripts.filter((item):item is {communicationId:string;transcript:unknown}=>Boolean(item));
    if(!available.length)throw httpError(404,'Genesys has no transcription available for this conversation. Check that transcription is enabled and the service account has Speech and Text Analytics permissions.');
    audit(req,'TRANSCRIPTION_DOWNLOAD','SUCCESS',connection.id,conversationId);
    res.setHeader('Content-Type','application/json; charset=utf-8');
    res.setHeader('Content-Disposition',`attachment; filename="transcription-${conversationId.replace(/[^a-zA-Z0-9_-]/g,'_')}.json"`);
    res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.json({conversationId,generatedAt:new Date().toISOString(),transcriptions:available});
  } catch(error) { next(error); }
});
app.get('/api/recordings/:recordingId/stream', requireAuth, async (req,res,next) => {
  try {
    const cId=String(req.query.connectionId||''), conversationId=String(req.query.conversationId||'');
    if(!conversationId||conversationId.length>128||String(req.params.recordingId).length>128)throw httpError(400,'Valid conversation and recording IDs are required.');
    if(cId==='mock'&&process.env.MOCK_MODE==='true') return res.status(501).json({error:'Synthetic demo recordings include metadata only; real audio playback requires an authorized Genesys recording.'});
    const c=connectionById(cId,req.session.user!.id,req.session.user!.role); const client=new GenesysClient(c);
    const recordingId=String(req.params.recordingId); const playable=await getRecordingMedia(client,conversationId,recordingId);
    if(!playable) throw httpError(409,'Genesys has not made playable media available yet. Confirm the recording is finalized and that the service account has permission to download recordings in the conversation’s division; then retry.');
    const voiceContext=typeof playable.metadata?.mediaType==='string'&&playable.metadata.mediaType.toLowerCase()==='voice'?undefined:await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);
    if(!isVoiceRecording(playable.metadata,voiceContext))throw httpError(409,'Only voice recordings can be played.');
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
  } catch(error) { if(!res.headersSent){audit(req,'PLAYBACK','FAILED',undefined,String(req.query.conversationId||''),String(req.params.recordingId||''));next(error);} }
});
app.get('/api/recordings/:recordingId/download', requireAuth, requireRole('administrator','supervisor','quality_analyst'), async (req,res,next) => {
  let connection:Connection|undefined,conversationId='',recordingId='';
   try { conversationId=String(req.query.conversationId||'');recordingId=String(req.params.recordingId);if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.');connection=connectionById(String(req.query.connectionId||''),req.session.user!.id,req.session.user!.role);const client=new GenesysClient(connection),playable=await getRecordingMedia(client,conversationId,recordingId);if(!playable)throw httpError(409,'Genesys has not made downloadable media available yet. Confirm the recording is finalized and that the service account has permission to download recordings in the conversation’s division; then retry.');const voiceContext=typeof playable.metadata?.mediaType==='string'&&playable.metadata.mediaType.toLowerCase()==='voice'?undefined:await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`);if(!isVoiceRecording(playable.metadata,voiceContext))throw httpError(409,'Only voice recordings can be downloaded.');const response=await fetchTrustedMedia(playable.mediaUri,connection,{});const extension=isZipMediaContentType(response.headers.get('content-type'))?'.zip':'';res.setHeader('Content-Disposition',`attachment; filename="recording-${recordingId.replace(/[^a-zA-Z0-9_-]/g,'_')}${extension}"`);await pipeMedia(req,res,response,{allowZip:true});audit(req,'DOWNLOAD','SUCCESS',connection.id,conversationId,recordingId);}
  catch(error) { audit(req,'DOWNLOAD','FAILED',connection?.id,conversationId||undefined,recordingId||undefined);next(error); }
});
app.get('/api/dashboard/summary', requireAuth, async (req,res,next) => {
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
        try{const recordings=await client.get<unknown>(`/api/v2/conversations/${encodeURIComponent(conversation.conversationId)}/recordings`);recordingCount=Array.isArray(recordings)?recordings.filter(recording=>isVoiceRecording(recording,conversation)).length:0;}
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
app.post('/api/audit/export',requireAuth,requireCsrf,(req,res,next)=>{try{const input=z.object({exportType:z.enum(['search-results','audit-log']),connectionId:z.string().optional(),rows:z.number().int().min(0).max(10000)}).parse(req.body);if(input.exportType==='audit-log'){if(req.session.user!.role!=='administrator')throw httpError(403,'Administrator role required to export audit logs.');}else{if(!input.connectionId)throw httpError(400,'Connection is required for a search-result export.');if(input.connectionId!=='mock')connectionById(input.connectionId,req.session.user!.id,req.session.user!.role);}audit(req,input.exportType==='audit-log'?'AUDIT_LOG_EXPORT':'METADATA_EXPORT','SUCCESS',input.connectionId||undefined,undefined,undefined,{rows:input.rows,exportType:input.exportType});res.json({ok:true});}catch(error){next(error);}});

function bootstrapUser() {
  const username=process.env.INITIAL_ADMIN_USERNAME, password=process.env.INITIAL_ADMIN_PASSWORD;
  if(!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
    if(!username||!password) { if(process.env.NODE_ENV==='production') throw new Error('Set INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD for first production startup.'); return; }
    if(!isPasswordPolicySatisfied(password)) throw new Error('INITIAL_ADMIN_PASSWORD must be at least 8 characters and include a letter plus a number or special character.');
    const normalized=username.trim();if(!/^[\p{L}\p{N}._@-]{2,128}$/u.test(normalized))throw new Error('INITIAL_ADMIN_USERNAME contains unsupported characters.');
    db.prepare('INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)').run(crypto.randomUUID(),normalized,bcrypt.hashSync(password,12),'administrator',new Date().toISOString());
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
const searchSchema=z.object({connectionId:z.string().min(1),intervalStart:z.string().datetime({offset:true}),intervalEnd:z.string().datetime({offset:true}),pageNumber:z.number().int().min(1).default(1),pageSize:z.number().int().min(1).max(100).default(25),includeNoRecording:z.boolean().default(false),agentId:z.string().optional(),queueId:z.string().optional(),direction:z.enum(['inbound','outbound']).optional(),phone:z.string().max(80).optional(),dnis:z.string().max(80).optional(),conversationId:z.string().max(128).optional()});
function requireAuth(req:Request,res:ExpressResponse,next:NextFunction){const sessionUser=req.session.user;if(!sessionUser)return res.status(401).json({error:'Sign in required.'});const account=db.prepare('SELECT username,role,enabled FROM users WHERE id=?').get(sessionUser.id) as {username:string;role:string;enabled:number}|undefined;if(!account||!account.enabled){req.session.destroy(()=>{});return res.status(401).json({error:'Your account is disabled or no longer exists.'});}req.session.user={id:sessionUser.id,username:account.username,role:account.role};next();}
function requireAdmin(req:Request,res:ExpressResponse,next:NextFunction){if(req.session.user?.role!=='administrator')return res.status(403).json({error:'Administrator role required.'});next();}
function requireRole(...roles:string[]){return(req:Request,res:ExpressResponse,next:NextFunction)=>roles.includes(req.session.user?.role||'')?next():res.status(403).json({error:'Your role cannot perform this action.'});}
function requireCsrf(req:Request,res:ExpressResponse,next:NextFunction){const sent=req.get('x-csrf-token')||'';if(!req.session.csrf||!safeEqual(sent,req.session.csrf))return res.status(403).json({error:'CSRF validation failed.'});next();}
function audit(req:Request,action:string,result:string,connectionId?:string,conversationId?:string,recordingId?:string,detail:Record<string,unknown>={}){const u=req.session.user;const address=req.ip||'';const ip=address.includes(':')?address.split(':').slice(0,4).join(':')+'::/64':address.split('.').slice(0,3).join('.')+'.0/24';db.prepare('INSERT INTO audit_logs(user_id,username,action,result,connection_id,conversation_id,recording_id,source_ip,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(u?.id||null,u?.username||'anonymous',action,result,connectionId||null,conversationId||null,recordingId||null,ip,JSON.stringify(detail),new Date().toISOString());}
function getAuditRetentionDays(){const row=db.prepare("SELECT value_json FROM application_settings WHERE key='audit_retention_days'").get() as {value_json:string}|undefined;if(!row)return 35;try{const days=JSON.parse(row.value_json);return Number.isInteger(days)&&days>=1&&days<=3650?days:35;}catch{return 35;}}
function purgeExpiredAuditLogs(){const cutoff=new Date(Date.now()-getAuditRetentionDays()*86400000).toISOString();return Number(db.prepare('DELETE FROM audit_logs WHERE created_at<?').run(cutoff).changes);}
function escapeLike(value:string){return value.replace(/[\\%_]/g,'\\$&');}
function redactSensitiveMetadata(value:any):any{if(Array.isArray(value))return value.map(redactSensitiveMetadata);if(value&&typeof value==='object'){const safe:Record<string,unknown>={};for(const [key,item] of Object.entries(value)){if(/token|secret|authorization|mediaUri|signed|url/i.test(key))safe[key]='[REDACTED]';else safe[key]=redactSensitiveMetadata(item);}return safe;}return value;}
async function mapWrapUpNames(client:GenesysClient,conversation:any){const ids=collectWrapUpCodeIds(conversation);if(!ids.length)return conversation;const entries=await mapWithConcurrency(ids,4,async id=>{try{const code=await client.get<{id?:string;name?:string}>(`/api/v2/routing/wrapupcodes/${encodeURIComponent(id)}`);return [id,typeof code?.name==='string'&&code.name.trim()?code.name:undefined] as const;}catch(error){if(error instanceof GenesysError&&[403,404].includes(error.status))return [id,undefined] as const;throw error;}});return withWrapUpCodeNames(conversation,Object.fromEntries(entries.filter((entry):entry is readonly [string,string]=>Boolean(entry[1]))));}
function publicError(error:unknown){if(error instanceof Error)return error.message.slice(0,200);return 'Connection test failed.';}
function httpError(status:number,message:string){return Object.assign(new Error(message),{status});}
function errorHandler(error:unknown,_req:Request,res:ExpressResponse,_next:NextFunction){const status=Number((error as any)?.status)|| (error instanceof z.ZodError?400:500);if(status===500)console.error('Request failed:',error);res.status(status).json({error:status===500?'Request failed. Check server logs using the correlation time.':publicError(error),...(error instanceof z.ZodError?{issues:error.issues.map(i=>({path:i.path,message:i.message}))}:{})});}
function mockMatches(c:any,input:z.infer<typeof searchSchema>){return matchesConversationFilters(c,input);}
function matchesConversationFilters(c:any,input:z.infer<typeof searchSchema>){const all=c.participants||[];if(input.agentId&&!all.some((p:any)=>p.userId===input.agentId))return false;if(input.queueId&&!all.some((p:any)=>p.sessions?.some((s:any)=>s.queueId===input.queueId)))return false;if(input.direction&&c.originatingDirection!==input.direction)return false;if(input.phone&&!JSON.stringify(all).includes(input.phone))return false;if(input.dnis&&!JSON.stringify(all).includes(input.dnis))return false;return true;}
function matchesPhone(c:any,input:z.infer<typeof searchSchema>){return (!input.phone||JSON.stringify(c).includes(input.phone))&&(!input.dnis||JSON.stringify(c).includes(input.dnis));}
function summarize(c:any){const participants=c.participants||[],agents=new Set<string>(),flows=new Set<string>(),queues=new Set<string>();let phone='',dnis='',wrapUp='';for(const p of participants){if(p.purpose==='agent')agents.add(p.participantName||p.userId||'Agent');if(p.purpose==='ivr'||p.purpose==='flow')flows.add(p.sessions?.[0]?.flowName||p.participantName||'IVR flow');for(const s of p.sessions||[]){phone ||= s.ani||'';dnis ||= s.dnis||'';if(s.queueName)queues.add(s.queueName);for(const seg of s.segments||[])if(seg.wrapUpCode)wrapUp=seg.wrapUpCode;}}const hasBot=flows.size>0;return {conversationId:c.conversationId,conversationStart:c.conversationStart,conversationEnd:c.conversationEnd,direction:c.originatingDirection||'unknown',ani:phone,dnis,agents:[...agents],flows:[...flows],queues:[...queues],wrapUp,durationSeconds:c.conversationStart&&c.conversationEnd?Math.round((Date.parse(c.conversationEnd)-Date.parse(c.conversationStart))/1000):null,interactionType:agents.size&&hasBot?'Bot to Agent':agents.size>1?'Multi-Agent':agents.size?'Human Agent':hasBot?'Bot Only':'Unknown'};}
function validateMediaUrl(value:string,connection:Connection){try{return validateRecordingMediaUrl(value,connection);}catch(error){throw httpError(502,error instanceof Error?error.message:'Genesys returned an invalid recording media URL.');}}
async function pipeMedia(_req:Request,res:ExpressResponse,response:globalThis.Response,options:{allowZip?:boolean}={}){if(!response.ok&&response.status!==206){throw httpError(response.status===403?410:502,response.status===403?'Recording media URL has expired. Retry playback to obtain a fresh URL.':'Recording media could not be retrieved.');}const type=response.headers.get('content-type')||'';if(isZipMediaContentType(type)&&!options.allowZip){await response.body?.cancel().catch(()=>{});throw httpError(409,'Genesys returned a ZIP message recording archive, not playable audio. This recording cannot play in the audio player; use Download to retrieve the archive.');}if(!/^audio\//i.test(type)&&!/^video\/webm/i.test(type)&&!/^application\/octet-stream/i.test(type)&&!(options.allowZip&&isZipMediaContentType(type)))throw httpError(502,'Genesys returned an unsupported media content type.');res.status(response.status);res.setHeader('Content-Type',type);res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('Accept-Ranges',response.headers.get('accept-ranges')||'bytes');const length=response.headers.get('content-length'),range=response.headers.get('content-range');if(length)res.setHeader('Content-Length',length);if(range)res.setHeader('Content-Range',range);if(!response.body)throw httpError(502,'Recording media response was empty.');const stream=Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);const onClose=()=>{if(!res.writableEnded)stream.destroy(new Error('Downstream playback client disconnected.'));};res.once('close',onClose);try{await new Promise<void>((resolve,reject)=>{stream.once('error',reject);res.once('error',reject);res.once('finish',resolve);stream.pipe(res);});}finally{res.off('close',onClose);}}
async function readBoundedBody(response:globalThis.Response,limit:number):Promise<Buffer>{if(!response.ok){await response.body?.cancel().catch(()=>{});throw httpError(response.status===403?410:502,'Recording media could not be retrieved.');}const declared=Number(response.headers.get('content-length')||0);if(declared>limit){await response.body?.cancel().catch(()=>{});throw httpError(413,'Recording ZIP archive exceeds the safe playback size limit.');}if(!response.body)throw httpError(502,'Recording media response was empty.');const reader=response.body.getReader(),chunks:Buffer[]=[];let total=0;try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>limit){await reader.cancel();throw httpError(413,'Recording ZIP archive exceeds the safe playback size limit.');}chunks.push(Buffer.from(value));}}finally{reader.releaseLock();}return Buffer.concat(chunks,total);}
function serveAudioBuffer(req:Request,res:ExpressResponse,audio:Buffer,mimeType:string){const match=/^bytes=(\d*)-(\d*)$/.exec(req.headers.range||'');let start=0,end=audio.length-1;if(match){if(!match[1]&&!match[2])throw httpError(416,'Requested audio range is invalid.');if(!match[1]){const suffix=Number(match[2]);if(!Number.isSafeInteger(suffix)||suffix<=0)throw httpError(416,'Requested audio range is invalid.');start=Math.max(0,audio.length-suffix);}else{start=Number(match[1]);if(match[2])end=Number(match[2]);}if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||start>=audio.length||end<start){res.status(416).setHeader('Content-Range',`bytes */${audio.length}`).end();return;}end=Math.min(end,audio.length-1);}res.status(match?206:200);res.setHeader('Content-Type',mimeType);res.setHeader('Content-Length',String(end-start+1));res.setHeader('Accept-Ranges','bytes');if(match)res.setHeader('Content-Range',`bytes ${start}-${end}/${audio.length}`);res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('X-Content-Type-Options','nosniff');res.end(audio.subarray(start,end+1));}
function safeRecording(r:any,conversation?:any){const mediaUris=r.mediaUris,mediaUriAvailable=(Array.isArray(mediaUris)&&mediaUris.some((entry:any)=>typeof entry?.mediaUri==='string'&&entry.mediaUri))||(mediaUris&&typeof mediaUris==='object'&&!Array.isArray(mediaUris)&&Object.values(mediaUris).some((entry:any)=>typeof entry?.mediaUri==='string'&&entry.mediaUri))||typeof r.mediaUri==='string'&&r.mediaUri,mediaType=r.mediaType||(r.media==='audio'&&conversationHasVoiceSession(conversation)?'voice':undefined);return {id:r.id||r.recordingId,startTime:r.startTime||r.recordingStartTime,endTime:r.endTime||r.recordingEndTime,status:r.status||r.recordingState||r.fileState||'UNKNOWN',media:r.media,mediaType,durationMs:r.durationMs||r.outputDurationMs,hasMedia:Boolean(mediaUriAvailable)};}
async function fetchTrustedMedia(value:string,connection:Connection,headers:Record<string,string>){let url=validateMediaUrl(value,connection);for(let redirects=0;redirects<=2;redirects++){let response:globalThis.Response;try{response=await fetch(url,{headers,signal:AbortSignal.timeout(30000),redirect:'manual'});}catch{throw httpError(502,'Recording media could not be reached. Retry playback.');}if(response.status<300||response.status>=400)return response;const location=response.headers.get('location');if(!location)throw httpError(502,'Recording media redirect was invalid.');if(redirects===2)throw httpError(502,'Recording media returned too many redirects.');let next:URL;try{next=new URL(location,url);}catch{throw httpError(502,'Recording media redirect was invalid.');}url=validateMediaUrl(next.toString(),connection);}throw httpError(502,'Recording media redirect was invalid.');}
async function mapWithConcurrency<T,R>(items:T[],limit:number,work:(item:T)=>Promise<R>):Promise<R[]>{const output=new Array<R>(items.length);let cursor=0;async function worker(){while(true){const index=cursor++;if(index>=items.length)return;output[index]=await work(items[index]);}}await Promise.all(Array.from({length:Math.min(limit,items.length)},worker));return output;}
function rejectCrossOrigin(req:Request,res:ExpressResponse,next:NextFunction){const origin=req.get('origin'),fetchSite=req.get('sec-fetch-site');if(fetchSite==='cross-site')return res.status(403).json({error:'Cross-site API requests are not allowed.'});if(origin){try{const expected=new URL(process.env.APP_ORIGIN||'http://localhost:5173').origin;if(new URL(origin).origin!==expected)return res.status(403).json({error:'Request origin is not allowed.'});}catch{return res.status(403).json({error:'Request origin is not allowed.'});}}next();}
function revokeUserSessions(userId:string){const rows=db.prepare('SELECT sid,sess FROM sessions').all() as {sid:string;sess:string}[];const remove=db.prepare('DELETE FROM sessions WHERE sid=?');for(const row of rows){try{if(JSON.parse(row.sess)?.user?.id===userId)remove.run(row.sid);}catch{remove.run(row.sid);}}}
function validateProductionConfig(){if(process.env.NODE_ENV!=='production')return;let origin:URL;try{origin=new URL(process.env.APP_ORIGIN||'');}catch{throw new Error('APP_ORIGIN must be set to the public HTTPS application origin in production.');}if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new Error('APP_ORIGIN must be a bare HTTPS origin in production.');if((process.env.SESSION_SECRET||'').length<48||/replace|change.?me|example|development/i.test(process.env.SESSION_SECRET||''))throw new Error('Set a unique production SESSION_SECRET with at least 48 characters.');if(process.env.MOCK_MODE!=='false')throw new Error('Set MOCK_MODE=false explicitly for authorized production use.');const key=process.env.MASTER_ENCRYPTION_KEY||'';if(Buffer.from(key,'base64').length!==32||Buffer.from(key,'base64').toString('base64').replace(/=+$/,'')!==key.replace(/=+$/,''))throw new Error('MASTER_ENCRYPTION_KEY must be a base64-encoded 32-byte key in production.');if(process.env.TRUST_PROXY!=='true')throw new Error('Set TRUST_PROXY=true only when the app is reachable solely through one trusted HTTPS reverse proxy.');}
function regenerate(req:Request){return new Promise<void>((resolve,reject)=>req.session.regenerate(error=>error?reject(error):resolve()));}
app.use(errorHandler);
if(process.env.NODE_ENV==='production'){const fs=await import('node:fs');const path=await import('node:path');const root=path.resolve('dist');app.use(express.static(root));app.get(/^(?!\/api\/).*/,(_req,res)=>res.sendFile(path.join(root,'index.html')));}
const server=app.listen(port,host,()=>console.log(`MFEC Recording Explorer API listening on ${host}:${port} (${process.env.MOCK_MODE==='true'?'Mock Mode':'Genesys mode'})`));
function shutdown(){server.close(()=>{try{sessionStore.close();db.close();}finally{process.exit(0);}});}
shutdownServer=shutdown;
process.once('SIGTERM',shutdown);
process.once('SIGINT',shutdown);
