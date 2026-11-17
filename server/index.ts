import 'dotenv/config';
import express, { type Request, type Response as ExpressResponse, type NextFunction } from 'express';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { z } from 'zod';
import { db, migrate } from './db/index.js';
import { BetterSqliteSessionStore } from './session-store.js';
import { encrypt, safeEqual } from './security.js';
import { REGIONS, trustedBaseUrl } from './regions.js';
import { connectionById, GenesysClient, GenesysError, type Connection } from './genesys.js';
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
    const input = z.object({ currentPassword: z.string().min(1).max(1024), newPassword: z.string().min(14).max(256) }).parse(req.body);
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

app.get('/api/genesys/regions', requireAuth, (_req, res) => res.json({ regions: REGIONS }));
app.get('/api/genesys/connections', requireAuth, (req, res) => {
  const rows = req.session.user!.role === 'administrator'
    ? (process.env.MOCK_MODE === 'true' ? [] : db.prepare("SELECT id,name,organization_label,region_id,enabled,is_default,last_success_at,CASE WHEN last_error IS NULL THEN NULL ELSE 'Connection check failed. Review administrator logs.' END AS last_error,client_id,CASE WHEN client_secret_enc='' THEN 0 ELSE 1 END AS secret_configured FROM connections ORDER BY name").all())
    : (process.env.MOCK_MODE === 'true' ? [] : db.prepare('SELECT c.id,c.name,c.organization_label,c.region_id,c.enabled,c.is_default,c.last_success_at,c.last_error,c.client_id,1 AS secret_configured FROM connections c JOIN user_connection_access a ON a.connection_id=c.id WHERE a.user_id=? AND c.enabled=1 ORDER BY c.name').all(req.session.user!.id));
  const values = process.env.MOCK_MODE === 'true' ? [{ id: 'mock', name: 'Synthetic Demo Organization', organization_label: 'Mock Mode · Synthetic data', region_id: 'ap-southeast-1', enabled: 1, is_default: 1, last_success_at: null, last_error: null, client_id: '', secret_configured: 0, mock: true }] : [];
  const validRows=(rows as any[]).filter(connection=>REGIONS.some(region=>region.id===connection.region_id&&region.api===connection.api_base_url&&region.oauth===connection.oauth_base_url));
  res.json({ connections: [...values, ...validRows] });
});
app.post('/api/genesys/connections', requireAuth, requireAdmin, requireCsrf, (req, res, next) => {
  try {
    const input = connectionSchema.parse(req.body);
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Disable Mock Mode and restart the application before saving live Genesys credentials.');
    const region = REGIONS.find(r => r.id === input.regionId); if (!region) throw httpError(400, 'Unknown Genesys region.');
    let apiUrl:string,oauthUrl:string;try{apiUrl=trustedBaseUrl(input.apiBaseUrl || region.api, 'api');oauthUrl=trustedBaseUrl(input.oauthBaseUrl || region.oauth, 'oauth');}catch{throw httpError(400,'The endpoint must exactly match an official Genesys Cloud region URL.');}
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
    if(!REGIONS.some(value=>value.id===existing.region_id&&value.api===existing.api_base_url&&value.oauth===existing.oauth_base_url))throw httpError(409,'The stored connection endpoints are not trusted. Remove and recreate this connection with an official region.');
    const input = connectionSchema.partial({ clientSecret: true }).parse(req.body);
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Disable Mock Mode and restart the application before updating live Genesys credentials.');
    const region = REGIONS.find(r => r.id === (input.regionId || existing.region_id)); if (!region) throw httpError(400,'Unknown Genesys region.');
    let apiUrl:string,oauthUrl:string;try{apiUrl=trustedBaseUrl(input.apiBaseUrl || region.api,'api');oauthUrl=trustedBaseUrl(input.oauthBaseUrl || region.oauth,'oauth');}catch{throw httpError(400,'The endpoint must exactly match an official Genesys Cloud region URL.');}
    if(apiUrl!==region.api||oauthUrl!==region.oauth)throw httpError(400,'API and OAuth base URLs must match the selected official region.');
    const nextEnabled=Boolean(input.enabled ?? Boolean(existing.enabled));
    const nextClientId=input.clientId ?? existing.client_id;
    const nextSecret=input.clientSecret ? encrypt(input.clientSecret) : existing.client_secret_enc;
    const nextDefault=Boolean(input.isDefault ?? Boolean(existing.is_default));
    const regionChanged=(input.regionId||existing.region_id)!==existing.region_id;
    const clientChanged=(input.clientId&&input.clientId!==existing.client_id)||Boolean(input.clientSecret);
    const transaction=db.transaction(()=>{if(nextDefault)db.prepare('UPDATE connections SET is_default=0').run();db.prepare('UPDATE connections SET name=?,organization_label=?,region_id=?,api_base_url=?,oauth_base_url=?,client_id=?,client_secret_enc=?,enabled=?,is_default=?,updated_at=?,last_error=NULL WHERE id=?').run(input.name ?? existing.name,input.organizationLabel ?? existing.organization_label,input.regionId ?? existing.region_id,apiUrl,oauthUrl,nextClientId,nextSecret,Number(nextEnabled),Number(nextDefault),new Date().toISOString(),existing.id);if(!nextEnabled||regionChanged||clientChanged)db.prepare('DELETE FROM user_connection_access WHERE connection_id=?').run(existing.id);});transaction();
    audit(req,'CONNECTION_UPDATE','SUCCESS',existing.id); res.json({ ok:true });
  } catch(error) { next(error); }
});
app.delete('/api/genesys/connections/:id', requireAuth, requireAdmin, requireCsrf, (req,res,next) => {
    try { const id=String(req.params.id);if(!db.prepare('SELECT id FROM connections WHERE id=?').get(id))throw httpError(404,'Connection not found.');if(process.env.MOCK_MODE==='true')throw httpError(409,'Disable Mock Mode and restart the application before changing live connections.');db.prepare('DELETE FROM connections WHERE id=?').run(id); audit(req,'CONNECTION_DELETE','SUCCESS',id); res.status(204).end(); }
  catch(error) { next(error); }
});
app.post('/api/genesys/connections/:id/test', requireAuth, requireAdmin, requireCsrf, async (req,res,next) => {
  try {
    if(process.env.MOCK_MODE==='true')throw httpError(409,'Mock Mode is active. Live Genesys connectivity tests are disabled.');
    const id=String(req.params.id); const connection = db.prepare('SELECT * FROM connections WHERE id=?').get(id) as Connection | undefined;
    if (!connection) throw httpError(404,'Connection not found.');
    if(!connection.enabled)throw httpError(409,'Enable the connection before testing it.');
    if(!REGIONS.some(value=>value.id===connection.region_id&&value.api===connection.api_base_url&&value.oauth===connection.oauth_base_url))throw httpError(409,'The connection endpoints are not trusted.');
    const client = new GenesysClient(connection); await client.accessToken();
    const now = new Date().toISOString(); db.prepare('UPDATE connections SET last_success_at=?,last_error=NULL WHERE id=?').run(now,connection.id);
    audit(req,'CONNECTION_TEST','SUCCESS',connection.id); res.json({ ok:true,message:'OAuth authentication succeeded.' });
  } catch(error) { const safe = publicError(error); const id=String(req.params.id); if(id) db.prepare('UPDATE connections SET last_error=? WHERE id=?').run(safe,id); audit(req,'CONNECTION_TEST','FAILED',id); next(error); }
});
app.get('/api/genesys/connections/:id/permissions', requireAuth, requireAdmin, (req,res,next) => {
  try { if(process.env.MOCK_MODE==='true')throw httpError(409,'Mock Mode is active. No live Genesys permissions are configured.');connectionById(String(req.params.id),req.session.user!.id,req.session.user!.role); res.json({ permissions:[{ name:'analytics:conversationDetail:view', purpose:'Search conversation details'},{name:'recording:recording:view', purpose:'Discover and play recordings'}], verified:false, note:'Permission availability must be verified against the configured Genesys organization; this screen does not infer delegated user permissions.' }); }
  catch(error) { next(error); }
});
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>{
  const users=db.prepare('SELECT id,username,role,enabled,created_at AS createdAt FROM users ORDER BY username').all() as {id:string;username:string;role:string;enabled:number;createdAt:string}[];
  const grants=db.prepare('SELECT user_id AS userId,connection_id AS connectionId FROM user_connection_access').all() as {userId:string;connectionId:string}[];
  res.json({users:users.map(user=>({...user,connections:grants.filter(grant=>grant.userId===user.id).map(grant=>grant.connectionId)}))});
});
app.post('/api/admin/users',requireAuth,requireAdmin,requireCsrf,async(req,res,next)=>{
  try { const input=z.object({username:z.string().trim().min(2).max(128).regex(/^[\p{L}\p{N}._@-]+$/u),password:z.string().min(14).max(256),role:z.enum(['administrator','supervisor','quality_analyst','viewer']),connectionIds:z.array(z.string()).max(100).default([])}).parse(req.body); for(const connectionId of input.connectionIds)if(!db.prepare('SELECT id FROM connections WHERE id=? AND enabled=1').get(connectionId))throw httpError(400,'An enabled organization connection is required.'); const id=crypto.randomUUID();
    const transaction=db.transaction(()=>{db.prepare('INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)').run(id,input.username,awaitHash(input.password),input.role,new Date().toISOString());const grant=db.prepare('INSERT INTO user_connection_access(user_id,connection_id) VALUES(?,?)');for(const connectionId of input.connectionIds)grant.run(id,connectionId);}); transaction(); audit(req,'USER_CREATE','SUCCESS'); res.status(201).json({id,username:input.username});
  } catch(error){next(error);}
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

app.post('/api/recordings/search', requireAuth, requireCsrf, rateLimit({windowMs:60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false}), async (req,res,next) => {
  try {
    const input = searchSchema.parse(req.body); const user = req.session.user!;
    const connection = input.connectionId === 'mock' ? null : connectionById(input.connectionId,user.id,user.role);
    if (!connection && !(input.connectionId === 'mock' && process.env.MOCK_MODE === 'true')) throw httpError(404,'Connection not found or access denied.');
    const from = Date.parse(input.intervalStart), to = Date.parse(input.intervalEnd);
    if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) throw httpError(400,'Choose a valid start and end time.');
    if (to - from > 7 * 86400000) throw httpError(400,'A single Genesys conversation-details query is limited to seven days. Narrow the interval; asynchronous search is not available in this release.');
    const client = connection ? new GenesysClient(connection) : null;
    let conversations: any[] = [], totalHits: number | null = null, partial = false;
    if (!client) {
      conversations = MOCK_CONVERSATIONS.filter(c => Date.parse(c.conversationStart) >= from && Date.parse(c.conversationStart) <= to && mockMatches(c,input) && (!input.conversationId||c.conversationId===input.conversationId));
      totalHits = conversations.length;
    } else {
      if(input.conversationId) {
        const conversation=await client.get<any>(`/api/v2/analytics/conversations/${encodeURIComponent(input.conversationId)}/details`);
        conversations=conversation?.conversationId===input.conversationId && Date.parse(conversation.conversationStart)>=from && Date.parse(conversation.conversationStart)<=to && matchesConversationFilters(conversation,input) ? [conversation] : [];
        totalHits=conversations.length;
      } else {
        const body: Record<string,unknown> = { interval: `${new Date(from).toISOString()}/${new Date(to).toISOString()}`, paging:{ pageSize:input.pageSize,pageNumber:input.pageNumber }, order:'desc', orderBy:'conversationStart' };
        const segmentPredicates: any[] = [];
        if(input.agentId) segmentPredicates.push({type:'dimension',dimension:'userId',operator:'matches',value:input.agentId});
        if(input.queueId) segmentPredicates.push({type:'dimension',dimension:'queueId',operator:'matches',value:input.queueId});
        if(input.direction) body.conversationFilters=[{type:'and',predicates:[{type:'dimension',dimension:'originatingDirection',operator:'matches',value:input.direction}]}];
        if(segmentPredicates.length) body.segmentFilters=[{type:'and',predicates:segmentPredicates}];
        const response = await client.post<{conversations?:any[];totalHits?:number;totalCount?:number;nextUri?:string}>('/api/v2/analytics/conversations/details/query',body);
        conversations = response.conversations || []; totalHits = response.totalHits ?? response.totalCount ?? null;
      }
      // ANI/DNIS are deliberately post-filtered on the current native page: Genesys analytics does not provide a documented universally available ANI/DNIS filter in this path.
      if(input.phone || input.dnis) { conversations = conversations.filter(c=>matchesPhone(c,input)); partial = true; }
    }
    const enriched = await mapWithConcurrency(conversations,5,async c => {
      let recordings: any[] = [];
      try {
        if(client) recordings = await client.get<any[]>(`/api/v2/conversations/${encodeURIComponent(c.conversationId)}/recordings`);
        else recordings = (MOCK_RECORDINGS[c.conversationId] as any[]) || [];
      } catch (error) { if(error instanceof GenesysError && error.status === 404) recordings=[]; else throw error; }
      return { ...summarize(c), recordingCount:recordings.length, recordings:recordings.map(safeRecording) };
    });
    audit(req,'SEARCH','SUCCESS',connection?.id || 'mock',undefined,undefined,{page:input.pageNumber});
    res.json({ results:enriched, page:input.pageNumber,pageSize:input.pageSize,totalHits,partial,scope:partial?'Genesys page filtered by ANI/DNIS after retrieval; this is not a complete phone search.':'Native Genesys detail query; result count depends on API response/permissions.', mock:!client });
  } catch(error) { audit(req,'SEARCH','FAILED'); next(error); }
});
app.get('/api/recordings/conversations/:conversationId', requireAuth, async (req,res,next) => {
  try { const conversationId=String(req.params.conversationId);if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.');if(String(req.query.connectionId||'')==='mock'&&process.env.MOCK_MODE==='true'){const mock=MOCK_CONVERSATIONS.find(item=>item.conversationId===conversationId);return mock?res.json(mock):res.status(404).json({error:'Conversation not found.'});}const connection = connectionById(String(req.query.connectionId||''),req.session.user!.id,req.session.user!.role); const client = new GenesysClient(connection); const conversation = await client.get(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`); audit(req,'DETAILS_VIEW','SUCCESS',connection.id,conversationId); res.json(conversation); }
  catch(error) { next(error); }
});
app.get('/api/recordings/conversations/:conversationId/recordings', requireAuth, async (req,res,next) => {
  try { const id=String(req.query.connectionId||''),conversationId=String(req.params.conversationId);if(!conversationId||conversationId.length>128)throw httpError(400,'A valid conversation ID is required.'); if(id==='mock'&&process.env.MOCK_MODE==='true') return res.json((MOCK_RECORDINGS[conversationId]||[]).map(safeRecording)); const c=connectionById(id,req.session.user!.id,req.session.user!.role); const items=await new GenesysClient(c).get<any[]>(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings`); res.json(items.map(safeRecording)); }
  catch(error) { next(error); }
});
app.get('/api/recordings/:recordingId/metadata', requireAuth, async (req,res,next) => {
  try { const cId=String(req.query.connectionId||''), conversationId=String(req.query.conversationId||''),recordingId=String(req.params.recordingId);if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.'); if(cId==='mock'&&process.env.MOCK_MODE==='true') { const r=(MOCK_RECORDINGS[conversationId] as any[]||[]).find(x=>x.id===recordingId); return r?res.json(safeRecording(r)):res.status(404).json({error:'Recording not found.'}); } const c=connectionById(cId,req.session.user!.id,req.session.user!.role); const item=await new GenesysClient(c).get<any>(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings/${encodeURIComponent(recordingId)}`); audit(req,'RECORDING_METADATA_VIEW','SUCCESS',c.id,conversationId,recordingId); res.json(safeRecording(item)); }
  catch(error) { next(error); }
});
app.get('/api/recordings/:recordingId/stream', requireAuth, async (req,res,next) => {
  try {
    const cId=String(req.query.connectionId||''), conversationId=String(req.query.conversationId||'');
    if(!conversationId||conversationId.length>128||String(req.params.recordingId).length>128)throw httpError(400,'Valid conversation and recording IDs are required.');
    if(cId==='mock'&&process.env.MOCK_MODE==='true') return res.status(501).json({error:'Synthetic demo recordings include metadata only; real audio playback requires an authorized Genesys recording.'});
    const c=connectionById(cId,req.session.user!.id,req.session.user!.role); const client=new GenesysClient(c);
    const recordingId=String(req.params.recordingId); const metadata=await client.get<any>(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings/${encodeURIComponent(recordingId)}`);
    const uri=recordingMediaUri(metadata);
    if(typeof uri!=='string') throw httpError(409,'Genesys has not returned a playable media URL for this recording yet.');
    const headers: Record<string,string>={}; if(req.headers.range) headers.Range=req.headers.range;
    audit(req,'PLAYBACK','SUCCESS',c.id,conversationId,recordingId);
    const media=await fetchTrustedMedia(uri,c,headers); await pipeMedia(req,res,media);
  } catch(error) { if(!res.headersSent){audit(req,'PLAYBACK','FAILED',undefined,String(req.query.conversationId||''),String(req.params.recordingId||''));next(error);} }
});
app.get('/api/recordings/:recordingId/download', requireAuth, requireRole('administrator','supervisor','quality_analyst'), async (req,res,next) => {
  let connection:Connection|undefined,conversationId='',recordingId='';
  try { conversationId=String(req.query.conversationId||'');recordingId=String(req.params.recordingId);if(!conversationId||conversationId.length>128||!recordingId||recordingId.length>128)throw httpError(400,'Valid conversation and recording IDs are required.');connection=connectionById(String(req.query.connectionId||''),req.session.user!.id,req.session.user!.role);const metadata=await new GenesysClient(connection).get<any>(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings/${encodeURIComponent(recordingId)}`);const uri=recordingMediaUri(metadata);if(!uri)throw httpError(409,'No downloadable media is available.');audit(req,'DOWNLOAD','SUCCESS',connection.id,conversationId,recordingId);res.setHeader('Content-Disposition',`attachment; filename="recording-${recordingId.replace(/[^a-zA-Z0-9_-]/g,'_')}"`);const response=await fetchTrustedMedia(uri,connection,{});await pipeMedia(req,res,response);}
  catch(error) { audit(req,'DOWNLOAD','FAILED',connection?.id,conversationId||undefined,recordingId||undefined);next(error); }
});
app.get('/api/dashboard/summary', requireAuth, (_req,res) => res.json({ available:false, note:'Dashboard metrics are not calculated from a complete organization-wide query yet. Run a bounded search to review authorized results.', mock:process.env.MOCK_MODE==='true' }));
app.get('/api/audit', requireAuth, requireRole('administrator'), (req,res) => { const page=Math.max(1,Math.min(100000,Number(req.query.page)||1)); const rows=db.prepare('SELECT id,username,action,result,connection_id AS connectionId,conversation_id AS conversationId,recording_id AS recordingId,source_ip AS sourceIp,created_at AS createdAt FROM audit_logs ORDER BY created_at DESC LIMIT 100 OFFSET ?').all((page-1)*100); res.json({logs:rows,page}); });
app.post('/api/audit/list-export',requireAuth,requireRole('administrator'),requireCsrf,(req,res,next)=>{try{const input=z.object({rows:z.number().int().min(0).max(100)}).parse(req.body);audit(req,'AUDIT_LOG_EXPORT','SUCCESS',undefined,undefined,undefined,{rows:input.rows});res.json({ok:true});}catch(error){next(error);}});
app.post('/api/audit/export',requireAuth,requireCsrf,(req,res,next)=>{try{const input=z.object({exportType:z.enum(['search-results','audit-log']),connectionId:z.string().optional(),rows:z.number().int().min(0).max(10000)}).parse(req.body);if(input.exportType==='audit-log'){if(req.session.user!.role!=='administrator')throw httpError(403,'Administrator role required to export audit logs.');}else{if(!input.connectionId)throw httpError(400,'Connection is required for a search-result export.');if(input.connectionId!=='mock')connectionById(input.connectionId,req.session.user!.id,req.session.user!.role);}audit(req,input.exportType==='audit-log'?'AUDIT_LOG_EXPORT':'METADATA_EXPORT','SUCCESS',input.connectionId||undefined,undefined,undefined,{rows:input.rows,exportType:input.exportType});res.json({ok:true});}catch(error){next(error);}});

function bootstrapUser() {
  const username=process.env.INITIAL_ADMIN_USERNAME, password=process.env.INITIAL_ADMIN_PASSWORD;
  if(!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
    if(!username||!password) { if(process.env.NODE_ENV==='production') throw new Error('Set INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD for first production startup.'); return; }
    if(password.length<14) throw new Error('INITIAL_ADMIN_PASSWORD must be at least 14 characters.');
    const normalized=username.trim();if(!/^[\p{L}\p{N}._@-]{2,128}$/u.test(normalized))throw new Error('INITIAL_ADMIN_USERNAME contains unsupported characters.');
    db.prepare('INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)').run(crypto.randomUUID(),normalized,bcrypt.hashSync(password,12),'administrator',new Date().toISOString());
    console.warn(`Initial administrator "${username}" created. Change the password after first login.`);
  }
  delete process.env.INITIAL_ADMIN_PASSWORD;
}
function awaitHash(password:string){return bcrypt.hashSync(password,12);}
const connectionSchema=z.object({name:z.string().trim().min(1).max(120),organizationLabel:z.string().trim().min(1).max(120),regionId:z.string().min(1).max(64),apiBaseUrl:z.string().url().optional(),oauthBaseUrl:z.string().url().optional(),clientId:z.string().trim().min(1).max(256),clientSecret:z.string().min(1).max(1024),enabled:z.boolean().default(true),isDefault:z.boolean().default(false)});
const searchSchema=z.object({connectionId:z.string().min(1),intervalStart:z.string().datetime({offset:true}),intervalEnd:z.string().datetime({offset:true}),pageNumber:z.number().int().min(1).default(1),pageSize:z.number().int().min(1).max(100).default(25),agentId:z.string().optional(),queueId:z.string().optional(),direction:z.enum(['inbound','outbound']).optional(),phone:z.string().max(80).optional(),dnis:z.string().max(80).optional(),conversationId:z.string().max(128).optional()});
function requireAuth(req:Request,res:ExpressResponse,next:NextFunction){const sessionUser=req.session.user;if(!sessionUser)return res.status(401).json({error:'Sign in required.'});const account=db.prepare('SELECT username,role,enabled FROM users WHERE id=?').get(sessionUser.id) as {username:string;role:string;enabled:number}|undefined;if(!account||!account.enabled){req.session.destroy(()=>{});return res.status(401).json({error:'Your account is disabled or no longer exists.'});}req.session.user={id:sessionUser.id,username:account.username,role:account.role};next();}
function requireAdmin(req:Request,res:ExpressResponse,next:NextFunction){if(req.session.user?.role!=='administrator')return res.status(403).json({error:'Administrator role required.'});next();}
function requireRole(...roles:string[]){return(req:Request,res:ExpressResponse,next:NextFunction)=>roles.includes(req.session.user?.role||'')?next():res.status(403).json({error:'Your role cannot perform this action.'});}
function requireCsrf(req:Request,res:ExpressResponse,next:NextFunction){const sent=req.get('x-csrf-token')||'';if(!req.session.csrf||!safeEqual(sent,req.session.csrf))return res.status(403).json({error:'CSRF validation failed.'});next();}
function audit(req:Request,action:string,result:string,connectionId?:string,conversationId?:string,recordingId?:string,detail:Record<string,unknown>={}){const u=req.session.user;const address=req.ip||'';const ip=address.includes(':')?address.split(':').slice(0,4).join(':')+'::/64':address.split('.').slice(0,3).join('.')+'.0/24';db.prepare('INSERT INTO audit_logs(user_id,username,action,result,connection_id,conversation_id,recording_id,source_ip,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(u?.id||null,u?.username||'anonymous',action,result,connectionId||null,conversationId||null,recordingId||null,ip,JSON.stringify(detail),new Date().toISOString());}
function publicError(error:unknown){if(error instanceof Error)return error.message.slice(0,200);return 'Connection test failed.';}
function httpError(status:number,message:string){return Object.assign(new Error(message),{status});}
function errorHandler(error:unknown,_req:Request,res:ExpressResponse,_next:NextFunction){const status=Number((error as any)?.status)|| (error instanceof z.ZodError?400:500);if(status===500)console.error('Request failed:',error);res.status(status).json({error:status===500?'Request failed. Check server logs using the correlation time.':publicError(error),...(error instanceof z.ZodError?{issues:error.issues.map(i=>({path:i.path,message:i.message}))}:{})});}
function mockMatches(c:any,input:z.infer<typeof searchSchema>){return matchesConversationFilters(c,input);}
function matchesConversationFilters(c:any,input:z.infer<typeof searchSchema>){const all=c.participants||[];if(input.agentId&&!all.some((p:any)=>p.userId===input.agentId))return false;if(input.queueId&&!all.some((p:any)=>p.sessions?.some((s:any)=>s.queueId===input.queueId)))return false;if(input.direction&&c.originatingDirection!==input.direction)return false;if(input.phone&&!JSON.stringify(all).includes(input.phone))return false;if(input.dnis&&!JSON.stringify(all).includes(input.dnis))return false;return true;}
function matchesPhone(c:any,input:z.infer<typeof searchSchema>){return (!input.phone||JSON.stringify(c).includes(input.phone))&&(!input.dnis||JSON.stringify(c).includes(input.dnis));}
function summarize(c:any){const participants=c.participants||[],agents=new Set<string>(),flows=new Set<string>(),queues=new Set<string>();let phone='',dnis='',wrapUp='';for(const p of participants){if(p.purpose==='agent')agents.add(p.participantName||p.userId||'Agent');if(p.purpose==='ivr'||p.purpose==='flow')flows.add(p.sessions?.[0]?.flowName||p.participantName||'IVR flow');for(const s of p.sessions||[]){phone ||= s.ani||'';dnis ||= s.dnis||'';if(s.queueName)queues.add(s.queueName);for(const seg of s.segments||[])if(seg.wrapUpCode)wrapUp=seg.wrapUpCode;}}const hasBot=flows.size>0;return {conversationId:c.conversationId,conversationStart:c.conversationStart,conversationEnd:c.conversationEnd,direction:c.originatingDirection||'unknown',ani:phone,dnis,agents:[...agents],flows:[...flows],queues:[...queues],wrapUp,durationSeconds:c.conversationStart&&c.conversationEnd?Math.round((Date.parse(c.conversationEnd)-Date.parse(c.conversationStart))/1000):null,interactionType:agents.size&&hasBot?'Bot to Agent':agents.size>1?'Multi-Agent':agents.size?'Human Agent':hasBot?'Bot Only':'Unknown'};}
function safeRecording(r:any){return {id:r.id||r.recordingId,startTime:r.startTime||r.recordingStartTime,endTime:r.endTime||r.recordingEndTime,status:r.status||r.recordingState||'UNKNOWN',media:r.media,mediaType:r.mediaType,durationMs:r.durationMs,hasMedia:Boolean(r.mediaUris||r.mediaUri)};}
function validateMediaUrl(value:string,connection:Connection){const u=new URL(value);const apiHost=new URL(connection.api_base_url).hostname.toLowerCase(),oauthHost=new URL(connection.oauth_base_url).hostname.toLowerCase();const roots=new Set([apiHost.replace(/^api\./,''),oauthHost.replace(/^login\./,'')]);const allowed=new Set([apiHost,oauthHost]);for(const root of roots){allowed.add(`apps.${root}`);allowed.add(`media.${root}`);allowed.add(`downloads.${root}`);}if(u.protocol!=='https:'||!allowed.has(u.hostname.toLowerCase())||u.username||u.password||u.port)throw httpError(502,'Genesys returned a media URL on an untrusted host.');return u;}
async function pipeMedia(_req:Request,res:ExpressResponse,response:globalThis.Response){if(!response.ok&&response.status!==206){throw httpError(response.status===403?410:502,response.status===403?'Recording media URL has expired. Retry playback to obtain a fresh URL.':'Recording media could not be retrieved.');}const type=response.headers.get('content-type')||'';if(!/^audio\//i.test(type)&&!/^application\/octet-stream/i.test(type))throw httpError(502,'Genesys returned an unsupported media content type.');res.status(response.status);res.setHeader('Content-Type',type);res.setHeader('Cache-Control','private, no-store, no-cache, must-revalidate');res.setHeader('Pragma','no-cache');res.setHeader('Accept-Ranges',response.headers.get('accept-ranges')||'bytes');const length=response.headers.get('content-length'),range=response.headers.get('content-range');if(length)res.setHeader('Content-Length',length);if(range)res.setHeader('Content-Range',range);if(!response.body)throw httpError(502,'Recording media response was empty.');const stream=Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);const onClose=()=>{if(!res.writableEnded)stream.destroy(new Error('Downstream playback client disconnected.'));};res.once('close',onClose);try{await new Promise<void>((resolve,reject)=>{stream.once('error',reject);res.once('error',reject);res.once('finish',resolve);stream.pipe(res);});}finally{res.off('close',onClose);}}
async function fetchTrustedMedia(value:string,connection:Connection,headers:Record<string,string>){let url=validateMediaUrl(value,connection);for(let redirects=0;redirects<=2;redirects++){const response=await fetch(url,{headers,signal:AbortSignal.timeout(30000),redirect:'manual'});if(response.status<300||response.status>=400)return response;const location=response.headers.get('location');if(!location)throw httpError(502,'Recording media redirect was invalid.');if(redirects===2)throw httpError(502,'Recording media returned too many redirects.');url=validateMediaUrl(new URL(location,url).toString(),connection);}throw httpError(502,'Recording media redirect was invalid.');}
function recordingMediaUri(metadata:any):string|undefined{const mediaUris=metadata?.mediaUris;if(Array.isArray(mediaUris)){for(const entry of mediaUris){if(typeof entry?.mediaUri==='string')return entry.mediaUri;}}if(mediaUris&&typeof mediaUris==='object'){for(const entry of Object.values(mediaUris) as any[]){if(typeof entry?.mediaUri==='string')return entry.mediaUri;}}return typeof metadata?.mediaUri==='string'?metadata.mediaUri:undefined;}
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
