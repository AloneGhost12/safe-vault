import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cors from 'cors';
import multer from 'multer';
import cloudinary from 'cloudinary';
import path from 'path';
import { fileURLToPath } from 'url';
import morgan from 'morgan';
import { Readable } from 'stream';
import fs from 'fs';
import { MongoClient, ObjectId } from 'mongodb';
dotenv.config();

const serverApp = express();
serverApp.use(cors());
serverApp.use(express.json({ limit: '2mb' }));
serverApp.use(morgan(process.env.LOG_FORMAT || 'dev'));

// Capture unhandled errors
process.on('unhandledRejection', (err) => { console.error('[unhandledRejection]', err); });
process.on('uncaughtException', (err) => { console.error('[uncaughtException]', err); });

// ---------------- User / Key Management (experimental) ----------------
// This implements a transitional server-assisted model while attempting to keep
// the data encryption key (DEK) inaccessible without password OR recovery key.
// For production replace file-store with a database and add rate limiting + email/phone verification.

const USERS_FILE = process.env.USERS_FILE || 'serverUsers.json';
function loadUsers(){
  try { return JSON.parse(fs.readFileSync(USERS_FILE,'utf-8')||'[]'); } catch { return []; }
}
function saveUsers(list){
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(list,null,2)); } catch(e){ console.error('saveUsers failed', e); }
}
function findUser(email){ return loadUsers().find(u=>u.email.toLowerCase()===String(email||'').toLowerCase()); }

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-change';

function b64(buf){ return Buffer.from(buf).toString('base64'); }
function b64d(b){ return Buffer.from(b,'base64'); }

function deriveWrapKey(password, saltB64, iterations){
  return crypto.pbkdf2Sync(password, b64d(saltB64), iterations, 32, 'sha256');
}
function wrapDEK(rawKey32, wrapKey){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, iv);
  const ct = Buffer.concat([cipher.update(rawKey32), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: b64(iv), ct: b64(ct), tag: b64(tag) };
}
function unwrapDEK(wrapped, wrapKey){
  const iv = b64d(wrapped.iv); const ct = b64d(wrapped.ct); const tag = b64d(wrapped.tag);
  const decipher = crypto.createDecipheriv('aes-256-gcm', wrapKey, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt; // Buffer (32 bytes)
}

// POST /api/register { email, phone, password }
serverApp.post('/api/register', async (req,res)=>{
  try {
    const { email, phone, password } = req.body || {};
    if(!email || !phone || !password) return res.status(400).json({ error:'Missing fields' });
    if(findUser(email)) return res.status(409).json({ error:'Email exists' });
    const users = loadUsers();
    const pwHash = await bcrypt.hash(password, 12);
    const phoneHash = await bcrypt.hash(phone, 10);
    const dek = crypto.randomBytes(32);
    const recoveryKey = crypto.randomBytes(32); // shown once
    const kdfSalt = crypto.randomBytes(16); const kdfSaltB64 = b64(kdfSalt);
    const kdfIterations = 310000;
    const wrapKeyPw = deriveWrapKey(password, kdfSaltB64, kdfIterations);
    const wrapKeyRk = crypto.createHash('sha256').update(recoveryKey).digest(); // simple KDF for recovery key
    const wrappedDEK_pw = wrapDEK(dek, wrapKeyPw);
    const wrappedDEK_rk = wrapDEK(dek, wrapKeyRk);
    const user = { email, phoneHash, pwHash, kdfSalt: kdfSaltB64, kdfIterations, wrappedDEK_pw, wrappedDEK_rk, createdAt: Date.now() };
    users.push(user); saveUsers(users);
    res.json({ ok:true, recoveryKey: b64(recoveryKey), kdfSalt: kdfSaltB64, kdfIterations, wrappedDEK_pw });
  } catch(e){ console.error(e); res.status(500).json({ error:'Register failed' }); }
});

// POST /api/login { email, password }
serverApp.post('/api/login', async (req,res)=>{
  try {
    const { email, password } = req.body || {};
    const user = findUser(email);
    if(!user) return res.status(401).json({ error:'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.pwHash);
    if(!ok) return res.status(401).json({ error:'Invalid credentials' });
    const token = jwt.sign({ sub:user.email }, JWT_SECRET, { expiresIn:'12h' });
    res.json({ ok:true, token, kdfSalt: user.kdfSalt, kdfIterations: user.kdfIterations, wrappedDEK_pw: user.wrappedDEK_pw });
  } catch(e){ res.status(500).json({ error:'Login failed' }); }
});

function authMiddleware(req,res,next){
  const h = req.headers.authorization || '';
  const [, token] = h.split(' ');
  if(!token) return res.status(401).json({ error:'No token' });
  try { const payload = jwt.verify(token, JWT_SECRET); req.userEmail = payload.sub; next(); } catch { return res.status(401).json({ error:'Bad token' }); }
}

// POST /api/change-password { currentPassword, newPassword }
serverApp.post('/api/change-password', authMiddleware, async (req,res)=>{
  try {
    const { currentPassword, newPassword } = req.body || {};
    if(!currentPassword || !newPassword) return res.status(400).json({ error:'Missing fields' });
    const users = loadUsers(); const idx = users.findIndex(u=>u.email===req.userEmail);
    if(idx<0) return res.status(404).json({ error:'User missing' });
    const user = users[idx];
    const ok = await bcrypt.compare(currentPassword, user.pwHash);
    if(!ok) return res.status(401).json({ error:'Invalid credentials' });
    // unwrap DEK using current password
    const wrapKeyOld = deriveWrapKey(currentPassword, user.kdfSalt, user.kdfIterations);
    let dek;
    try { dek = unwrapDEK(user.wrappedDEK_pw, wrapKeyOld); } catch { return res.status(500).json({ error:'Unwrap failed' }); }
    // derive new wrap key
    const newPwHash = await bcrypt.hash(newPassword, 12);
    const wrapKeyNew = deriveWrapKey(newPassword, user.kdfSalt, user.kdfIterations);
    const wrappedDEK_pw = wrapDEK(dek, wrapKeyNew);
    users[idx] = { ...user, pwHash: newPwHash, wrappedDEK_pw };
    saveUsers(users);
    res.json({ ok:true });
  } catch(e){ console.error(e); res.status(500).json({ error:'Change failed' }); }
});

// POST /api/forgot/reset { email, phone, recoveryKey, newPassword }
serverApp.post('/api/forgot/reset', async (req,res)=>{
  try {
    const { email, phone, recoveryKey, newPassword } = req.body || {};
    if(!email || !phone || !recoveryKey || !newPassword) return res.status(400).json({ error:'Missing fields' });
    const users = loadUsers(); const idx = users.findIndex(u=>u.email.toLowerCase()===email.toLowerCase());
    if(idx<0) return res.status(404).json({ error:'Not found' });
    const user = users[idx];
    const phoneOk = await bcrypt.compare(phone, user.phoneHash);
    if(!phoneOk) return res.status(401).json({ error:'Mismatch' });
    // unwrap using recovery key
    const rkBuf = Buffer.from(recoveryKey, 'base64');
    const wrapKeyRk = crypto.createHash('sha256').update(rkBuf).digest();
    let dek;
    try { dek = unwrapDEK(user.wrappedDEK_rk, wrapKeyRk); } catch { return res.status(401).json({ error:'Bad recovery key' }); }
    // new password hash + wrap
    const newPwHash = await bcrypt.hash(newPassword, 12);
    const wrapKeyNew = deriveWrapKey(newPassword, user.kdfSalt, user.kdfIterations);
    const wrappedDEK_pw = wrapDEK(dek, wrapKeyNew);
    users[idx] = { ...user, pwHash: newPwHash, wrappedDEK_pw };
    saveUsers(users);
    res.json({ ok:true });
  } catch(e){ console.error(e); res.status(500).json({ error:'Reset failed' }); }
});

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const upload = multer({ storage: multer.memoryStorage() });

// Health check
serverApp.get('/api/health', (_req,res)=> res.json({ ok:true, time: Date.now() }));
// Mongo connection status (augmented below once state tracking added)
serverApp.get('/api/mongo/status', (_req,res)=>{
  res.json({ ok:true, connected: !!filesCol, state: mongoState.state, error: mongoState.error, attempts: mongoState.attempts });
});

// ---------------- MongoDB Setup (replacing Firebase) ----------------
const mongoUri = process.env.MONGODB_URI || null; // set in env
let mongoClient; let filesCol; let activityCol;
const mongoState = { state: 'init', error: null, attempts: 0, nextRetryMs: 0 };
const MAX_ATTEMPTS = 8;
async function initMongo(){
  if(!mongoUri){
    mongoState.state = 'missing-env';
    mongoState.error = 'MONGODB_URI not set';
    console.warn('MONGODB_URI not set; Mongo features disabled');
    return;
  }
  if(mongoState.state === 'connected') return;
  mongoState.state = 'connecting';
  mongoState.error = null;
  mongoState.attempts++;
  try {
    mongoClient = new MongoClient(mongoUri, { maxPoolSize: 5 });
    await mongoClient.connect();
    const dbName = process.env.MONGODB_DB || 'safe_vault';
    const db = mongoClient.db(dbName);
    filesCol = db.collection('files');
    activityCol = db.collection('activity');
    await filesCol.createIndex({ email:1, createdAt:-1 });
    await activityCol.createIndex({ email:1, ts:-1 });
    mongoState.state = 'connected';
    console.log('MongoDB connected');
  } catch(e){
    mongoState.state = 'error';
    mongoState.error = e.message || 'connect failed';
    console.error('Mongo connect failed', e.message);
    if(mongoState.attempts < MAX_ATTEMPTS){
      const delay = Math.min(30000, 1000 * Math.pow(2, mongoState.attempts));
      mongoState.nextRetryMs = Date.now() + delay;
      setTimeout(initMongo, delay);
      console.log(`Retrying Mongo in ${delay}ms (attempt ${mongoState.attempts+1}/${MAX_ATTEMPTS})`);
    } else {
      console.error('Mongo giving up after max attempts');
    }
  }
}
// Kick off initial connect attempt
initMongo();

// List files
serverApp.get('/api/files', async (req,res)=>{
  try {
    if(!filesCol) return res.json({ ok:true, files:[] });
    const email = req.query.email || 'anonymous';
    const docs = await filesCol.find({ email }).sort({ createdAt:-1 }).toArray();
    res.json({ ok:true, files: docs });
  } catch(e){ res.status(500).json({ error:'List failed' }); }
});
// Create file metadata
serverApp.post('/api/files', async (req,res)=>{
  try {
    if(!filesCol) return res.status(503).json({ error:'Storage not ready' });
    const { email='anonymous', name, category, size, date, type, iv, data, mime, cloudinaryId, rawBytes, createdAt } = req.body || {};
    if(!name || !iv || !data) return res.status(400).json({ error:'Missing fields'});
    const doc = { email, name, category, size, date, type, iv, data, mime, cloudinaryId: cloudinaryId||null, rawBytes, createdAt: createdAt||Date.now() };
    const r = await filesCol.insertOne(doc);
    res.json({ ok:true, id: r.insertedId, file: { ...doc, _id: r.insertedId } });
  } catch(e){ res.status(500).json({ error:'Create failed' }); }
});
// Update file (e.g., add cloudinaryId)
serverApp.patch('/api/files/:id', async (req,res)=>{
  try {
    if(!filesCol) return res.status(503).json({ error:'Storage not ready' });
    const { id } = req.params; const patch = req.body || {};
    await filesCol.updateOne({ _id: new ObjectId(id) }, { $set: patch });
    res.json({ ok:true });
  } catch(e){ res.status(500).json({ error:'Update failed' }); }
});
// Delete file
serverApp.delete('/api/files/:id', async (req,res)=>{
  try {
    if(!filesCol) return res.status(503).json({ error:'Storage not ready' });
    const { id } = req.params; await filesCol.deleteOne({ _id: new ObjectId(id) });
    res.json({ ok:true });
  } catch(e){ res.status(500).json({ error:'Delete failed' }); }
});
// Activity log endpoints
serverApp.post('/api/activity', async (req,res)=>{
  try { if(!activityCol) return res.status(503).json({ error:'Activity not ready'}); const entry = { ...(req.body||{}), ts: Date.now() }; await activityCol.insertOne(entry); res.json({ ok:true }); } catch(e){ res.status(500).json({ error:'Act add failed'}); }
});
serverApp.get('/api/activity', async (req,res)=>{
  try { if(!activityCol) return res.json({ ok:true, activity:[] }); const email = req.query.email||'anonymous'; const lim = Math.min(parseInt(req.query.limit)||25, 200); const list = await activityCol.find({ email }).sort({ ts:-1 }).limit(lim).toArray(); res.json({ ok:true, activity:list }); } catch(e){ res.status(500).json({ error:'Act list failed'}); }
});

// Runtime client configuration (avoids rebuild for changing Cloudinary values)
serverApp.get('/api/client-config', (req, res) => {
  res.json({
    cloudName: process.env.CLOUDINARY_CLOUD_NAME || null,
    uploadPreset: process.env.CLOUDINARY_UPLOAD_PRESET || null
  });
});

// Proxy Cloudinary raw uploads
serverApp.post('/api/cloudinary/upload', upload.single('file'), (req, res) => {
  try {
    const { upload_preset, folder, resource_type } = req.body || {};
    if (!req.file) return res.status(400).json({ error: 'Missing file' });

    const opts = {
      upload_preset,
      folder: folder || 'vault',
      resource_type: resource_type || 'raw'
    };

    const uploadStream = cloudinary.v2.uploader.upload_stream(opts, (error, result) => {
      if (error) {
        console.error('[cloudinary.upload_stream]', error);
        return res.status(500).json({ error: error.message });
      }
      res.json(result);
    });

    // Create a readable from buffer and pipe to Cloudinary
    const readable = Readable.from(req.file.buffer);
    readable.on('error', (e) => {
      console.error('[readable.error]', e);
      if (!res.headersSent) res.status(500).json({ error: 'Stream error' });
    });
    readable.pipe(uploadStream);
  } catch (err) {
    console.error('[upload.handler]', err);
    res.status(500).json({ error: err.message });
  }
});

// Cloudinary signature endpoint (for signed uploads if you switch from unsigned)
serverApp.post('/api/cloudinary/signature', (req,res) => {
  const { timestamp = Math.floor(Date.now()/1000), folder = 'vault', public_id } = req.body || {};
  const paramsToSign = { folder, timestamp, ...(public_id ? { public_id } : {}) };
  const sorted = Object.keys(paramsToSign).sort().map(k => `${k}=${paramsToSign[k]}`).join('&');
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!apiSecret) return res.status(500).json({ error: 'Missing CLOUDINARY_API_SECRET' });
  const signature = crypto.createHash('sha1').update(sorted + apiSecret).digest('hex');
  res.json({ signature, timestamp, folder, apiKey: process.env.CLOUDINARY_API_KEY, cloudName: process.env.CLOUDINARY_CLOUD_NAME });
});

const port = process.env.PORT || 4000;
// Serve built frontend (Vite output) if present
try {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const distPath = path.join(__dirname, 'dist');
  serverApp.use(express.static(distPath));
  // SPA fallback (after API routes so API 404s are not hijacked)
  serverApp.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    return res.sendFile(path.join(distPath, 'index.html'));
  });
} catch (e) {
  console.warn('Static serve setup skipped:', e.message);
}

// Generic error handler (keep last)
// eslint-disable-next-line no-unused-vars
serverApp.use((err, _req, res, _next) => {
  console.error('[express.error]', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

serverApp.listen(port, () => console.log('Server listening on', port));
