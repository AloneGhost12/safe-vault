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

dotenv.config();

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Basic request logging (combined for detailed info in production)
app.use(morgan(process.env.LOG_FORMAT || 'dev'));

// Capture unhandled errors
process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err);
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
});

// Health check
app.get('/api/health', (_req,res)=> res.json({ ok:true, time: Date.now() }));

// Runtime client configuration (avoids rebuild for changing Cloudinary values)
app.get('/api/client-config', (req, res) => {
  res.json({
    cloudName: process.env.CLOUDINARY_CLOUD_NAME || null,
    uploadPreset: process.env.CLOUDINARY_UPLOAD_PRESET || null
  });
});

// Proxy Cloudinary raw uploads
app.post('/api/cloudinary/upload', upload.single('file'), (req, res) => {
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
app.post('/api/cloudinary/signature', (req,res) => {
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
  app.use(express.static(distPath));
  // SPA fallback (after API routes so API 404s are not hijacked)
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    return res.sendFile(path.join(distPath, 'index.html'));
  });
} catch (e) {
  console.warn('Static serve setup skipped:', e.message);
}

// Generic error handler (keep last)
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[express.error]', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(port, () => console.log('Server listening on', port));
