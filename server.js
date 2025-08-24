import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cors from 'cors';
import multer from 'multer';
import cloudinary from 'cloudinary';

dotenv.config();

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
app.use(cors());
app.use(express.json());

// Health check
app.get('/api/health', (_req,res)=> res.json({ ok:true, time: Date.now() }));

// Proxy Cloudinary raw uploads
app.post('/api/cloudinary/upload', upload.single('file'), async (req, res) => {
  try {
    const { upload_preset, folder, resource_type } = req.body;
    if (!req.file) return res.status(400).json({ error: 'Missing file' });
    const result = await cloudinary.v2.uploader.upload_stream(
      {
        upload_preset,
        folder: folder || 'vault',
        resource_type: resource_type || 'raw',
      },
      (error, result) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(result);
      }
    );
    // Pipe file buffer to Cloudinary
    require('stream').Readable.from(req.file.buffer).pipe(result);
  } catch (err) {
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
app.listen(port, () => console.log('Server listening on', port));
