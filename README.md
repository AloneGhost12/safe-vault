# SecureVault (React + Vite)

A demo secure document vault UI with dark mode, drag & drop uploads, categories, emergency access panel, and settings. Built with React 18, Vite 5, and Tailwind CSS 3.

## Prerequisites
- Node.js 18+ (LTS recommended)
- Internet access for Font Awesome CDN (or replace with local icons)

## Install & Run (Windows PowerShell)
```powershell
# (Optional) Initialize npm if lockfile missing
npm install

# Start dev server (default: http://localhost:5173)
npm run dev
```

If the browser doesnΓÇÖt open automatically, visit: http://localhost:5173

## Build for Production
```powershell
npm run build
npm run preview   # Serve the build locally to test
```

## Tailwind IntelliSense Warnings
VS Code may flag `@tailwind` or `@apply` as unknown until PostCSS runs; this is normal. Ensure the Tailwind and PostCSS extensions are installed for best DX.

## Customize
- Edit UI: `src/App.jsx`
- Global styles: `src/styles.css`
- Tailwind config: `tailwind.config.cjs`
 - Mongo + Cloudinary backend already integrated (see server.js). Firebase has been fully removed.

## Notes
End-to-end encryption performed in-browser (AES-GCM). Encrypted blobs are uploaded to Cloudinary via unsigned raw uploads. Metadata (still encrypted) and activity logs are stored in MongoDB through the Express server. Master password never leaves the client; losing it means encrypted data cannot be recovered.

## Environment Variables
Create a `.env.local` for client-exposed vars and standard `.env` (server) for secrets.

Client (prefix with VITE_):
- VITE_CLOUDINARY_CLOUD_NAME
- VITE_CLOUDINARY_UPLOAD_PRESET
- VITE_API_BASE_URL  (e.g. https://your-render-app.onrender.com)

Server only:
- CLOUDINARY_CLOUD_NAME / CLOUDINARY_API_KEY / CLOUDINARY_API_SECRET
- MONGODB_URI (e.g. mongodb+srv://user:pass@cluster/db)
- MONGODB_DB (optional, default safe_vault)
- JWT_SECRET (for auth endpoints if extended)

Remove any legacy Firebase vars; they are no longer used.

## Deployment

This application consists of two parts:

### Backend (Express + MongoDB)
Deploy the backend to Render or similar platform:
1. The `render.yaml` file is pre-configured for Render deployment
2. Set the environment variables in your hosting platform dashboard
3. The backend will be available at a URL like `https://your-app-name.onrender.com`

### Frontend (React SPA) 
Deploy the frontend to GitHub Pages:
1. The repository includes a GitHub Actions workflow that automatically builds and deploys to GitHub Pages
2. Create a `.env.local` file with: `VITE_API_BASE_URL=https://your-backend-url.onrender.com`
3. Push to the main branch to trigger automatic deployment
4. The frontend will be available at `https://your-username.github.io/safe-vault/`

### Development
For local development, run both parts:
```bash
# Terminal 1: Start backend server
npm run server

# Terminal 2: Start frontend dev server  
npm run dev
```
The Vite dev server proxies `/api/*` requests to the backend automatically.
