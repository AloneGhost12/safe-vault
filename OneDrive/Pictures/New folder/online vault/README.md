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

If the browser doesn’t open automatically, visit: http://localhost:5173

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
 - Firebase setup: `src/firebase.js` (uses Vite env vars)

## Notes
All file encryption, sharing, and security operations are currently simulated (UI only). Add real logic / backend as needed.
Encrypted file payload (AES-GCM ciphertext base64) is also uploaded to Firebase Storage under `vault/` when available. Master password never leaves the client; losing it means data unrecoverable.
