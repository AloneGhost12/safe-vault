// Restored vite.config.js (ESM). Maintains same config as vite.config.mjs.
// NOTE: Keeping both .js and .mjs may be redundant. If Render reintroduces the
// earlier ESM loading issue, remove this file and keep only vite.config.mjs.
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5200,
    strictPort: true,
  },
});
