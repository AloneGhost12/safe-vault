import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5200,      // Fixed port to keep origin constant (avoid localStorage reset)
    strictPort: true
  }
});
