import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// `npm run dev` proxies /api to the Python API (./tip serve); `npm run build` output is served by ./tip serve itself.
export default defineConfig({
  plugins: [react()],
  server: { port: 5174, proxy: { '/api': 'http://localhost:8000' } },
});
