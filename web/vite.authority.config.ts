import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// This build is installed only with the independent authority. The controller
// cannot supply its review HTML, scripts, session proof or plan evidence.
export default defineConfig({
  root: 'authority',
  plugins: [react()],
  build: { outDir: '../dist-authority', emptyOutDir: true, assetsDir: 'assets' },
});
