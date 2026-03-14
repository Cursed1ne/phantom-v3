import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],

  publicDir: 'public',

  server: {
    port: 3001,
    strictPort: true,
    host: '127.0.0.1',
    open: false,
  },

  build: {
    outDir: 'build',
    sourcemap: false,
    rollupOptions: {
      input: path.resolve(__dirname, 'index.html'),
    },
  },

  define: {
    'process.env': JSON.stringify({}),
  },

  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
    extensions: ['.jsx', '.js', '.tsx', '.ts', '.json'],
  },
});
