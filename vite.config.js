import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  server: {
    port: 5173,
    open: false,
  },
  optimizeDeps: {
    include: ['kdbxweb', 'hash-wasm', 'lucide']
  }
});
