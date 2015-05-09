import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Builds a static SPA into ./build, served by the FastAPI control plane.
// In dev, /api and the WebSocket are proxied to the running control plane.
export default defineConfig({
  plugins: [svelte()],
  build: { outDir: 'build', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8787', ws: true }
    }
  }
});
