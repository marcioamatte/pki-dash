import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';

// dist/ is embedded into the Go binary and is otherwise git-ignored. Emptying it
// on each build would delete the placeholder that lets `go build` work on a
// fresh clone, so put it back.
const keepPlaceholder: Plugin = {
  name: 'keep-placeholder',
  generateBundle() {
    this.emitFile({ type: 'asset', fileName: '.gitkeep', source: '' });
  },
};

export default defineConfig({
  plugins: [tailwindcss(), svelte(), keepPlaceholder],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // The preload polyfill is an inline script, which our CSP forbids.
    modulePreload: { polyfill: false },
  },
  server: { proxy: { '/api': 'http://127.0.0.1:8443' } },
});
