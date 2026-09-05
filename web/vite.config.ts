import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `base: './'` is not cosmetic. Issue #90 wants a directory that opens from the
// filesystem with no server, and an absolute `/assets/...` is a 404 under
// `file://`. Relative asset URLs are what make the export and the served build
// the same bundle rather than two.
//
// No CDN, no external font, nothing fetched at runtime (#82): everything is
// built into the assets, which is also what lets the export be screenshotted on
// a machine with no network.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    outDir: 'dist',
    // One chunk. The whole app is a few pages over a JSON API, and a split
    // bundle means a network round trip mid-navigation — "no spinners on
    // camera" (docs/VIDEO.md) is easier to guarantee than to debug.
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    // `mk web` is the only backend. Same-origin in production, proxied in dev,
    // so no frontend code ever names an absolute URL.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8090', changeOrigin: false },
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
})
