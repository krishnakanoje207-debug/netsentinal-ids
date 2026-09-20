// vitest/config, not vite: the plain defineConfig has no `test` key in its type.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dashboard reaches the API through an SSH tunnel in deployment, so it is
// same-origin there and the backend deliberately ships no CORS middleware. In
// development this proxy reproduces that: the browser only ever talks to Vite.
const API_TARGET = process.env.NETSENTINEL_API ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
        // The alert feed is a WebSocket under the same prefix.
        ws: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
