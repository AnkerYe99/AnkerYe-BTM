import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: './',
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': 'http://10.14.7.206:9000'
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})
