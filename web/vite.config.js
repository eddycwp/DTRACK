import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 生产构建输出到 web/dist，由后端 stdlib 服务器托管。
// 开发模式将 /api 代理到本地后端（默认 8080）。
export default defineConfig({
  plugins: [vue()],
  base: '/',
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: '../dtrack/static',
    chunkSizeWarningLimit: 1500
  }
})
