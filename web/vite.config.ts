import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Split large libraries into their own long-lived cached chunks
        manualChunks: {
          'vendor-antd': ['antd', '@ant-design/icons'],
          'vendor-arco': ['@arco-design/web-react'],
          'vendor-echarts': ['echarts', 'echarts-for-react'],
        },
      },
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
