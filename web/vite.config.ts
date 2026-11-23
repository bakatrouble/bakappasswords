import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ui from '@nuxt/ui/vite'

// Served by the Rust binary under /__admin/, so all asset URLs carry that base.
export default defineConfig({
  base: '/__admin/',
  plugins: [vue(), ui()],
})
