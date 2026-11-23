import './assets/main.css'

import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import ui from '@nuxt/ui/vue-plugin'
import App from './App.vue'

document.documentElement.classList.add('dark')

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [],
})

createApp(App).use(router).use(ui).mount('#app')
