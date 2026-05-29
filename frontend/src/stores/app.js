import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  const theme = ref(localStorage.getItem('theme') || 'dark')
  const sidebarCollapsed = ref(false)
  const notifications = ref([])
  let notifId = 0

  function toggleTheme() {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
    localStorage.setItem('theme', theme.value)
    document.documentElement.setAttribute('data-theme', theme.value)
  }

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  function addNotification(type, message, duration = 3000) {
    const id = ++notifId
    notifications.value.push({ id, type, message })
    if (duration > 0) {
      setTimeout(() => removeNotification(id), duration)
    }
  }

  function removeNotification(id) {
    notifications.value = notifications.value.filter(n => n.id !== id)
  }

  return { theme, sidebarCollapsed, notifications, toggleTheme, toggleSidebar, addNotification, removeNotification }
})
