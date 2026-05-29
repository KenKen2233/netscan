<template>
  <div class="app-layout" :class="{ 'sidebar-collapsed': store.sidebarCollapsed }">
    <!-- Disclaimer Dialog -->
    <el-dialog v-model="showDisclaimer" title="⚠️ 免责声明" width="500px" :close-on-click-modal="false" :close-on-press-escape="false" :show-close="false">
      <div style="line-height:1.8;color:var(--text-primary)">
        <p>欢迎使用 <b>NetScan Pro v1.0.0</b></p>
        <p style="margin-top:12px">本工具仅用于<b>合法授权</b>的安全测试和渗透测试。使用本工具进行未经授权的网络扫描、漏洞检测或任何非法活动，后果由使用者自行承担。</p>
        <p style="margin-top:12px">使用前请确保已获得目标系统所有者的<b>书面授权</b>。</p>
        <div style="margin-top:16px;padding:12px;background:var(--bg-tertiary);border-radius:6px;font-size:13px">
          <div>作者：A_Kanaki_1</div>
          <div>联系方式：微信 Baiyh322</div>
        </div>
      </div>
      <template #footer>
        <el-button type="primary" @click="acceptDisclaimer">我已知晓并同意</el-button>
      </template>
    </el-dialog>

    <!-- Sidebar -->
    <aside class="sidebar" :class="{ collapsed: store.sidebarCollapsed }">
      <div class="sidebar-header">
        <span class="sidebar-logo" v-show="!store.sidebarCollapsed">🛡️ NetScan</span>
        <span class="sidebar-logo" v-show="store.sidebarCollapsed">🛡️</span>
      </div>
      <nav class="sidebar-nav">
        <router-link v-for="r in navRoutes" :key="r.path" :to="r.path" class="nav-item" active-class="active">
          <el-icon><component :is="r.meta.icon" /></el-icon>
          <span class="nav-text">{{ r.meta.title }}</span>
        </router-link>
      </nav>
      <div style="padding:8px;border-top:1px solid var(--border-color)">
        <div class="nav-item" @click="store.toggleSidebar" style="justify-content:center">
          <el-icon><Fold v-if="!store.sidebarCollapsed" /><Expand v-else /></el-icon>
          <span class="nav-text" v-show="!store.sidebarCollapsed">收起</span>
        </div>
      </div>
      <div class="sidebar-footer" v-show="!store.sidebarCollapsed">
        <div style="font-size:11px;color:var(--text-muted);text-align:center;padding:4px 8px">
          A_Kanaki_1 · 微信 Baiyh322
        </div>
      </div>
    </aside>

    <!-- Main -->
    <div class="main-area">
      <header class="header">
        <div class="header-left">
          <div class="header-status">
            <span class="status-dot running"></span>
            <span>就绪</span>
          </div>
        </div>
        <div class="header-right">
          <span style="font-size:12px;color:var(--text-muted)">v1.0.0</span>
          <el-tooltip content="切换主题">
            <el-button :icon="store.theme === 'dark' ? 'Sunny' : 'Moon'" circle size="small" @click="store.toggleTheme" />
          </el-tooltip>
        </div>
      </header>
      <main class="content">
        <router-view />
      </main>
    </div>

    <!-- Notifications -->
    <div class="notification-container">
      <div v-for="n in store.notifications" :key="n.id" class="notification" :class="n.type" @click="store.removeNotification(n.id)">
        <span>{{ n.message }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useAppStore } from './stores/app'
import { routes } from './router'

const store = useAppStore()
const navRoutes = routes.filter(r => r.meta?.title)
const showDisclaimer = ref(false)

function acceptDisclaimer() {
  showDisclaimer.value = false
  localStorage.setItem('disclaimer_accepted', 'true')
}

onMounted(() => {
  document.documentElement.setAttribute('data-theme', store.theme)
  // Show disclaimer on first run
  if (!localStorage.getItem('disclaimer_accepted')) {
    showDisclaimer.value = true
  }
})
</script>
