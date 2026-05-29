<template>
  <div>
    <div class="page-header">
      <h2>⚙️ 系统设置</h2>
      <p>配置全局参数和偏好设置</p>
    </div>

    <el-tabs type="border-card">
      <el-tab-pane label="基本设置">
        <el-form :model="settings" label-width="120px" style="max-width:600px;padding:16px">
          <el-form-item label="全局代理"><el-input v-model="settings.proxy" placeholder="http://127.0.0.1:7890" /></el-form-item>
          <el-form-item label="默认超时(ms)"><el-input-number v-model="settings.default_timeout" :min="100" :max="60000" /></el-form-item>
          <el-form-item label="默认并发数"><el-input-number v-model="settings.default_max_conn" :min="1" :max="2000" /></el-form-item>
          <el-form-item><el-button type="primary" @click="saveSettings">保存设置</el-button></el-form-item>
        </el-form>
      </el-tab-pane>

      <el-tab-pane label="主题设置">
        <div style="padding:16px">
          <div style="margin-bottom:16px">
            <span style="margin-right:12px">主题模式：</span>
            <el-radio-group v-model="settings.theme" @change="applyTheme">
              <el-radio-button value="dark">🌙 深色</el-radio-button>
              <el-radio-button value="light">☀️ 浅色</el-radio-button>
            </el-radio-group>
          </div>
          <div>
            <span style="margin-right:12px">主题色：</span>
            <el-color-picker v-model="settings.theme_color" />
          </div>
        </div>
      </el-tab-pane>

      <el-tab-pane label="关于">
        <div style="padding:24px">
          <h3 style="margin-bottom:16px">🛡️ NetScan Pro v1.0.0</h3>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="软件名称">NetScan Pro</el-descriptions-item>
            <el-descriptions-item label="版本">v1.0.0</el-descriptions-item>
            <el-descriptions-item label="作者">A_Kanaki_1</el-descriptions-item>
            <el-descriptions-item label="联系方式">微信: Baiyh322</el-descriptions-item>
            <el-descriptions-item label="技术栈">Wails v2 + Vue 3 + Element Plus + Go</el-descriptions-item>
            <el-descriptions-item label="支持平台">Windows 10+ / macOS 12+ / Ubuntu 20.04+</el-descriptions-item>
          </el-descriptions>
          <el-divider />
          <div style="color:var(--text-secondary);font-size:13px;line-height:1.8">
            <p>⚠️ 免责声明：本工具仅用于合法授权的安全测试。使用者需遵守当地法律法规。</p>
            <p style="margin-top:8px">使用前请确保已获得目标系统所有者的书面授权。</p>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { GetSettings, SaveSettings } from '../wailsjs/go/app/App'
import { useAppStore } from '../stores/app'

const store = useAppStore()
const settings = ref({ proxy: '', default_timeout: 5000, default_max_conn: 100, theme: 'dark', theme_color: '#409EFF' })

function applyTheme() {
  document.documentElement.setAttribute('data-theme', settings.value.theme)
  store.theme = settings.value.theme
}

async function loadSettings() {
  try {
    const s = await GetSettings()
    if (s) settings.value = s
  } catch (e) { console.error(e) }
}

async function saveSettings() {
  try {
    await SaveSettings(settings.value)
    applyTheme()
    store.addNotification('success', '设置已保存')
  } catch (e) { console.error(e) }
}

onMounted(loadSettings)
</script>
