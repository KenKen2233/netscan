<template>
  <div>
    <div class="page-header">
      <h2>⚙️ 系统设置</h2>
      <p>配置全局参数、API密钥和偏好设置</p>
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

      <el-tab-pane label="🔑 API配置">
        <div style="padding:16px;max-width:700px">
          <el-alert title="配置第三方平台API密钥，用于空间测绘和情报查询" type="info" show-icon :closable="false" style="margin-bottom:20px" />

          <el-divider content-position="left">🔍 Shodan</el-divider>
          <el-form label-width="120px" style="margin-bottom:16px">
            <el-form-item label="API Key">
              <el-input v-model="apiKeys.shodan_key" placeholder="Shodan API Key" show-password />
            </el-form-item>
            <el-form-item>
              <el-button size="small" @click="openLink('https://account.shodan.io/')">获取 Key</el-button>
              <span style="font-size:12px;color:var(--text-secondary);margin-left:12px">免费账户：1次/秒，查询端口/漏洞/设备信息</span>
            </el-form-item>
          </el-form>

          <el-divider content-position="left">🌐 Fofa</el-divider>
          <el-form label-width="120px" style="margin-bottom:16px">
            <el-form-item label="Email">
              <el-input v-model="apiKeys.fofa_email" placeholder="注册邮箱" />
            </el-form-item>
            <el-form-item label="API Key">
              <el-input v-model="apiKeys.fofa_key" placeholder="Fofa API Key" show-password />
            </el-form-item>
            <el-form-item>
              <el-button size="small" @click="openLink('https://fofa.info/myProfile')">获取 Key</el-button>
              <span style="font-size:12px;color:var(--text-secondary);margin-left:12px">免费账户：100次/天，国内资产测绘</span>
            </el-form-item>
          </el-form>

          <el-divider content-position="left">🦅 Hunter</el-divider>
          <el-form label-width="120px" style="margin-bottom:16px">
            <el-form-item label="API Key">
              <el-input v-model="apiKeys.hunter_key" placeholder="Hunter API Key" show-password />
            </el-form-item>
            <el-form-item>
              <el-button size="small" @click="openLink('https://hunter.qianxin.com/home/userInfo')">获取 Key</el-button>
              <span style="font-size:12px;color:var(--text-secondary);margin-left:12px">奇安信旗下，免费15次/天</span>
            </el-form-item>
          </el-form>

          <el-divider content-position="left">🌊 Quake</el-divider>
          <el-form label-width="120px" style="margin-bottom:16px">
            <el-form-item label="API Key">
              <el-input v-model="apiKeys.quake_key" placeholder="360 Quake API Key" show-password />
            </el-form-item>
            <el-form-item>
              <el-button size="small" @click="openLink('https://quake.360.net/quake/#/personal')">获取 Key</el-button>
              <span style="font-size:12px;color:var(--text-secondary);margin-left:12px">360旗下，网络空间测绘</span>
            </el-form-item>
          </el-form>

          <el-divider content-position="left">👁️ ZoomEye</el-divider>
          <el-form label-width="120px" style="margin-bottom:16px">
            <el-form-item label="API Key">
              <el-input v-model="apiKeys.zoomeye_key" placeholder="ZoomEye API Key" show-password />
            </el-form-item>
            <el-form-item>
              <el-button size="small" @click="openLink('https://www.zoomeye.org/profile')">获取 Key</el-button>
              <span style="font-size:12px;color:var(--text-secondary);margin-left:12px">知道创宇旗下，网络空间搜索引擎</span>
            </el-form-item>
          </el-form>

          <el-button type="primary" size="large" @click="saveApiKeys" style="margin-top:16px">💾 保存 API 配置</el-button>
        </div>
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
          <h3 style="margin-bottom:16px">🛡️ NetScan Pro v2.0.0</h3>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="软件名称">NetScan Pro</el-descriptions-item>
            <el-descriptions-item label="版本">v2.0.0</el-descriptions-item>
            <el-descriptions-item label="作者">A_Kanaki_1</el-descriptions-item>
            <el-descriptions-item label="联系方式">微信: Baiyh322</el-descriptions-item>
            <el-descriptions-item label="技术栈">Wails v2 + Vue 3 + Element Plus + Go 1.24</el-descriptions-item>
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
const apiKeys = ref({ shodan_key: '', fofa_email: '', fofa_key: '', hunter_key: '', quake_key: '', zoomeye_key: '' })

function applyTheme() {
  document.documentElement.setAttribute('data-theme', settings.value.theme)
  store.theme = settings.value.theme
}

function openLink(url) {
  window['go']['app']['App']['OpenURL'](url).catch(() => {})
}

async function loadSettings() {
  try {
    const s = await GetSettings()
    if (s) {
      settings.value = { ...settings.value, ...s }
      // Load API keys from settings
      apiKeys.value.shodan_key = s.shodan_key || ''
      apiKeys.value.fofa_email = s.fofa_email || ''
      apiKeys.value.fofa_key = s.fofa_key || ''
      apiKeys.value.hunter_key = s.hunter_key || ''
      apiKeys.value.quake_key = s.quake_key || ''
      apiKeys.value.zoomeye_key = s.zoomeye_key || ''
    }
  } catch (e) { console.error(e) }
}

async function saveSettings() {
  try {
    await SaveSettings(settings.value)
    applyTheme()
    store.addNotification('success', '设置已保存')
  } catch (e) { console.error(e) }
}

async function saveApiKeys() {
  try {
    // Merge API keys into settings and save
    const merged = { ...settings.value, ...apiKeys.value }
    await SaveSettings(merged)
    store.addNotification('success', 'API 配置已保存')
  } catch (e) { console.error(e) }
}

onMounted(loadSettings)
</script>
