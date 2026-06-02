<template>
  <div>
    <div class="page-header">
      <h2>🌐 空间测绘</h2>
      <p>多平台资产测绘：Fofa、Hunter、Quake、ZoomEye、Shodan</p>
    </div>

    <!-- API Config -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">🔑 平台 API 配置</span>
        <el-button text type="primary" size="small" @click="showApi = !showApi">{{ showApi ? '收起' : '展开' }}</el-button>
      </div>
      <div v-show="showApi" style="margin-top:16px">
        <el-form label-width="100px" style="max-width:650px">
          <el-form-item label="Shodan">
            <el-input v-model="apiKeys.shodan_key" placeholder="API Key" show-password size="small" />
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">免费 1次/秒 · <a @click="openLink('https://account.shodan.io/')" style="cursor:pointer">获取</a></div>
          </el-form-item>
          <el-form-item label="Fofa">
            <el-input v-model="apiKeys.fofa_email" placeholder="邮箱" size="small" style="margin-bottom:6px" />
            <el-input v-model="apiKeys.fofa_key" placeholder="API Key" show-password size="small" />
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">免费 100次/天 · <a @click="openLink('https://fofa.info/myProfile')" style="cursor:pointer">获取</a></div>
          </el-form-item>
          <el-form-item label="Hunter">
            <el-input v-model="apiKeys.hunter_key" placeholder="API Key" show-password size="small" />
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">免费 15次/天 · <a @click="openLink('https://hunter.qianxin.com/home/userInfo')" style="cursor:pointer">获取</a></div>
          </el-form-item>
          <el-form-item label="Quake">
            <el-input v-model="apiKeys.quake_key" placeholder="API Key" show-password size="small" />
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">360 旗下 · <a @click="openLink('https://quake.360.net/quake/#/personal')" style="cursor:pointer">获取</a></div>
          </el-form-item>
          <el-form-item label="ZoomEye">
            <el-input v-model="apiKeys.zoomeye_key" placeholder="API Key" show-password size="small" />
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px">知道创宇 · <a @click="openLink('https://www.zoomeye.org/profile')" style="cursor:pointer">获取</a></div>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" size="small" @click="saveApiKeys">💾 保存 API 配置</el-button>
            <el-tag v-if="apiSaved" type="success" size="small" style="margin-left:8px">已保存</el-tag>
          </el-form-item>
        </el-form>
      </div>
    </div>

    <!-- Query Config -->
    <div class="card">
      <div class="card-title" style="margin-bottom:16px">查询配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="查询语句">
          <el-input v-model="form.query" placeholder='例：domain="example.com" 或 ip="1.2.3.4" 或 title="后台"' />
        </el-form-item>
        <el-form-item label="查询平台">
          <el-checkbox-group v-model="form.platforms">
            <el-checkbox v-for="p in platforms" :key="p.value" :value="p.value">
              {{ p.label }}
              <el-tag v-if="!p.configured" type="info" size="small" style="margin-left:4px">未配置</el-tag>
              <el-tag v-else type="success" size="small" style="margin-left:4px">✓</el-tag>
            </el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="返回数量">
          <el-input-number v-model="form.size" :min="10" :max="500" :step="10" />
        </el-form-item>
        <el-form-item label="快捷语法">
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            <el-tag v-for="q in syntaxExamples" :key="q" size="small" effect="plain" style="cursor:pointer" @click="form.query = q">{{ q }}</el-tag>
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startQuery" :loading="querying" size="large">
            {{ querying ? '查询中...' : '🔍 开始查询' }}
          </el-button>
          <el-button v-if="results.length > 0 && !querying" type="success" @click="exportResults" size="large">📥 导出 CSV</el-button>
          <el-button v-if="results.length > 0 && !querying" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- Query Status -->
    <div class="card" v-if="querying || queryStatus.length > 0">
      <div style="display:flex;gap:16px;flex-wrap:wrap">
        <div v-for="(st, idx) in queryStatus" :key="idx" style="display:flex;align-items:center;gap:6px;font-size:13px">
          <el-icon v-if="st.status === 'loading'" class="is-loading"><Loading /></el-icon>
          <el-icon v-else-if="st.status === 'done'" style="color:var(--success-color)"><CircleCheckFilled /></el-icon>
          <el-icon v-else-if="st.status === 'error'" style="color:var(--danger-color)"><CircleCloseFilled /></el-icon>
          <el-icon v-else-if="st.status === 'skip'" style="color:var(--text-muted)"><WarningFilled /></el-icon>
          <span>{{ st.name }}</span>
          <span style="color:var(--text-muted)">{{ st.msg }}</span>
        </div>
      </div>
    </div>

    <!-- Results -->
    <div class="card" v-if="results.length > 0">
      <div class="card-header">
        <span class="card-title">查询结果 ({{ filteredResults.length }}/{{ results.length }})</span>
        <div style="display:flex;gap:8px;align-items:center">
          <el-input v-model="searchText" placeholder="搜索 Host/IP/标题..." size="small" style="width:200px" clearable />
          <el-select v-model="filterPlatform" size="small" style="width:110px" clearable placeholder="平台筛选">
            <el-option label="全部" value="" />
            <el-option v-for="p in platforms" :key="p.value" :label="p.label" :value="p.value" />
          </el-select>
        </div>
      </div>

      <el-table :data="filteredResults" stripe style="width:100%" max-height="500" :row-key="row => row.platform + row.host + row.port">
        <el-table-column prop="platform" label="平台" width="80">
          <template #default="{ row }">
            <el-tag :type="platformTag(row.platform)" size="small" effect="dark">{{ row.platform }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="host" label="Host" min-width="180">
          <template #default="{ row }">
            <a v-if="row.url" class="result-link" @click.prevent="openURL(row.url)">{{ row.host }}</a>
            <span v-else style="font-family:monospace;font-size:12px">{{ row.host }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="ip" label="IP" width="130" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="title" label="标题" width="180" show-overflow-tooltip />
        <el-table-column prop="server" label="Server" width="120" show-overflow-tooltip />
        <el-table-column prop="country" label="地区" width="80" />
        <el-table-column prop="os" label="OS" width="100" show-overflow-tooltip />
        <el-table-column label="操作" width="70" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.url" text type="primary" size="small" @click="openURL(row.url)">访问</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Empty -->
    <div class="card" v-if="!querying && queried && results.length === 0">
      <div style="text-align:center;padding:40px;color:var(--text-secondary)">
        <p style="font-size:16px;margin-bottom:8px">未查询到结果</p>
        <p>请检查 API 配置和查询语法</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { Loading, CircleCheckFilled, CircleCloseFilled, WarningFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { SpaceMappingQuery, GetSettings, SaveSettings, OpenURL } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_spacemapping_results'

const form = ref({ query: '', platforms: ['fofa', 'hunter'], size: 100 })
const querying = ref(false)
const queried = ref(false)
const results = ref([])
const searchText = ref('')
const filterPlatform = ref('')
const queryStatus = ref([])
const showApi = ref(false)
const apiSaved = ref(false)

const apiKeys = ref({
  shodan_key: '', fofa_email: '', fofa_key: '',
  hunter_key: '', quake_key: '', zoomeye_key: ''
})

const syntaxExamples = [
  'domain="example.com"', 'ip="1.2.3.4"', 'title="后台管理"',
  'body="login"', 'server="nginx"', 'port="8080"',
  'cert="example.com"', 'country="CN" && title="系统"',
]

const platforms = computed(() => [
  { value: 'fofa', label: 'Fofa', configured: !!apiKeys.value.fofa_key },
  { value: 'hunter', label: 'Hunter', configured: !!apiKeys.value.hunter_key },
  { value: 'quake', label: 'Quake', configured: !!apiKeys.value.quake_key },
  { value: 'zoomeye', label: 'ZoomEye', configured: !!apiKeys.value.zoomeye_key },
  { value: 'shodan', label: 'Shodan', configured: !!apiKeys.value.shodan_key },
])

const filteredResults = computed(() => {
  let list = results.value
  if (searchText.value) {
    const q = searchText.value.toLowerCase()
    list = list.filter(r => (r.host||'').toLowerCase().includes(q) || (r.ip||'').includes(q) || (r.title||'').toLowerCase().includes(q))
  }
  if (filterPlatform.value) list = list.filter(r => r.platform === filterPlatform.value)
  return list
})

function platformTag(p) {
  return { fofa: '', hunter: 'success', quake: 'warning', zoomeye: 'info', shodan: 'danger' }[p] || ''
}

function openLink(url) { OpenURL(url).catch(() => {}) }
function openURL(url) { OpenURL(url).catch(() => {}) }

async function loadApiKeys() {
  try {
    const s = await GetSettings()
    if (s) {
      apiKeys.value.shodan_key = s.shodan_key || ''
      apiKeys.value.fofa_email = s.fofa_email || ''
      apiKeys.value.fofa_key = s.fofa_key || ''
      apiKeys.value.hunter_key = s.hunter_key || ''
      apiKeys.value.quake_key = s.quake_key || ''
      apiKeys.value.zoomeye_key = s.zoomeye_key || ''
    }
  } catch (e) {}
}

async function saveApiKeys() {
  try {
    const s = await GetSettings()
    const merged = { ...s, ...apiKeys.value }
    await SaveSettings(merged)
    apiSaved.value = true
    ElMessage.success('API 配置已保存')
    setTimeout(() => { apiSaved.value = false }, 2000)
  } catch (e) { ElMessage.error('保存失败') }
}

function clearResults() {
  results.value = []; queried.value = false; queryStatus.value = []; localStorage.removeItem(STORAGE_KEY)
}

function saveResults() { try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ results: results.value, query: form.value.query })) } catch(e){} }
function loadResults() { try { const s = localStorage.getItem(STORAGE_KEY); if (s) { const d = JSON.parse(s); if (d.results?.length > 0) { results.value = d.results; queried.value = true; if (d.query) form.value.query = d.query } } } catch(e){} }

async function startQuery() {
  if (!form.value.query.trim()) return

  // Check which platforms have API keys
  const toQuery = []
  const skipped = []
  for (const p of form.value.platforms) {
    const cfg = platforms.value.find(x => x.value === p)
    if (cfg?.configured) {
      toQuery.push(p)
    } else {
      skipped.push(p)
    }
  }

  if (toQuery.length === 0) {
    ElMessage.warning('请先配置至少一个平台的 API Key')
    showApi.value = true
    return
  }

  querying.value = true
  queried.value = true
  results.value = []

  queryStatus.value = [
    ...toQuery.map(p => ({ name: p, status: 'loading', msg: '查询中...' })),
    ...skipped.map(p => ({ name: p, status: 'skip', msg: '未配置 Key' }))
  ]

  try {
    const res = await SpaceMappingQuery(form.value.query, toQuery, form.value.size)
    if (res && res.length > 0) results.value = res

    for (const st of queryStatus.value) {
      if (st.status === 'skip') continue
      const count = (res || []).filter(r => r.platform === st.name).length
      st.status = count > 0 ? 'done' : 'error'
      st.msg = count > 0 ? `${count} 条` : '无结果'
    }
    saveResults()
  } catch (e) {
    console.error(e)
    for (const st of queryStatus.value) {
      if (st.status === 'loading') { st.status = 'error'; st.msg = '查询失败' }
    }
  }
  querying.value = false
}

function exportResults() {
  if (results.value.length === 0) return
  let csv = '平台,Host,IP,端口,标题,Server,地区,OS\n'
  for (const r of results.value) {
    csv += `${r.platform},${r.host},${r.ip},${r.port},"${(r.title||'').replace(/"/g,'""')}",${r.server||''},${r.country||''},${r.os||''}\n`
  }
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = `spacemapping_${Date.now()}.csv`; a.click()
  URL.revokeObjectURL(url)
}

// Auto-select only configured platforms
watch(platforms, (val) => {
  const configured = val.filter(p => p.configured).map(p => p.value)
  form.value.platforms = form.value.platforms.filter(p => configured.includes(p))
  if (form.value.platforms.length === 0 && configured.length > 0) {
    form.value.platforms = [configured[0]]
  }
}, { immediate: true })

onMounted(() => { loadApiKeys(); loadResults() })
</script>

<style scoped>
.result-link { color: var(--primary-color); cursor: pointer; font-size: 12px; font-family: monospace; text-decoration: none; max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
.result-link:hover { text-decoration: underline; }
</style>
