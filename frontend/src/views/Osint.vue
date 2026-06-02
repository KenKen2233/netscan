<template>
  <div>
    <div class="page-header">
      <h2>📈 信息收集 (OSINT)</h2>
      <p>综合信息收集：子域名、WHOIS、DNS、IP归属、证书透明度、SSL证书、子域名爆破</p>
    </div>

    <div class="card">
      <div class="card-title" style="margin-bottom:16px">收集配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标域名">
          <el-input v-model="form.target" placeholder="example.com" />
        </el-form-item>
        <el-form-item label="收集模块">
          <el-checkbox-group v-model="form.modules">
            <el-checkbox value="dns">DNS解析</el-checkbox>
            <el-checkbox value="whois">WHOIS查询</el-checkbox>
            <el-checkbox value="subdomain">子域名枚举</el-checkbox>
            <el-checkbox value="crtsh">证书透明度</el-checkbox>
            <el-checkbox value="subdomain_brute">子域名爆破</el-checkbox>
            <el-checkbox value="ssl">SSL证书</el-checkbox>
            <el-checkbox value="ipinfo">IP归属地</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startOsint" :loading="scanning" size="large">
            {{ scanning ? '收集中...' : '🚀 开始收集' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopOsint" size="large">⏹ 停止</el-button>
          <el-button v-if="Object.keys(results).length > 0 && !scanning" type="success" @click="exportResults" size="large">📥 导出</el-button>
          <el-button v-if="Object.keys(results).length > 0 && !scanning" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- Progress -->
    <div class="card" v-if="scanning">
      <el-progress :percentage="progress" :stroke-width="8" style="margin-bottom:8px" />
      <span style="font-size:13px;color:var(--text-secondary)">{{ progressText }}</span>
    </div>

    <!-- Results -->
    <div v-if="Object.keys(results).length > 0">
      <div class="card" v-for="(data, mod) in results" :key="mod">
        <div class="card-header">
          <span class="card-title">{{ getModuleLabel(mod) }}</span>
          <el-tag v-if="mod === 'subdomain' || mod === 'crtsh' || mod === 'subdomain_brute'" size="small">{{ getCount(data) }} 条</el-tag>
        </div>

        <!-- DNS -->
        <div v-if="mod === 'dns'">
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="域名">{{ data.domain }}</el-descriptions-item>
            <el-descriptions-item label="A记录">
              <span v-for="(ip, i) in (data.a_records || [])" :key="i" style="margin-right:8px;font-family:monospace">{{ ip }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="CNAME">{{ data.cname || '-' }}</el-descriptions-item>
            <el-descriptions-item label="MX记录">
              <div v-for="(mx, i) in (data.mx_records || [])" :key="i">{{ mx }}</div>
              <span v-if="!data.mx_records?.length">-</span>
            </el-descriptions-item>
            <el-descriptions-item label="NS记录">
              <div v-for="(ns, i) in (data.ns_records || [])" :key="i">{{ ns }}</div>
            </el-descriptions-item>
            <el-descriptions-item label="TXT记录">
              <div v-for="(txt, i) in (data.txt_records || [])" :key="i" style="font-size:12px;word-break:break-all">{{ txt }}</div>
            </el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- WHOIS -->
        <div v-else-if="mod === 'whois'">
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="域名">{{ data.domain }}</el-descriptions-item>
            <el-descriptions-item label="IP">{{ data.ip || '-' }}</el-descriptions-item>
            <el-descriptions-item label="注册商">{{ data.whois_parsed?.registrar || '-' }}</el-descriptions-item>
            <el-descriptions-item label="创建时间">{{ data.whois_parsed?.creation_date || '-' }}</el-descriptions-item>
            <el-descriptions-item label="到期时间">{{ data.whois_parsed?.expiry_date || '-' }}</el-descriptions-item>
            <el-descriptions-item label="更新时间">{{ data.whois_parsed?.updated_date || '-' }}</el-descriptions-item>
            <el-descriptions-item label="反向DNS">{{ data.reverse_dns || '-' }}</el-descriptions-item>
          </el-descriptions>
          <el-collapse v-if="data.whois_raw" style="margin-top:8px">
            <el-collapse-item title="原始 WHOIS 数据">
              <pre style="font-size:11px;white-space:pre-wrap;color:var(--text-secondary);max-height:300px;overflow:auto">{{ data.whois_raw }}</pre>
            </el-collapse-item>
          </el-collapse>
        </div>

        <!-- Subdomain / crt.sh / subdomain_brute -->
        <div v-else-if="(mod === 'subdomain' || mod === 'crtsh' || mod === 'subdomain_brute')">
          <div v-if="getCount(data) === 0" style="color:var(--text-secondary);padding:12px">未发现子域名</div>
          <el-table v-else :data="getSubdomainList(data)" stripe max-height="300" size="small">
            <el-table-column prop="domain" label="子域名" min-width="200">
              <template #default="{ row }">
                <a class="result-link" @click.prevent="openURL('https://' + row.domain)">{{ row.domain }}</a>
              </template>
            </el-table-column>
            <el-table-column v-if="hasIP(data)" prop="ip" label="IP" width="140" />
            <el-table-column label="操作" width="70">
              <template #default="{ row }"><el-button text type="primary" size="small" @click="openURL('https://' + row.domain)">访问</el-button></template>
            </el-table-column>
          </el-table>
        </div>

        <!-- SSL -->
        <div v-else-if="mod === 'ssl'">
          <div v-if="data.error" style="color:var(--danger-color);padding:12px">{{ data.error }}</div>
          <el-descriptions v-else :column="2" border size="small">
            <el-descriptions-item label="域名">{{ data.domain }}</el-descriptions-item>
            <el-descriptions-item label="有效期">
              <el-tag :type="data.is_valid ? 'success' : 'danger'" size="small">{{ data.is_valid ? '有效' : '过期' }}</el-tag>
              <span v-if="data.days_left !== undefined" style="margin-left:8px">剩余 {{ data.days_left }} 天</span>
            </el-descriptions-item>
            <el-descriptions-item label="颁发者">{{ data.issuer }}</el-descriptions-item>
            <el-descriptions-item label="使用者">{{ data.subject }}</el-descriptions-item>
            <el-descriptions-item label="生效时间">{{ data.not_before }}</el-descriptions-item>
            <el-descriptions-item label="过期时间">{{ data.not_after }}</el-descriptions-item>
            <el-descriptions-item label="SAN" :span="2">
              <div v-for="(san, i) in (data.sans || [])" :key="i" style="font-family:monospace;font-size:12px">{{ san }}</div>
              <span v-if="!data.sans?.length">-</span>
            </el-descriptions-item>
            <el-descriptions-item label="序列号" :span="2" v-if="data.serial_number">
              <span style="font-family:monospace;font-size:12px">{{ data.serial_number }}</span>
            </el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- IP Info -->
        <div v-else-if="mod === 'ipinfo'">
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="IP">{{ data.ip }}</el-descriptions-item>
            <el-descriptions-item label="私有地址">{{ data.is_private ? '是' : '否' }}</el-descriptions-item>
            <el-descriptions-item label="回环地址">{{ data.is_loopback ? '是' : '否' }}</el-descriptions-item>
            <el-descriptions-item label="反向DNS">{{ data.reverse_dns || '-' }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- Fallback -->
        <pre v-else style="font-size:12px;color:var(--text-secondary);white-space:pre-wrap">{{ formatData(data) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import { StartOsint, GetOsintResults, GetScanTaskStatus, StopScanTask, ExportResults, OpenURL } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_osint_results'

const form = ref({ target: '', modules: ['dns', 'subdomain', 'crtsh', 'whois', 'ssl', 'ipinfo'] })
// Shodan 已移至空间测绘模块
const scanning = ref(false)
const progress = ref(0)
const progressText = ref('')
const results = ref({})
const taskId = ref(null)
let pollTimer = null

const moduleLabels = {
  dns: '🔗 DNS解析',
  whois: '📋 WHOIS信息',
  subdomain: '🌐 子域名枚举 (常见)',
  crtsh: '📜 证书透明度 (crt.sh)',
  subdomain_brute: '💥 子域名爆破 (字典)',
  ssl: '🔒 SSL证书解析',
  ipinfo: '📍 IP归属地',
}

function getModuleLabel(mod) { return moduleLabels[mod] || mod }

function getCount(data) {
  if (Array.isArray(data)) return data.length
  return data.subdomains?.length || data.total || 0
}

function getSubdomainList(data) {
  if (Array.isArray(data)) return data.map(d => typeof d === 'string' ? { domain: d } : d)
  if (data.subdomains) {
    if (Array.isArray(data.subdomains) && data.subdomains.length > 0 && typeof data.subdomains[0] === 'string') {
      return data.subdomains.map(d => ({ domain: d }))
    }
    return data.subdomains
  }
  return []
}

function hasIP(data) {
  const list = Array.isArray(data) ? data : (data.subdomains || [])
  return list.length > 0 && typeof list[0] === 'object' && list[0].ip
}

function openURL(url) { OpenURL(url).catch(e => console.error(e)) }

function formatData(data) {
  if (typeof data === 'string') { try { return JSON.stringify(JSON.parse(data), null, 2) } catch { return data } }
  return JSON.stringify(data, null, 2)
}

function clearResults() {
  results.value = {}; taskId.value = null; localStorage.removeItem(STORAGE_KEY)
}

function saveResults() { try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ results: results.value, taskId: taskId.value })) } catch(e){} }
function loadSavedResults() { try { const s = localStorage.getItem(STORAGE_KEY); if (s) { const d = JSON.parse(s); if (d.results && Object.keys(d.results).length > 0) { results.value = d.results; taskId.value = d.taskId } } } catch(e){} }

function onProgress(data) {
  if (data.task_id !== taskId.value) return
  progress.value = data.progress || 0
  progressText.value = `正在收集... ${data.progress || 0}%`
}

function onComplete(data) {
  if (data.task_id !== taskId.value) return
  clearInterval(pollTimer)
  progress.value = 100
  progressText.value = '收集完成'
  loadResults()
}

async function loadResults() {
  if (!taskId.value) return
  try {
    const osintResults = await GetOsintResults(taskId.value)
    const mapped = {}
    for (const r of (osintResults || [])) {
      try { mapped[r.module] = JSON.parse(r.data) } catch { mapped[r.module] = r.data }
    }
    results.value = mapped
    scanning.value = false
    saveResults()
  } catch (e) { console.error(e) }
}

async function startOsint() {
  if (!form.value.target.trim()) return
  if (Object.keys(results.value).length > 0) {
    try { await ElMessageBox.confirm('保留当前收集结果？', '确认', { confirmButtonText: '保留', cancelButtonText: '清空', type: 'warning', distinguishCancelAndClose: true }) } catch (a) { if (a === 'cancel') clearResults(); else return }
  }
  scanning.value = true
  progress.value = 0
  progressText.value = '正在初始化...'
  results.value = {}
  try {
    taskId.value = await StartOsint(form.value.target, form.value.modules)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        if (status.status === 'completed') { clearInterval(pollTimer); progress.value = 100; await loadResults() }
      } catch (e) {}
    }, 1000)
  } catch (e) { scanning.value = false; console.error(e) }
}

async function stopOsint() {
  if (taskId.value) {
    try { await StopScanTask(taskId.value) } catch (e) {}
    clearInterval(pollTimer)
    scanning.value = false
  }
}

async function exportResults() {
  if (!taskId.value) return
  try {
    const content = await ExportResults(taskId.value, 'markdown')
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `osint_${taskId.value}.md`; a.click()
    URL.revokeObjectURL(url)
  } catch (e) {}
}

onMounted(() => { loadSavedResults(); EventsOn('scan:progress', onProgress); EventsOn('scan:complete', onComplete) })
onUnmounted(() => { EventsOff('scan:progress'); EventsOff('scan:complete'); if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.result-link { color: var(--primary-color); cursor: pointer; font-size: 12px; font-family: monospace; text-decoration: none; } .result-link:hover { text-decoration: underline; }
</style>
