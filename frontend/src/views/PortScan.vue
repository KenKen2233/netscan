<template>
  <div>
    <div class="page-header">
      <h2>🔌 端口扫描</h2>
      <p>TCP/UDP端口扫描，发现开放服务并生成可访问链接</p>
    </div>

    <div class="card">
      <div class="card-title" style="margin-bottom:16px">扫描配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标地址">
          <el-input v-model="form.targets" type="textarea" :rows="3" placeholder="支持IP、域名、CIDR，多行分隔&#10;例：192.168.1.0/24&#10;example.com" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="端口范围">
            <el-select v-model="form.portPreset" style="width:100%">
              <el-option label="Top 100 常用端口" value="top100" />
              <el-option label="Top 1000 端口" value="top1000" />
              <el-option label="全端口 (1-65535)" value="all" />
              <el-option label="自定义" value="custom" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="form.portPreset === 'custom'" label="自定义端口">
            <el-input v-model="form.customPorts" placeholder="80,443,8080-8090" />
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="扫描模式">
            <el-radio-group v-model="form.mode">
              <el-radio-button value="tcp">TCP全连接</el-radio-button>
              <el-radio-button value="syn">SYN半开</el-radio-button>
              <el-radio-button value="udp">UDP</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="最大并发">
            <el-input-number v-model="form.maxConn" :min="10" :max="2000" />
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="超时时间(ms)">
            <el-input-number v-model="form.timeout" :min="100" :max="30000" :step="100" />
          </el-form-item>
        </div>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">
            {{ scanning ? '扫描中...' : '🚀 开始扫描' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="success" @click="exportResults" size="large">📥 导出</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- Progress -->
    <div class="card" v-if="scanning">
      <div class="card-header">
        <span class="card-title">扫描进度</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progressData.completed }}/{{ progressData.total }} ({{ progress }}%)</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="8" style="margin-bottom:12px" />
      <div style="display:flex;gap:24px;font-size:13px;color:var(--text-secondary)">
        <span>已发现: <b style="color:var(--success-color)">{{ results.length }}</b> 个开放端口</span>
        <span>扫描速度: <b>{{ scanSpeed }}</b>/秒</span>
        <span>预计剩余: <b>{{ estimatedTime }}</b></span>
      </div>
    </div>

    <!-- Results -->
    <div class="card" v-if="results.length > 0">
      <div class="card-header">
        <span class="card-title">扫描结果 ({{ results.length }})</span>
        <div style="display:flex;gap:8px;align-items:center">
          <el-input v-model="searchText" placeholder="搜索IP/端口/服务..." size="small" style="width:200px" clearable />
          <el-select v-model="filterState" size="small" style="width:100px" clearable placeholder="状态">
            <el-option label="全部" value="" />
            <el-option label="open" value="open" />
          </el-select>
        </div>
      </div>

      <el-table :data="filteredResults" stripe style="width:100%" max-height="500" :row-key="row => row.ip+':'+row.port">
        <el-table-column prop="ip" label="IP地址" width="140" sortable />
        <el-table-column prop="port" label="端口" width="70" sortable />
        <el-table-column prop="protocol" label="协议" width="60" />
        <el-table-column prop="service" label="服务" width="100" sortable />
        <el-table-column prop="version" label="版本" width="100" />
        <el-table-column prop="state" label="状态" width="70">
          <template #default="{ row }">
            <el-tag :type="row.state === 'open' ? 'success' : 'info'" size="small">{{ row.state }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="链接" min-width="180">
          <template #default="{ row }">
            <div v-if="row.url && row.accessible" style="display:flex;align-items:center;gap:6px">
              <el-tag type="success" size="small" effect="plain">
                {{ row.url_protocol || 'http' }}
              </el-tag>
              <a class="result-link" @click.prevent="openURL(row.url)" :title="row.url">
                {{ row.url }}
              </a>
              <el-button text type="primary" size="small" @click="copyText(row.url)" style="padding:2px">📋</el-button>
            </div>
            <span v-else style="color:var(--text-muted);font-size:12px">{{ row.url ? '不可达' : '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="response_time" label="响应" width="70" sortable>
          <template #default="{ row }">{{ row.response_time }}ms</template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Empty -->
    <div class="card" v-if="!scanning && scanComplete && results.length === 0">
      <div style="text-align:center;padding:40px;color:var(--text-secondary)">
        <p style="font-size:16px;margin-bottom:8px">扫描完成</p>
        <p>未发现开放端口</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import { StartPortScan, GetPortResults, GetScanTaskStatus, StopScanTask, ExportResults, ProbePorts, OpenURL } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_portscan_results'

const form = ref({
  targets: '',
  portPreset: 'top100',
  customPorts: '',
  mode: 'tcp',
  maxConn: 500,
  timeout: 500
})

const scanning = ref(false)
const scanComplete = ref(false)
const progress = ref(0)
const results = ref([])
const taskId = ref(null)
const searchText = ref('')
const filterState = ref('')
const progressData = ref({ completed: 0, total: 0 })
const startTime = ref(0)

let pollTimer = null

// Computed
const filteredResults = computed(() => {
  let list = results.value
  if (searchText.value) {
    const q = searchText.value.toLowerCase()
    list = list.filter(r =>
      r.ip.includes(q) ||
      String(r.port).includes(q) ||
      (r.service || '').toLowerCase().includes(q)
    )
  }
  if (filterState.value) {
    list = list.filter(r => r.state === filterState.value)
  }
  return list
})

const scanSpeed = computed(() => {
  if (!startTime.value || progressData.value.completed === 0) return '0'
  const elapsed = (Date.now() - startTime.value) / 1000
  return Math.round(progressData.value.completed / elapsed)
})

const estimatedTime = computed(() => {
  if (!startTime.value || progressData.value.completed === 0) return '计算中...'
  const elapsed = (Date.now() - startTime.value) / 1000
  const remaining = progressData.value.total - progressData.value.completed
  const speed = progressData.value.completed / elapsed
  if (speed === 0) return '计算中...'
  const secs = Math.round(remaining / speed)
  if (secs < 60) return `${secs}秒`
  if (secs < 3600) return `${Math.floor(secs / 60)}分${secs % 60}秒`
  return `${Math.floor(secs / 3600)}时${Math.floor((secs % 3600) / 60)}分`
})

// Save/Load results
function saveResults() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      results: results.value,
      taskId: taskId.value,
      timestamp: Date.now()
    }))
  } catch (e) { /* ignore */ }
}

function loadResults() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved) {
      const data = JSON.parse(saved)
      if (data.results && data.results.length > 0) {
        results.value = data.results
        taskId.value = data.taskId
        scanComplete.value = true
      }
    }
  } catch (e) { /* ignore */ }
}

function clearResults() {
  results.value = []
  taskId.value = null
  scanComplete.value = false
  localStorage.removeItem(STORAGE_KEY)
}

// Event handlers
function onPortResult(data) {
  if (data.task_id !== taskId.value) return
  const key = data.ip + ':' + data.port
  const idx = results.value.findIndex(r => r.ip + ':' + r.port === key)
  if (idx === -1) {
    results.value.push(data)
    saveResults()
  }
}

function onScanProgress(data) {
  if (data.task_id !== taskId.value) return
  progress.value = data.progress || 0
  progressData.value = { completed: data.completed || 0, total: data.total || 0 }
}

function onScanComplete(data) {
  if (data.task_id !== taskId.value) return
  clearInterval(pollTimer)
  scanning.value = false
  scanComplete.value = true
  progress.value = 100
  // Load final results then probe
  loadAndProbe()
}

async function loadAndProbe() {
  if (!taskId.value) return
  try {
    const res = await GetPortResults(taskId.value)
    if (res && res.length > 0) {
      results.value = res
    }
    // Probe ports for URLs
    try {
      const probed = await ProbePorts(taskId.value)
      if (probed && probed.length > 0) {
        results.value = probed
      }
    } catch (e) { console.error('Probe failed:', e) }
    saveResults()
  } catch (e) { console.error('Load results failed:', e) }
}

async function startScan() {
  if (!form.value.targets.trim()) return

  // Prompt if existing results
  if (results.value.length > 0) {
    try {
      await ElMessageBox.confirm(
        `当前有 ${results.value.length} 条历史扫描结果，是否保留？`,
        '扫描确认',
        {
          confirmButtonText: '保留并继续',
          cancelButtonText: '清空重扫',
          type: 'warning',
          distinguishCancelAndClose: true
        }
      )
      // User chose to keep
    } catch (action) {
      if (action === 'cancel') {
        clearResults()
      } else {
        return // closed dialog
      }
    }
  }

  scanning.value = true
  scanComplete.value = false
  progress.value = 0
  if (results.value.length === 0) results.value = []
  progressData.value = { completed: 0, total: 0 }
  startTime.value = Date.now()

  const ports = form.value.portPreset === 'custom' ? form.value.customPorts : form.value.portPreset
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)

  try {
    taskId.value = await StartPortScan(targets, ports, form.value.mode, form.value.timeout, form.value.maxConn)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        if (status.status === 'completed' || status.status === 'stopped') {
          clearInterval(pollTimer)
          scanning.value = false
          scanComplete.value = true
          progress.value = 100
          await loadAndProbe()
        }
      } catch (e) { /* ignore */ }
    }, 3000)
  } catch (e) {
    scanning.value = false
    console.error('Start scan failed:', e)
  }
}

async function stopScan() {
  if (taskId.value) {
    try { await StopScanTask(taskId.value) } catch (e) { console.error(e) }
    clearInterval(pollTimer)
    scanning.value = false
    scanComplete.value = true
  }
}

async function exportResults() {
  if (!taskId.value) return
  try {
    const content = await ExportResults(taskId.value, 'markdown')
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `portscan_${taskId.value}_${Date.now()}.md`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) { console.error(e) }
}

function openURL(url) {
  OpenURL(url).catch(e => console.error(e))
}

function copyText(text) {
  navigator.clipboard.writeText(text)
}

onMounted(() => {
  loadResults()
  EventsOn('portscan:result', onPortResult)
  EventsOn('scan:progress', onScanProgress)
  EventsOn('scan:complete', onScanComplete)
})

onUnmounted(() => {
  EventsOff('portscan:result')
  EventsOff('scan:progress')
  EventsOff('scan:complete')
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style scoped>
.result-link {
  color: var(--primary-color);
  cursor: pointer;
  font-size: 12px;
  font-family: monospace;
  text-decoration: none;
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
}
.result-link:hover {
  text-decoration: underline;
  color: #66b1ff;
}
</style>
