<template>
  <div>
    <div class="page-header">
      <h2>⚠️ POC 漏洞检测</h2>
      <p>基于Nuclei模板的漏洞检测引擎，支持IP/域名/URL</p>
    </div>

    <div class="card">
      <div class="card-title" style="margin-bottom:16px">检测配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标地址">
          <el-input v-model="form.targets" type="textarea" :rows="4" placeholder="支持多种格式，每行一个：&#10;192.168.1.1&#10;example.com&#10;http://example.com&#10;https://example.com:8443" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="严重程度">
            <el-select v-model="form.severity" style="width:100%">
              <el-option label="全部" value="" />
              <el-option label="Critical" value="critical" />
              <el-option label="High" value="high" />
              <el-option label="Medium" value="medium" />
              <el-option label="Low" value="low" />
              <el-option label="Info" value="info" />
            </el-select>
          </el-form-item>
          <el-form-item label="最大并发">
            <el-input-number v-model="form.maxConn" :min="1" :max="100" />
          </el-form-item>
        </div>
        <el-form-item label="超时时间(ms)">
          <el-input-number v-model="form.timeout" :min="1000" :max="30000" :step="1000" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">
            {{ scanning ? '检测中...' : '🚀 开始检测' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="success" @click="exportResults" size="large">📥 导出</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
          <el-button type="info" @click="updatePocs" :loading="updating" size="large">🔄 更新 POC 库</el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- Progress -->
    <div class="card" v-if="scanning">
      <div class="card-header">
        <span class="card-title">检测进度</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="8" style="margin-bottom:12px" />
      <div style="display:flex;gap:24px;font-size:13px;color:var(--text-secondary)">
        <span>已发现: <b style="color:var(--danger-color)">{{ results.length }}</b> 个漏洞</span>
        <span>严重: <b style="color:#f56c6c">{{ severityStats.critical }}</b></span>
        <span>高危: <b style="color:#e6a23c">{{ severityStats.high }}</b></span>
      </div>
    </div>

    <!-- Results -->
    <div class="card" v-if="results.length > 0">
      <div class="card-header">
        <span class="card-title">检测结果 ({{ results.length }})</span>
        <div style="display:flex;gap:8px;align-items:center">
          <el-input v-model="searchText" placeholder="搜索..." size="small" style="width:200px" clearable />
          <el-select v-model="filterSeverity" size="small" style="width:120px" clearable placeholder="严重程度">
            <el-option label="全部" value="" />
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
          </el-select>
        </div>
      </div>

      <el-table :data="filteredResults" stripe style="width:100%" max-height="500">
        <el-table-column label="目标URL" min-width="200">
          <template #default="{ row }">
            <a class="result-link" @click.prevent="openURL(row.url)" :title="row.url">{{ row.url }}</a>
          </template>
        </el-table-column>
        <el-table-column prop="poc_name" label="漏洞名称" width="140" sortable />
        <el-table-column prop="cve_id" label="CVE" width="130" sortable />
        <el-table-column prop="severity" label="严重程度" width="90" sortable>
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="70">
          <template #default="{ row }">
            <el-tag :type="row.vulnerable ? 'danger' : 'info'" size="small">
              {{ row.vulnerable ? '存在' : '安全' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button text type="primary" size="small" @click="openURL(row.url)">访问</el-button>
            <el-button text type="primary" size="small" @click="showDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Detail Dialog -->
    <el-dialog v-model="detailVisible" title="漏洞详情" width="600px">
      <div v-if="detailData">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="URL">
            <a class="result-link" @click.prevent="openURL(detailData.url)">{{ detailData.url }}</a>
          </el-descriptions-item>
          <el-descriptions-item label="漏洞名称">{{ detailData.poc_name }}</el-descriptions-item>
          <el-descriptions-item label="CVE">{{ detailData.cve_id || '-' }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">
            <el-tag :type="severityType(detailData.severity)">{{ detailData.severity }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="请求">{{ detailData.request }}</el-descriptions-item>
          <el-descriptions-item label="响应">{{ detailData.response }}</el-descriptions-item>
          <el-descriptions-item label="描述">{{ detailData.description }}</el-descriptions-item>
        </el-descriptions>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import { StartPocScan, GetPocResults, GetScanTaskStatus, StopScanTask, ExportResults, OpenURL, UpdatePocTemplates } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_poc_results'

const form = ref({ targets: '', severity: '', maxConn: 20, timeout: 5000 })
const scanning = ref(false)
const scanComplete = ref(false)
const progress = ref(0)
const results = ref([])
const taskId = ref(null)
const searchText = ref('')
const filterSeverity = ref('')
const updating = ref(false)
const detailVisible = ref(false)
const detailData = ref(null)
let pollTimer = null

const severityStats = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  results.value.forEach(r => { if (counts[r.severity] !== undefined) counts[r.severity]++ })
  return counts
})

const filteredResults = computed(() => {
  let list = results.value
  if (searchText.value) {
    const q = searchText.value.toLowerCase()
    list = list.filter(r =>
      (r.poc_name || '').toLowerCase().includes(q) ||
      (r.cve_id || '').toLowerCase().includes(q) ||
      (r.url || '').toLowerCase().includes(q)
    )
  }
  if (filterSeverity.value) list = list.filter(r => r.severity === filterSeverity.value)
  return list
})

function severityType(s) {
  return { critical: 'danger', high: 'warning', medium: '', low: 'success', info: 'info' }[s] || 'info'
}

function saveResults() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ results: results.value, taskId: taskId.value, timestamp: Date.now() })) } catch (e) {}
}

function loadResults() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved) {
      const data = JSON.parse(saved)
      if (data.results?.length > 0) { results.value = data.results; taskId.value = data.taskId; scanComplete.value = true }
    }
  } catch (e) {}
}

function clearResults() {
  results.value = []; taskId.value = null; scanComplete.value = false; localStorage.removeItem(STORAGE_KEY)
}

function onPocResult(data) {
  if (data.task_id !== taskId.value) return
  if (!results.value.find(r => r.url === data.url && r.poc_name === data.poc_name)) {
    results.value.push(data); saveResults()
  }
}

function onScanProgress(data) { if (data.task_id === taskId.value) progress.value = data.progress || 0 }

function onScanComplete(data) {
  if (data.task_id !== taskId.value) return
  clearInterval(pollTimer); scanning.value = false; scanComplete.value = true; progress.value = 100; loadFinal()
}

async function loadFinal() {
  if (!taskId.value) return
  try { const res = await GetPocResults(taskId.value); if (res?.length > 0) results.value = res; saveResults() } catch (e) {}
}

async function startScan() {
  if (!form.value.targets.trim()) return
  if (results.value.length > 0) {
    try { await ElMessageBox.confirm(`当前有 ${results.value.length} 条历史结果，是否保留？`, '扫描确认', { confirmButtonText: '保留并继续', cancelButtonText: '清空重扫', type: 'warning', distinguishCancelAndClose: true }) }
    catch (action) { if (action === 'cancel') clearResults(); else return }
  }
  scanning.value = true; scanComplete.value = false; progress.value = 0
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)
  try {
    taskId.value = await StartPocScan(targets, form.value.severity, form.value.maxConn, form.value.timeout)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        if (status.status === 'completed' || status.status === 'stopped') { clearInterval(pollTimer); scanning.value = false; scanComplete.value = true; progress.value = 100; await loadFinal() }
      } catch (e) {}
    }, 3000)
  } catch (e) { scanning.value = false; console.error(e) }
}

async function stopScan() {
  if (taskId.value) { try { await StopScanTask(taskId.value) } catch (e) {} clearInterval(pollTimer); scanning.value = false; scanComplete.value = true }
}

async function exportResults() {
  if (!taskId.value) return
  try {
    const content = await ExportResults(taskId.value, 'markdown')
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `poc_${taskId.value}.md`; a.click()
    URL.revokeObjectURL(url)
  } catch (e) {}
}

function openURL(url) { OpenURL(url).catch(e => console.error(e)) }
function showDetail(row) { detailData.value = row; detailVisible.value = true }

async function updatePocs() {
  updating.value = true
  try {
    const count = await UpdatePocTemplates()
    alert(`POC 库更新完成，新增 ${count} 个模板`)
  } catch (e) { alert('更新失败: ' + e) }
  updating.value = false
}

onMounted(() => { loadResults(); EventsOn('poc:result', onPocResult); EventsOn('scan:progress', onScanProgress); EventsOn('scan:complete', onScanComplete) })
onUnmounted(() => { EventsOff('poc:result'); EventsOff('scan:progress'); EventsOff('scan:complete'); if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.result-link { color: var(--primary-color); cursor: pointer; font-size: 12px; font-family: monospace; text-decoration: none; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
.result-link:hover { text-decoration: underline; color: #66b1ff; }
</style>
