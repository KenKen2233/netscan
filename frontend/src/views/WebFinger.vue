<template>
  <div>
    <div class="page-header">
      <h2>🔍 Web 指纹识别</h2>
      <p>识别目标的CMS、框架、服务器、CDN等信息</p>
    </div>
    <div class="card">
      <div class="card-title" style="margin-bottom:16px">识别配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标地址">
          <el-input v-model="form.targets" type="textarea" :rows="3" placeholder="每行一个URL&#10;http://example.com&#10;https://example.com" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="最大并发"><el-input-number v-model="form.maxConn" :min="1" :max="200" /></el-form-item>
          <el-form-item label="超时时间(ms)"><el-input-number v-model="form.timeout" :min="1000" :max="30000" :step="1000" /></el-form-item>
        </div>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">{{ scanning ? '识别中...' : '🚀 开始识别' }}</el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="success" @click="exportResults" size="large">📥 导出</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
        </el-form-item>
      </el-form>
    </div>
    <div class="card" v-if="scanning">
      <el-progress :percentage="progress" :stroke-width="8" style="margin-bottom:8px" />
      <span style="font-size:13px;color:var(--text-secondary)">{{ progress }}% · 已识别 {{ results.length }} 个目标</span>
    </div>
    <div class="card" v-if="results.length > 0">
      <div class="card-header">
        <span class="card-title">识别结果 ({{ results.length }})</span>
        <el-input v-model="searchText" placeholder="搜索..." size="small" style="width:200px" clearable />
      </div>
      <el-table :data="filteredResults" stripe style="width:100%" max-height="500">
        <el-table-column label="URL" min-width="200">
          <template #default="{ row }"><a class="result-link" @click.prevent="openURL(row.url)">{{ row.url }}</a></template>
        </el-table-column>
        <el-table-column prop="status_code" label="状态码" width="80" sortable />
        <el-table-column prop="title" label="标题" width="150" show-overflow-tooltip />
        <el-table-column prop="server" label="服务器" width="120" />
        <el-table-column prop="cms" label="CMS" width="120" sortable />
        <el-table-column prop="language" label="语言" width="80" />
        <el-table-column prop="cdn" label="CDN" width="100" />
        <el-table-column label="操作" width="70" fixed="right">
          <template #default="{ row }"><el-button text type="primary" size="small" @click="openURL(row.url)">访问</el-button></template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import { StartWebFinger, GetWebFingerResults, GetScanTaskStatus, StopScanTask, ExportResults, OpenURL } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_webfinger_results'
const form = ref({ targets: '', maxConn: 50, timeout: 5000 })
const scanning = ref(false); const progress = ref(0); const results = ref([]); const taskId = ref(null); const searchText = ref(''); let pollTimer = null

const filteredResults = computed(() => {
  if (!searchText.value) return results.value
  const q = searchText.value.toLowerCase()
  return results.value.filter(r => (r.url||'').toLowerCase().includes(q) || (r.cms||'').toLowerCase().includes(q))
})

function saveResults() { try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ results: results.value, taskId: taskId.value })) } catch(e){} }
function loadResults() { try { const s = localStorage.getItem(STORAGE_KEY); if (s) { const d = JSON.parse(s); if (d.results?.length > 0) { results.value = d.results; taskId.value = d.taskId } } } catch(e){} }
function clearResults() { results.value = []; taskId.value = null; localStorage.removeItem(STORAGE_KEY) }

function onResult(data) { if (data.task_id === taskId.value) { const i = results.value.findIndex(r => r.url === data.url); if (i === -1) results.value.push(data); else results.value[i] = data; saveResults() } }
function onProgress(data) { if (data.task_id === taskId.value) progress.value = data.progress || 0 }
function onComplete(data) { if (data.task_id === taskId.value) { clearInterval(pollTimer); scanning.value = false; progress.value = 100; loadFinal() } }
async function loadFinal() { if (!taskId.value) return; try { const r = await GetWebFingerResults(taskId.value); if (r?.length > 0) results.value = r; saveResults() } catch(e){} }

async function startScan() {
  if (!form.value.targets.trim()) return
  if (results.value.length > 0) { try { await ElMessageBox.confirm(`保留当前 ${results.value.length} 条结果？`, '确认', { confirmButtonText: '保留', cancelButtonText: '清空', type: 'warning', distinguishCancelAndClose: true }) } catch(a) { if (a === 'cancel') clearResults(); else return } }
  scanning.value = true; progress.value = 0
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)
  try {
    taskId.value = await StartWebFinger(targets, form.value.timeout, form.value.maxConn)
    pollTimer = setInterval(async () => { try { const s = await GetScanTaskStatus(taskId.value); progress.value = s.progress || 0; if (s.status === 'completed' || s.status === 'stopped') { clearInterval(pollTimer); scanning.value = false; progress.value = 100; await loadFinal() } } catch(e){} }, 3000)
  } catch(e) { scanning.value = false }
}

async function stopScan() { if (taskId.value) { try { await StopScanTask(taskId.value) } catch(e){} clearInterval(pollTimer); scanning.value = false } }
async function exportResults() { if (!taskId.value) return; try { const c = await ExportResults(taskId.value, 'markdown'); const b = new Blob([c], {type:'text/markdown'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `webfinger_${taskId.value}.md`; a.click(); URL.revokeObjectURL(u) } catch(e){} }
function openURL(url) { OpenURL(url).catch(e => console.error(e)) }

onMounted(() => { loadResults(); EventsOn('webfinger:result', onResult); EventsOn('scan:progress', onProgress); EventsOn('scan:complete', onComplete) })
onUnmounted(() => { EventsOff('webfinger:result'); EventsOff('scan:progress'); EventsOff('scan:complete'); if (pollTimer) clearInterval(pollTimer) })
</script>
<style scoped>.result-link { color: var(--primary-color); cursor: pointer; font-size: 12px; font-family: monospace; text-decoration: none; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; } .result-link:hover { text-decoration: underline; }</style>
