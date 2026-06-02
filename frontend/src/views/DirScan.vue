<template>
  <div>
    <div class="page-header">
      <h2>📂 目录扫描</h2>
      <p>Web应用目录和文件枚举</p>
    </div>
    <div class="card">
      <div class="card-title" style="margin-bottom:16px">扫描配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标URL">
          <el-input v-model="form.targets" type="textarea" :rows="2" placeholder="每行一个URL&#10;http://example.com&#10;https://example.com" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="字典选择">
            <el-select v-model="form.wordlist" style="width:100%">
              <el-option label="默认字典 (Top 100)" value="default" />
              <el-option label="自定义字典" value="custom" />
            </el-select>
          </el-form-item>
          <el-form-item label="最大并发"><el-input-number v-model="form.maxConn" :min="1" :max="500" /></el-form-item>
        </div>
        <el-form-item v-if="form.wordlist === 'custom'" label="自定义字典">
          <el-input v-model="form.customWordlist" type="textarea" :rows="4" placeholder="每行一个路径" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">{{ scanning ? '扫描中...' : '🚀 开始扫描' }}</el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="success" @click="exportResults" size="large">📥 导出</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
        </el-form-item>
      </el-form>
    </div>
    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">扫描结果 ({{ results.length }})</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="6" style="margin-bottom:16px" />
      <el-table :data="results" stripe style="width:100%" max-height="500">
        <el-table-column label="URL" min-width="250">
          <template #default="{ row }"><a class="result-link" @click.prevent="openURL(row.url)">{{ row.url }}</a></template>
        </el-table-column>
        <el-table-column prop="status_code" label="状态码" width="80" sortable>
          <template #default="{ row }"><el-tag :type="row.status_code < 300 ? 'success' : row.status_code < 400 ? 'warning' : 'danger'" size="small">{{ row.status_code }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="content_length" label="大小" width="80" sortable><template #default="{ row }">{{ row.content_length }}B</template></el-table-column>
        <el-table-column prop="title" label="标题" width="150" show-overflow-tooltip />
        <el-table-column prop="response_time" label="响应" width="80" sortable><template #default="{ row }">{{ row.response_time }}ms</template></el-table-column>
        <el-table-column label="操作" width="70" fixed="right">
          <template #default="{ row }"><el-button text type="primary" size="small" @click="openURL(row.url)">访问</el-button></template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import { StartDirScan, GetDirResults, GetScanTaskStatus, StopScanTask, ExportResults, OpenURL } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_dirscan_results'
const form = ref({ targets: '', wordlist: 'default', customWordlist: '', maxConn: 100, timeout: 5000 })
const scanning = ref(false); const progress = ref(0); const results = ref([]); const taskId = ref(null); let pollTimer = null

function saveResults() { try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ results: results.value, taskId: taskId.value })) } catch(e){} }
function loadResults() { try { const s = localStorage.getItem(STORAGE_KEY); if (s) { const d = JSON.parse(s); if (d.results?.length > 0) { results.value = d.results; taskId.value = d.taskId } } } catch(e){} }
function clearResults() { results.value = []; taskId.value = null; localStorage.removeItem(STORAGE_KEY) }

function onResult(data) { if (data.task_id === taskId.value) { if (!results.value.find(r => r.url === data.url)) { results.value.push(data); saveResults() } } }
function onProgress(data) { if (data.task_id === taskId.value) progress.value = data.progress || 0 }
function onComplete(data) { if (data.task_id === taskId.value) { clearInterval(pollTimer); scanning.value = false; progress.value = 100; loadFinal() } }
async function loadFinal() { if (!taskId.value) return; try { const r = await GetDirResults(taskId.value); if (r?.length > 0) results.value = r; saveResults() } catch(e){} }

async function startScan() {
  if (!form.value.targets.trim()) return
  if (results.value.length > 0) { try { await ElMessageBox.confirm(`保留当前 ${results.value.length} 条结果？`, '确认', { confirmButtonText: '保留', cancelButtonText: '清空', type: 'warning', distinguishCancelAndClose: true }) } catch(a) { if (a === 'cancel') clearResults(); else return } }
  scanning.value = true; progress.value = 0
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)
  const wordlist = form.value.wordlist === 'custom' ? form.value.customWordlist : ''
  try {
    taskId.value = await StartDirScan(targets, wordlist, form.value.maxConn, form.value.timeout)
    pollTimer = setInterval(async () => { try { const s = await GetScanTaskStatus(taskId.value); progress.value = s.progress || 0; if (s.status === 'completed' || s.status === 'stopped') { clearInterval(pollTimer); scanning.value = false; progress.value = 100; await loadFinal() } } catch(e){} }, 3000)
  } catch(e) { scanning.value = false }
}

async function stopScan() { if (taskId.value) { try { await StopScanTask(taskId.value) } catch(e){} clearInterval(pollTimer); scanning.value = false } }
async function exportResults() { if (!taskId.value) return; try { const c = await ExportResults(taskId.value, 'markdown'); const b = new Blob([c], {type:'text/markdown'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `dirscan_${taskId.value}.md`; a.click(); URL.revokeObjectURL(u) } catch(e){} }
function openURL(url) { OpenURL(url).catch(e => console.error(e)) }

onMounted(() => { loadResults(); EventsOn('dirscan:result', onResult); EventsOn('scan:progress', onProgress); EventsOn('scan:complete', onComplete) })
onUnmounted(() => { EventsOff('dirscan:result'); EventsOff('scan:progress'); EventsOff('scan:complete'); if (pollTimer) clearInterval(pollTimer) })
</script>
<style scoped>.result-link { color: var(--primary-color); cursor: pointer; font-size: 12px; font-family: monospace; text-decoration: none; max-width: 230px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; } .result-link:hover { text-decoration: underline; }</style>
