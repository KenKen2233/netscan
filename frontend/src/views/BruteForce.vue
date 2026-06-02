<template>
  <div>
    <div class="page-header">
      <h2>🔒 弱口令破解</h2>
      <p>支持SSH/FTP/MySQL/Redis等服务的弱口令检测</p>
    </div>
    <div class="card">
      <div class="card-title" style="margin-bottom:16px">破解配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标地址">
          <el-input v-model="form.targets" type="textarea" :rows="2" placeholder="每行一个，支持 IP:端口 或 域名" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="服务类型">
            <el-select v-model="form.service" style="width:100%">
              <el-option label="SSH" value="ssh" /><el-option label="FTP" value="ftp" />
              <el-option label="MySQL" value="mysql" /><el-option label="Redis" value="redis" />
              <el-option label="MSSQL" value="mssql" /><el-option label="PostgreSQL" value="postgresql" />
              <el-option label="MongoDB" value="mongodb" /><el-option label="Telnet" value="telnet" />
              <el-option label="SMB" value="smb" />
            </el-select>
          </el-form-item>
          <el-form-item label="最大并发"><el-input-number v-model="form.maxConn" :min="1" :max="100" /></el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="用户名字典"><el-input v-model="form.usernames" type="textarea" :rows="2" placeholder="留空使用默认字典" /></el-form-item>
          <el-form-item label="密码字典"><el-input v-model="form.passwords" type="textarea" :rows="2" placeholder="留空使用默认字典" /></el-form-item>
        </div>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">{{ scanning ? '破解中...' : '🚀 开始破解' }}</el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="success" @click="exportResults" size="large">📥 导出</el-button>
          <el-button v-if="results.length > 0 && !scanning" type="warning" @click="clearResults" size="large">🗑 清空</el-button>
        </el-form-item>
      </el-form>
    </div>
    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">破解结果 ({{ results.length }})</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="6" style="margin-bottom:16px" />
      <div v-if="results.length === 0 && !scanning" style="text-align:center;padding:20px;color:var(--text-secondary)">未发现弱口令</div>
      <el-table v-else :data="results" stripe style="width:100%" max-height="500">
        <el-table-column label="连接" min-width="200">
          <template #default="{ row }">
            <a class="result-link" @click.prevent="openService(row)">{{ row.service }}://{{ row.target }}</a>
          </template>
        </el-table-column>
        <el-table-column prop="service" label="服务" width="80"><template #default="{ row }"><el-tag size="small">{{ row.service }}</el-tag></template></el-table-column>
        <el-table-column prop="username" label="用户名" width="120"><template #default="{ row }"><span style="color:var(--warning-color);font-weight:600">{{ row.username }}</span></template></el-table-column>
        <el-table-column prop="password" label="密码" width="150"><template #default="{ row }"><span style="color:var(--danger-color);font-weight:700;font-family:monospace">{{ row.password }}</span></template></el-table-column>
        <el-table-column label="操作" width="80" fixed="right">
          <template #default="{ row }"><el-button text type="primary" size="small" @click="copyCreds(row)">复制</el-button></template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessageBox } from 'element-plus'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import { StartBruteForce, GetBruteResults, GetScanTaskStatus, StopScanTask, ExportResults, OpenURL } from '../wailsjs/go/app/App'

const STORAGE_KEY = 'netscan_brute_results'
const form = ref({ targets: '', service: 'ssh', usernames: '', passwords: '', maxConn: 30, timeout: 3000 })
const scanning = ref(false); const progress = ref(0); const results = ref([]); const taskId = ref(null); let pollTimer = null

function saveResults() { try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ results: results.value, taskId: taskId.value })) } catch(e){} }
function loadResults() { try { const s = localStorage.getItem(STORAGE_KEY); if (s) { const d = JSON.parse(s); if (d.results?.length > 0) { results.value = d.results; taskId.value = d.taskId } } } catch(e){} }
function clearResults() { results.value = []; taskId.value = null; localStorage.removeItem(STORAGE_KEY) }

function onResult(data) { if (data.task_id === taskId.value) { if (!results.value.find(r => r.target === data.target && r.username === data.username && r.password === data.password)) { results.value.push(data); saveResults() } } }
function onProgress(data) { if (data.task_id === taskId.value) progress.value = data.progress || 0 }
function onComplete(data) { if (data.task_id === taskId.value) { clearInterval(pollTimer); scanning.value = false; progress.value = 100; loadFinal() } }
async function loadFinal() { if (!taskId.value) return; try { const r = await GetBruteResults(taskId.value); if (r?.length > 0) results.value = r; saveResults() } catch(e){} }

async function startScan() {
  if (!form.value.targets.trim()) return
  if (results.value.length > 0) { try { await ElMessageBox.confirm(`保留当前 ${results.value.length} 条结果？`, '确认', { confirmButtonText: '保留', cancelButtonText: '清空', type: 'warning', distinguishCancelAndClose: true }) } catch(a) { if (a === 'cancel') clearResults(); else return } }
  scanning.value = true; progress.value = 0
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)
  const users = form.value.usernames ? form.value.usernames.split('\n').map(s => s.trim()).filter(Boolean) : []
  const pwds = form.value.passwords ? form.value.passwords.split('\n').map(s => s.trim()).filter(Boolean) : []
  try {
    taskId.value = await StartBruteForce(targets, form.value.service, users, pwds, form.value.maxConn, form.value.timeout)
    pollTimer = setInterval(async () => { try { const s = await GetScanTaskStatus(taskId.value); progress.value = s.progress || 0; if (s.status === 'completed' || s.status === 'stopped') { clearInterval(pollTimer); scanning.value = false; progress.value = 100; await loadFinal() } } catch(e){} }, 3000)
  } catch(e) { scanning.value = false }
}

async function stopScan() { if (taskId.value) { try { await StopScanTask(taskId.value) } catch(e){} clearInterval(pollTimer); scanning.value = false } }
async function exportResults() { if (!taskId.value) return; try { const c = await ExportResults(taskId.value, 'markdown'); const b = new Blob([c], {type:'text/markdown'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `brute_${taskId.value}.md`; a.click(); URL.revokeObjectURL(u) } catch(e){} }

function openService(row) {
  const portMap = { ssh: 22, ftp: 21, mysql: 3306, redis: 6379 }
  const port = row.target.includes(':') ? '' : ':' + (portMap[row.service] || '')
  const url = `${row.service}://${row.target}${port}`
  OpenURL(url).catch(e => console.error(e))
}

function copyCreds(row) { navigator.clipboard.writeText(`${row.username}:${row.password}`) }

onMounted(() => { loadResults(); EventsOn('brute:result', onResult); EventsOn('scan:progress', onProgress); EventsOn('scan:complete', onComplete) })
onUnmounted(() => { EventsOff('brute:result'); EventsOff('scan:progress'); EventsOff('scan:complete'); if (pollTimer) clearInterval(pollTimer) })
</script>
<style scoped>.result-link { color: var(--primary-color); cursor: pointer; font-size: 13px; font-family: monospace; text-decoration: none; } .result-link:hover { text-decoration: underline; }</style>
