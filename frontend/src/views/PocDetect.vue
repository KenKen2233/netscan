<template>
  <div>
    <div class="page-header">
      <h2>⚠️ POC 漏洞检测</h2>
      <p>基于Nuclei模板的漏洞检测引擎</p>
    </div>

    <div class="card">
      <div class="card-title" style="margin-bottom:16px">检测配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标URL">
          <el-input v-model="form.targets" type="textarea" :rows="3" placeholder="每行一个URL" />
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
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">
            {{ scanning ? '检测中...' : '🚀 开始检测' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">检测结果 ({{ results.length }})</span>
        <div style="display:flex;gap:8px">
          <el-tag v-for="s in severityStats" :key="s.type" :type="s.type" size="small">{{ s.label }}: {{ s.count }}</el-tag>
        </div>
      </div>
      <el-progress :percentage="progress" :status="progress === 100 ? 'success' : ''" :stroke-width="6" style="margin-bottom:16px" />
      <div style="max-height:500px;overflow:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>漏洞名称</th>
              <th>CVE</th>
              <th>严重程度</th>
              <th>验证结果</th>
              <th>描述</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in results" :key="r.url + r.poc_name">
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.url }}</td>
              <td style="font-weight:600">{{ r.poc_name }}</td>
              <td style="color:var(--accent-color)">{{ r.cve_id || '-' }}</td>
              <td><span class="severity-tag" :class="r.severity">{{ r.severity }}</span></td>
              <td><el-tag :type="r.vulnerable ? 'danger' : 'info'" size="small">{{ r.vulnerable ? '存在' : '未发现' }}</el-tag></td>
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.description || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onUnmounted } from 'vue'
import { StartPocScan, GetPocResults, GetScanTaskStatus, StopScanTask } from '../wailsjs/go/app/App'

const form = ref({ targets: '', severity: '', maxConn: 20, timeout: 5000 })
const scanning = ref(false)
const progress = ref(0)
const results = ref([])
const taskId = ref(null)
let pollTimer = null

const severityStats = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  results.value.forEach(r => { if (counts[r.severity] !== undefined) counts[r.severity]++ })
  return [
    { type: 'danger', label: 'Critical', count: counts.critical },
    { type: 'warning', label: 'High', count: counts.high },
    { type: '', label: 'Medium', count: counts.medium },
    { type: 'success', label: 'Low', count: counts.low },
    { type: 'info', label: 'Info', count: counts.info }
  ]
})

async function startScan() {
  if (!form.value.targets.trim()) return
  scanning.value = true
  progress.value = 0
  results.value = []
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)
  try {
    taskId.value = await StartPocScan(targets, form.value.severity, form.value.maxConn, form.value.timeout)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        const res = await GetPocResults(taskId.value)
        results.value = res || []
        if (status.status === 'completed' || status.status === 'stopped') {
          clearInterval(pollTimer)
          scanning.value = false
          progress.value = 100
        }
      } catch (e) { console.error(e) }
    }, 1000)
  } catch (e) { scanning.value = false; console.error(e) }
}

async function stopScan() {
  if (taskId.value) {
    await StopScanTask(taskId.value)
    clearInterval(pollTimer)
    scanning.value = false
  }
}

onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>
