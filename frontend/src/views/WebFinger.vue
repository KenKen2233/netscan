<template>
  <div>
    <div class="page-header">
      <h2>🔍 Web 指纹识别</h2>
      <p>批量识别网站CMS、框架、服务器等信息</p>
    </div>

    <div class="card">
      <div class="card-title" style="margin-bottom:16px">扫描配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标URL">
          <el-input v-model="form.targets" type="textarea" :rows="3" placeholder="每行一个URL&#10;http://example.com&#10;https://test.com" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="超时时间">
            <el-input-number v-model="form.timeout" :min="1000" :max="30000" :step="1000" />
          </el-form-item>
          <el-form-item label="最大并发">
            <el-input-number v-model="form.maxConn" :min="1" :max="200" />
          </el-form-item>
        </div>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">
            {{ scanning ? '识别中...' : '🚀 开始识别' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">识别结果 ({{ results.length }})</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :status="progress === 100 ? 'success' : ''" :stroke-width="6" style="margin-bottom:16px" />
      <div style="max-height:500px;overflow:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>状态码</th>
              <th>标题</th>
              <th>服务器</th>
              <th>CMS</th>
              <th>语言</th>
              <th>CDN</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in results" :key="r.url">
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.url }}</td>
              <td><el-tag :type="r.status_code < 300 ? 'success' : r.status_code < 400 ? 'warning' : 'danger'" size="small">{{ r.status_code }}</el-tag></td>
              <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.title || '-' }}</td>
              <td>{{ r.server || '-' }}</td>
              <td><span v-if="r.cms" style="color:var(--success-color);font-weight:600">{{ r.cms }}</span><span v-else>-</span></td>
              <td>{{ r.language || '-' }}</td>
              <td>{{ r.cdn || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onUnmounted } from 'vue'
import { StartWebFinger, GetWebFingerResults, GetScanTaskStatus, StopScanTask } from '../wailsjs/go/app/App'

const form = ref({ targets: '', timeout: 5000, maxConn: 50 })
const scanning = ref(false)
const progress = ref(0)
const results = ref([])
const taskId = ref(null)
let pollTimer = null

async function startScan() {
  if (!form.value.targets.trim()) return
  scanning.value = true
  progress.value = 0
  results.value = []
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)
  try {
    taskId.value = await StartWebFinger(targets, form.value.timeout, form.value.maxConn)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        const res = await GetWebFingerResults(taskId.value)
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
