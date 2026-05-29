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
          <el-input v-model="form.targets" type="textarea" :rows="2" placeholder="每行一个URL" />
        </el-form-item>
        <div class="form-row">
          <el-form-item label="字典选择">
            <el-select v-model="form.wordlist" style="width:100%">
              <el-option label="默认字典 (Top 100)" value="default" />
              <el-option label="自定义字典" value="custom" />
            </el-select>
          </el-form-item>
          <el-form-item label="最大并发">
            <el-input-number v-model="form.maxConn" :min="1" :max="500" />
          </el-form-item>
        </div>
        <el-form-item v-if="form.wordlist === 'custom'" label="自定义字典">
          <el-input v-model="form.customWordlist" type="textarea" :rows="4" placeholder="每行一个路径" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">
            {{ scanning ? '扫描中...' : '🚀 开始扫描' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">扫描结果 ({{ results.length }})</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="6" style="margin-bottom:16px" />
      <table class="data-table">
        <thead>
          <tr><th>URL</th><th>状态码</th><th>大小</th><th>标题</th><th>响应时间</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in results" :key="r.url">
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.url }}</td>
            <td><el-tag :type="r.status_code < 300 ? 'success' : r.status_code < 400 ? 'warning' : 'danger'" size="small">{{ r.status_code }}</el-tag></td>
            <td>{{ r.content_length }}B</td>
            <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ r.title || '-' }}</td>
            <td>{{ r.response_time }}ms</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onUnmounted } from 'vue'
import { StartDirScan, GetDirResults, GetScanTaskStatus, StopScanTask } from '../wailsjs/go/app/App'

const form = ref({ targets: '', wordlist: 'default', customWordlist: '', maxConn: 100, timeout: 5000 })
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
  const wordlist = form.value.wordlist === 'custom' ? form.value.customWordlist : ''
  try {
    taskId.value = await StartDirScan(targets, wordlist, form.value.maxConn, form.value.timeout)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        const res = await GetDirResults(taskId.value)
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
