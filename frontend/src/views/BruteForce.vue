<template>
  <div>
    <div class="page-header">
      <h2>🔒 弱口令破解</h2>
      <p>支持SSH/FTP/MySQL/Redis等10+服务的弱口令检测</p>
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
              <el-option label="SSH" value="ssh" />
              <el-option label="FTP" value="ftp" />
              <el-option label="MySQL" value="mysql" />
              <el-option label="Redis" value="redis" />
            </el-select>
          </el-form-item>
          <el-form-item label="最大并发">
            <el-input-number v-model="form.maxConn" :min="1" :max="100" />
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="用户名字典">
            <el-input v-model="form.usernames" type="textarea" :rows="2" placeholder="留空使用默认字典" />
          </el-form-item>
          <el-form-item label="密码字典">
            <el-input v-model="form.passwords" type="textarea" :rows="2" placeholder="留空使用默认字典" />
          </el-form-item>
        </div>
        <el-form-item>
          <el-button type="primary" @click="startScan" :loading="scanning" size="large">
            {{ scanning ? '破解中...' : '🚀 开始破解' }}
          </el-button>
          <el-button v-if="scanning" type="danger" @click="stopScan" size="large">⏹ 停止</el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">破解结果 ({{ results.length }})</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :stroke-width="6" style="margin-bottom:16px" />
      <div v-if="results.length === 0 && !scanning" style="text-align:center;padding:20px;color:var(--text-secondary)">
        未发现弱口令
      </div>
      <table v-else class="data-table">
        <thead>
          <tr><th>目标</th><th>服务</th><th>用户名</th><th>密码</th><th>状态</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in results" :key="r.target+r.username+r.password">
            <td>{{ r.target }}</td>
            <td><el-tag size="small">{{ r.service }}</el-tag></td>
            <td style="color:var(--warning-color);font-weight:600">{{ r.username }}</td>
            <td style="color:var(--danger-color);font-weight:700;font-family:monospace">{{ r.password }}</td>
            <td><el-tag type="success" size="small">{{ r.status }}</el-tag></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onUnmounted } from 'vue'
import { StartBruteForce, GetBruteResults, GetScanTaskStatus, StopScanTask } from '../wailsjs/go/app/App'

const form = ref({ targets: '', service: 'ssh', usernames: '', passwords: '', maxConn: 30, timeout: 3000 })
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
  const users = form.value.usernames ? form.value.usernames.split('\n').map(s => s.trim()).filter(Boolean) : []
  const pwds = form.value.passwords ? form.value.passwords.split('\n').map(s => s.trim()).filter(Boolean) : []
  try {
    taskId.value = await StartBruteForce(targets, form.value.service, users, pwds, form.value.maxConn, form.value.timeout)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        const res = await GetBruteResults(taskId.value)
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
