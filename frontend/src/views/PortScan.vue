<template>
  <div>
    <div class="page-header">
      <h2>🔌 端口扫描</h2>
      <p>TCP/UDP端口扫描，发现开放服务</p>
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
        </el-form-item>
      </el-form>
    </div>

    <div class="card" v-if="scanning || results.length > 0">
      <div class="card-header">
        <span class="card-title">扫描结果 ({{ results.length }})</span>
        <span style="color:var(--text-secondary);font-size:13px">{{ progress }}%</span>
      </div>
      <el-progress :percentage="progress" :status="progress === 100 ? 'success' : ''" :stroke-width="6" style="margin-bottom:16px" />
      <div style="max-height:500px;overflow:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>端口</th>
              <th>协议</th>
              <th>服务</th>
              <th>版本</th>
              <th>状态</th>
              <th>响应时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in results" :key="item.ip + ':' + item.port">
              <td style="font-family:monospace">{{ item.ip }}</td>
              <td class="port-num">{{ item.port }}</td>
              <td>{{ item.protocol || 'tcp' }}</td>
              <td class="service">{{ item.service || '-' }}</td>
              <td style="color:var(--text-secondary)">{{ item.version || '-' }}</td>
              <td><el-tag type="success" size="small">{{ item.state }}</el-tag></td>
              <td>{{ item.response_time }}ms</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onUnmounted } from 'vue'
import { StartPortScan, GetPortResults, GetScanTaskStatus, StopScanTask } from '../wailsjs/go/app/App'

const form = ref({
  targets: '',
  portPreset: 'top100',
  customPorts: '',
  mode: 'tcp',
  maxConn: 500,
  timeout: 500
})

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

  const ports = form.value.portPreset === 'custom' ? form.value.customPorts : form.value.portPreset
  const targets = form.value.targets.split('\n').map(s => s.trim()).filter(Boolean)

  try {
    taskId.value = await StartPortScan(targets, ports, form.value.mode, form.value.timeout, form.value.maxConn)
    pollTimer = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId.value)
        progress.value = status.progress || 0
        const res = await GetPortResults(taskId.value)
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
