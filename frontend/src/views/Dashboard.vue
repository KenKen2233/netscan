<template>
  <div>
    <div class="page-header">
      <h2>📊 仪表盘</h2>
      <p>NetScan Pro v2.0.0 — 网络安全扫描工具总览</p>
    </div>

    <!-- Quick Scan -->
    <div class="card" style="margin-bottom:16px">
      <div class="card-title" style="margin-bottom:12px">⚡ 快速扫描</div>
      <div style="display:flex;gap:12px;align-items:flex-end">
        <div style="flex:1">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px">目标地址</div>
          <el-input v-model="quickTarget" placeholder="IP / 域名 / CIDR，如 192.168.1.1 或 example.com" size="large" clearable />
        </div>
        <div style="width:160px">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:4px">扫描类型</div>
          <el-select v-model="quickType" size="large" style="width:100%">
            <el-option label="🔌 端口扫描" value="portscan" />
            <el-option label="🔍 Web 指纹" value="webfinger" />
            <el-option label="⚠️ 漏洞检测" value="poc" />
            <el-option label="📂 目录扫描" value="dirscan" />
          </el-select>
        </div>
        <el-button type="primary" size="large" @click="quickScan" :disabled="!quickTarget.trim()">
          🚀 扫描
        </el-button>
      </div>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid">
      <div class="stat-card"><span class="label">📁 项目总数</span><span class="value info">{{ stats.total_projects || 0 }}</span></div>
      <div class="stat-card"><span class="label">🔍 扫描任务</span><span class="value">{{ stats.total_tasks || 0 }}</span></div>
      <div class="stat-card"><span class="label">⚡ 运行中</span><span class="value success">{{ stats.running_tasks || 0 }}</span></div>
      <div class="stat-card"><span class="label">🔓 开放端口</span><span class="value info">{{ stats.total_open_ports || 0 }}</span></div>
      <div class="stat-card"><span class="label">🐛 漏洞总数</span><span class="value danger">{{ stats.total_vulns || 0 }}</span></div>
      <div class="stat-card"><span class="label">🔴 严重</span><span class="value danger">{{ stats.vuln_critical || 0 }}</span></div>
      <div class="stat-card"><span class="label">🟠 高危</span><span class="value" style="color:#ff6b6b">{{ stats.vuln_high || 0 }}</span></div>
      <div class="stat-card"><span class="label">🟡 中危</span><span class="value warning">{{ stats.vuln_medium || 0 }}</span></div>
    </div>

    <!-- Charts -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
      <div class="card">
        <div class="card-title" style="margin-bottom:12px">漏洞严重程度分布</div>
        <div ref="vulnChart" style="height:250px"></div>
      </div>
      <div class="card">
        <div class="card-title" style="margin-bottom:12px">任务类型分布</div>
        <div ref="taskChart" style="height:250px"></div>
      </div>
    </div>

    <!-- Recent Tasks -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">最近任务</span>
        <el-button text type="primary" size="small" @click="$router.push('/projects')">查看全部 →</el-button>
      </div>
      <div v-if="!recentTasks.length" style="text-align:center;padding:40px;color:var(--text-secondary)">暂无扫描任务</div>
      <el-table v-else :data="recentTasks" stripe style="width:100%" max-height="300">
        <el-table-column prop="id" label="ID" width="60" sortable />
        <el-table-column prop="type" label="类型" width="100" sortable>
          <template #default="{ row }"><el-tag size="small">{{ getTypeLabel(row.type) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="targets" label="目标" min-width="200" show-overflow-tooltip />
        <el-table-column prop="status" label="状态" width="80" sortable>
          <template #default="{ row }">
            <el-tag :type="row.status === 'completed' ? 'success' : row.status === 'running' ? '' : 'info'" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="found" label="发现" width="60" sortable />
        <el-table-column prop="created_at" label="时间" width="160" sortable />
      </el-table>
    </div>

    <div class="card" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div style="color:var(--text-secondary);font-size:13px">⚠️ 免责声明：本工具仅用于合法授权的安全测试。使用者需遵守当地法律法规。</div>
        <div style="font-size:12px;color:var(--text-muted);text-align:right">作者：A_Kanaki_1 · 微信：Baiyh322</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { GetScanStats, GetRecentTasks } from '../wailsjs/go/app/App'

const router = useRouter()
const stats = ref({})
const recentTasks = ref([])
const vulnChart = ref(null)
const taskChart = ref(null)
const quickTarget = ref('')
const quickType = ref('portscan')

function getTypeLabel(type) {
  return { portscan: '端口扫描', webfinger: 'Web指纹', poc: '漏洞检测', brute: '弱口令', dirscan: '目录扫描', osint: '信息收集' }[type] || type
}

function quickScan() {
  const t = quickTarget.value.trim()
  if (!t) return
  const routeMap = { portscan: '/portscan', webfinger: '/webfinger', poc: '/poc', dirscan: '/dirscan' }
  router.push(routeMap[quickType.value] || '/portscan')
}

function initCharts() {
  if (vulnChart.value) {
    const chart = echarts.init(vulnChart.value)
    chart.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie', radius: ['40%', '70%'],
        data: [
          { value: stats.value.vuln_critical || 0, name: '严重', itemStyle: { color: '#f56c6c' } },
          { value: stats.value.vuln_high || 0, name: '高危', itemStyle: { color: '#e6a23c' } },
          { value: stats.value.vuln_medium || 0, name: '中危', itemStyle: { color: '#409eff' } },
          { value: stats.value.vuln_low || 0, name: '低危', itemStyle: { color: '#67c23a' } }
        ],
        label: { color: '#c9d1d9', fontSize: 12 }
      }]
    })
  }
  if (taskChart.value) {
    const chart = echarts.init(taskChart.value)
    chart.setOption({
      tooltip: { trigger: 'item' },
      series: [{
        type: 'pie', radius: ['40%', '70%'],
        data: [
          { value: stats.value.tasks_portscan || 0, name: '端口扫描' },
          { value: stats.value.tasks_webfinger || 0, name: 'Web指纹' },
          { value: stats.value.tasks_poc || 0, name: '漏洞检测' },
          { value: stats.value.tasks_brute || 0, name: '弱口令' },
          { value: stats.value.tasks_dirscan || 0, name: '目录扫描' },
          { value: stats.value.tasks_osint || 0, name: '信息收集' }
        ],
        label: { color: '#c9d1d9', fontSize: 12 }
      }]
    })
  }
}

onMounted(async () => {
  try {
    stats.value = await GetScanStats()
    recentTasks.value = await GetRecentTasks(10) || []
  } catch (e) { console.error(e) }
  await nextTick()
  initCharts()
})
</script>
