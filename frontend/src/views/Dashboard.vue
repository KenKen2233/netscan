<template>
  <div>
    <div class="page-header">
      <h2>📊 仪表盘</h2>
      <p>网络安全扫描工具总览</p>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <span class="label">📁 项目总数</span>
        <span class="value info">{{ stats.total_projects || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">🔍 扫描任务</span>
        <span class="value">{{ stats.total_tasks || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">⚡ 运行中</span>
        <span class="value success">{{ stats.running_tasks || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">🔓 开放端口</span>
        <span class="value info">{{ stats.total_open_ports || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">🐛 漏洞总数</span>
        <span class="value danger">{{ stats.total_vulns || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">🔴 严重</span>
        <span class="value danger">{{ stats.vuln_critical || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">🟠 高危</span>
        <span class="value" style="color:#ff6b6b">{{ stats.vuln_high || 0 }}</span>
      </div>
      <div class="stat-card">
        <span class="label">🟡 中危</span>
        <span class="value warning">{{ stats.vuln_medium || 0 }}</span>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">最近任务</span>
      </div>
      <div v-if="!recentTasks.length" style="text-align:center;padding:40px;color:var(--text-secondary)">
        暂无扫描任务
      </div>
      <div v-else>
        <div v-for="task in recentTasks" :key="task.id" style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border-color)">
          <span class="status-dot" :class="task.status"></span>
          <span style="font-weight:500;min-width:80px">{{ getTypeLabel(task.type) }}</span>
          <span style="flex:1;color:var(--text-secondary);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ task.targets }}</span>
          <el-tag :type="task.status === 'completed' ? 'success' : task.status === 'running' ? '' : 'info'" size="small">{{ task.status }}</el-tag>
          <span style="color:var(--text-secondary);font-size:12px;min-width:140px;text-align:right">{{ task.created_at }}</span>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <div style="color:var(--text-secondary);font-size:13px;line-height:1.8">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            ⚠️ 免责声明：本工具仅用于合法授权的安全测试。使用者需遵守当地法律法规。
          </div>
          <div style="font-size:12px;color:var(--text-muted);text-align:right">
            作者：A_Kanaki_1 · 微信：Baiyh322
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { GetScanStats, GetRecentTasks } from '../wailsjs/go/app/App'

const stats = ref({})
const recentTasks = ref([])

function getTypeLabel(type) {
  const labels = { portscan: '端口扫描', webfinger: 'Web指纹', poc: '漏洞检测', brute: '弱口令', dirscan: '目录扫描', osint: '信息收集' }
  return labels[type] || type
}

onMounted(async () => {
  try {
    stats.value = await GetScanStats()
    recentTasks.value = await GetRecentTasks(10) || []
  } catch (e) {
    console.error('Dashboard load failed:', e)
  }
})
</script>
