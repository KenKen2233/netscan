<template>
  <div>
    <div class="page-header">
      <h2>📈 信息收集 (OSINT)</h2>
      <p>综合信息收集：子域名、WHOIS、DNS、IP归属等</p>
    </div>

    <div class="card">
      <div class="card-title" style="margin-bottom:16px">收集配置</div>
      <el-form label-width="100px" class="scan-form">
        <el-form-item label="目标域名">
          <el-input v-model="form.target" placeholder="example.com" />
        </el-form-item>
        <el-form-item label="收集模块">
          <el-checkbox-group v-model="form.modules">
            <el-checkbox value="subdomain">子域名枚举</el-checkbox>
            <el-checkbox value="whois">WHOIS查询</el-checkbox>
            <el-checkbox value="dns">DNS解析</el-checkbox>
            <el-checkbox value="ipinfo">IP归属地</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="startOsint" :loading="scanning" size="large">
            {{ scanning ? '收集中...' : '🚀 开始收集' }}
          </el-button>
        </el-form-item>
      </el-form>
    </div>

    <div v-if="Object.keys(results).length > 0">
      <div class="card" v-for="(data, mod) in results" :key="mod">
        <div class="card-title" style="margin-bottom:12px">{{ getModuleLabel(mod) }}</div>
        <div v-if="mod === 'subdomain' && data.subdomains">
          <div v-if="data.subdomains.length === 0" style="color:var(--text-secondary)">未发现子域名</div>
          <div v-for="(sub, i) in data.subdomains" :key="i" style="padding:4px 0;font-family:monospace;font-size:13px;border-bottom:1px solid var(--border-color)">{{ sub }}</div>
        </div>
        <div v-else-if="mod === 'dns'">
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="域名">{{ data.domain }}</el-descriptions-item>
            <el-descriptions-item label="A记录">
              <span v-for="(ip, i) in (data.a_records || [])" :key="i" style="margin-right:8px;font-family:monospace">{{ ip }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="CNAME">{{ data.cname || '-' }}</el-descriptions-item>
            <el-descriptions-item label="MX记录">
              <div v-for="(mx, i) in (data.mx_records || [])" :key="i">{{ mx }}</div>
              <span v-if="!data.mx_records?.length">-</span>
            </el-descriptions-item>
            <el-descriptions-item label="NS记录">
              <div v-for="(ns, i) in (data.ns_records || [])" :key="i">{{ ns }}</div>
            </el-descriptions-item>
            <el-descriptions-item label="TXT记录">
              <div v-for="(txt, i) in (data.txt_records || [])" :key="i" style="font-size:12px;word-break:break-all">{{ txt }}</div>
            </el-descriptions-item>
          </el-descriptions>
        </div>
        <div v-else-if="mod === 'whois'">
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="域名">{{ data.domain }}</el-descriptions-item>
            <el-descriptions-item label="IP">{{ data.ip || '-' }}</el-descriptions-item>
            <el-descriptions-item label="反向DNS">{{ data.reverse_dns || '-' }}</el-descriptions-item>
          </el-descriptions>
        </div>
        <div v-else-if="mod === 'ipinfo'">
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="IP">{{ data.ip }}</el-descriptions-item>
            <el-descriptions-item label="私有地址">{{ data.is_private ? '是' : '否' }}</el-descriptions-item>
            <el-descriptions-item label="反向DNS">{{ data.reverse_dns || '-' }}</el-descriptions-item>
          </el-descriptions>
        </div>
        <pre v-else style="font-size:12px;color:var(--text-secondary);white-space:pre-wrap">{{ formatData(data) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { StartOsint, GetOsintResults, GetScanTaskStatus } from '../wailsjs/go/app/App'

const form = ref({ target: '', modules: ['subdomain', 'dns', 'ipinfo'] })
const scanning = ref(false)
const results = ref({})

function getModuleLabel(mod) {
  const labels = { dns: '🔗 DNS解析', whois: '📋 WHOIS信息', subdomain: '🌐 子域名', ipinfo: '📍 IP归属地' }
  return labels[mod] || mod
}

function formatData(data) {
  if (typeof data === 'string') {
    try { return JSON.stringify(JSON.parse(data), null, 2) } catch { return data }
  }
  return JSON.stringify(data, null, 2)
}

async function startOsint() {
  if (!form.value.target.trim()) return
  scanning.value = true
  results.value = {}
  try {
    const taskId = await StartOsint(form.value.target, form.value.modules)
    // Wait for completion
    const check = setInterval(async () => {
      try {
        const status = await GetScanTaskStatus(taskId)
        if (status.status === 'completed') {
          clearInterval(check)
          const osintResults = await GetOsintResults(taskId)
          const mapped = {}
          for (const r of (osintResults || [])) {
            try { mapped[r.module] = JSON.parse(r.data) } catch { mapped[r.module] = r.data }
          }
          results.value = mapped
          scanning.value = false
        }
      } catch (e) { console.error(e) }
    }, 500)
  } catch (e) { scanning.value = false; console.error(e) }
}
</script>
