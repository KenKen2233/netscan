<template>
  <div>
    <div class="page-header">
      <h2>📁 项目管理</h2>
      <p>管理项目、扫描模板和历史记录</p>
    </div>

    <el-tabs v-model="activeTab" type="border-card">
      <!-- Projects Tab -->
      <el-tab-pane label="项目管理" name="projects">
        <div style="margin-bottom:12px;text-align:right">
          <el-button type="primary" @click="showCreate = true">+ 新建项目</el-button>
        </div>
        <div v-if="projects.length === 0" style="text-align:center;padding:40px;color:var(--text-secondary)">
          暂无项目，点击"新建项目"开始
        </div>
        <el-table v-else :data="projects" stripe style="width:100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="name" label="项目名称" min-width="150" />
          <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
          <el-table-column prop="created_at" label="创建时间" width="180" />
          <el-table-column label="操作" width="180" fixed="right">
            <template #default="{ row }">
              <el-button text type="primary" size="small" @click="editProject(row)">编辑</el-button>
              <el-button text type="danger" size="small" @click="deleteProject(row.id)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- Scan History Tab -->
      <el-tab-pane label="扫描历史" name="history">
        <div style="margin-bottom:12px;display:flex;gap:8px;justify-content:space-between;align-items:center">
          <el-select v-model="taskFilter" size="small" style="width:140px" clearable placeholder="类型筛选" @change="loadTasks">
            <el-option label="全部" value="" />
            <el-option label="端口扫描" value="portscan" />
            <el-option label="Web指纹" value="webfinger" />
            <el-option label="POC检测" value="poc" />
            <el-option label="弱口令" value="brute" />
            <el-option label="目录扫描" value="dirscan" />
            <el-option label="信息收集" value="osint" />
          </el-select>
          <div style="display:flex;gap:8px;align-items:center">
            <el-button size="small" :disabled="compareIds.length < 2" @click="doCompare">对比选中 ({{ compareIds.length }}/2)</el-button>
            <span style="font-size:12px;color:var(--text-secondary)">共 {{ taskTotal }} 条</span>
          </div>
        </div>
        <el-table :data="tasks" stripe style="width:100%" @selection-change="onTaskSelect" max-height="500">
          <el-table-column type="selection" width="40" />
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="type" label="类型" width="100">
            <template #default="{ row }">
              <el-tag size="small">{{ typeLabel(row.type) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="targets" label="目标" min-width="200" show-overflow-tooltip />
          <el-table-column prop="status" label="状态" width="80">
            <template #default="{ row }">
              <el-tag :type="row.status === 'completed' ? 'success' : row.status === 'running' ? '' : 'info'" size="small">
                {{ row.status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="found" label="发现" width="60" />
          <el-table-column prop="created_at" label="时间" width="160" />
          <el-table-column label="操作" width="100" fixed="right">
            <template #default="{ row }">
              <el-button text type="primary" size="small" @click="exportTask(row.id)">导出</el-button>
              <el-button text type="danger" size="small" @click="deleteTask(row.id)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
        <div style="margin-top:12px;display:flex;justify-content:center">
          <el-pagination
            v-model:current-page="taskPage"
            :page-size="20"
            :total="taskTotal"
            layout="prev, pager, next"
            @current-change="loadTasks"
          />
        </div>
      </el-tab-pane>

      <!-- Templates Tab -->
      <el-tab-pane label="扫描模板" name="templates">
        <div style="margin-bottom:12px;text-align:right">
          <el-button type="primary" @click="showTemplateCreate = true">+ 新建模板</el-button>
        </div>
        <div v-if="templates.length === 0" style="text-align:center;padding:40px;color:var(--text-secondary)">
          暂无模板，点击"新建模板"创建常用扫描配置
        </div>
        <el-table v-else :data="templates" stripe style="width:100%">
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column prop="name" label="模板名称" width="150" />
          <el-table-column prop="type" label="类型" width="100">
            <template #default="{ row }">
              <el-tag size="small">{{ typeLabel(row.type) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="config" label="配置" min-width="300" show-overflow-tooltip />
          <el-table-column prop="created_at" label="创建时间" width="160" />
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="{ row }">
              <el-button text type="primary" size="small" @click="copyTemplate(row)">复制</el-button>
              <el-button text type="danger" size="small" @click="deleteTemplate(row.id)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <!-- Create/Edit Project Dialog -->
    <el-dialog v-model="showCreate" :title="editingId ? '编辑项目' : '新建项目'" width="400px">
      <el-form :model="form" label-width="80px">
        <el-form-item label="项目名称"><el-input v-model="form.name" placeholder="我的安全测试项目" /></el-form-item>
        <el-form-item label="项目描述"><el-input v-model="form.description" type="textarea" :rows="3" placeholder="可选" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" @click="saveProject">{{ editingId ? '保存' : '创建' }}</el-button>
      </template>
    </el-dialog>

    <!-- Create Template Dialog -->
    <el-dialog v-model="showTemplateCreate" title="新建扫描模板" width="500px">
      <el-form :model="templateForm" label-width="80px">
        <el-form-item label="模板名称"><el-input v-model="templateForm.name" placeholder="如：内网端口扫描" /></el-form-item>
        <el-form-item label="扫描类型">
          <el-select v-model="templateForm.type" style="width:100%">
            <el-option label="端口扫描" value="portscan" />
            <el-option label="Web指纹" value="webfinger" />
            <el-option label="POC检测" value="poc" />
            <el-option label="弱口令" value="brute" />
            <el-option label="目录扫描" value="dirscan" />
            <el-option label="信息收集" value="osint" />
          </el-select>
        </el-form-item>
        <el-form-item label="配置JSON"><el-input v-model="templateForm.config" type="textarea" :rows="4" placeholder='{"ports":"top100","mode":"tcp","timeout":500}' /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showTemplateCreate = false">取消</el-button>
        <el-button type="primary" @click="saveTemplate">创建</el-button>
      </template>
    </el-dialog>

    <!-- Compare Dialog -->
    <el-dialog v-model="showCompare" title="扫描结果对比" width="700px">
      <div v-if="compareResult">
        <el-descriptions :column="2" border size="small" style="margin-bottom:16px">
          <el-descriptions-item label="任务1 ID">{{ compareResult.task1?.type }} #{{ compareResult.task1?.status }}</el-descriptions-item>
          <el-descriptions-item label="任务2 ID">{{ compareResult.task2?.type }} #{{ compareResult.task2?.status }}</el-descriptions-item>
        </el-descriptions>
        <el-divider />
        <div v-if="compareResult.added?.length" style="margin-bottom:12px">
          <h4 style="color:var(--success-color);margin-bottom:8px">🟢 新增 ({{ compareResult.added.length }})</h4>
          <div v-for="item in compareResult.added" :key="item" style="font-family:monospace;font-size:13px;padding:2px 0;color:var(--success-color)">+ {{ item }}</div>
        </div>
        <div v-if="compareResult.removed?.length">
          <h4 style="color:var(--danger-color);margin-bottom:8px">🔴 消失 ({{ compareResult.removed.length }})</h4>
          <div v-for="item in compareResult.removed" :key="item" style="font-family:monospace;font-size:13px;padding:2px 0;color:var(--danger-color)">- {{ item }}</div>
        </div>
        <div v-if="!compareResult.added?.length && !compareResult.removed?.length" style="text-align:center;padding:20px;color:var(--text-secondary)">
          两次扫描结果完全一致
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import {
  GetProjects, CreateProject, UpdateProject, DeleteProject,
  GetRecentTasksPaginated, DeleteTask, ExportResults,
  GetTemplates, CreateTemplate, DeleteTemplate, CompareTasks
} from '../wailsjs/go/app/App'

const activeTab = ref('projects')
const projects = ref([])
const tasks = ref([])
const templates = ref([])
const showCreate = ref(false)
const showTemplateCreate = ref(false)
const showCompare = ref(false)
const editingId = ref(null)
const form = ref({ name: '', description: '' })
const templateForm = ref({ name: '', type: 'portscan', config: '{}' })
const taskFilter = ref('')
const taskPage = ref(1)
const taskTotal = ref(0)
const compareIds = ref([])
const compareResult = ref(null)

function typeLabel(type) {
  const map = { portscan: '端口扫描', webfinger: 'Web指纹', poc: 'POC检测', brute: '弱口令', dirscan: '目录扫描', osint: '信息收集' }
  return map[type] || type
}

async function loadProjects() {
  try { projects.value = await GetProjects() || [] } catch (e) { console.error(e) }
}

async function loadTasks() {
  try {
    const res = await GetRecentTasksPaginated(taskPage.value, 20, taskFilter.value)
    if (res) {
      tasks.value = res.tasks || []
      taskTotal.value = res.total || 0
    }
  } catch (e) { console.error(e) }
}

async function loadTemplates() {
  try { templates.value = await GetTemplates('') || [] } catch (e) { console.error(e) }
}

function editProject(row) {
  editingId.value = row.id
  form.value = { name: row.name, description: row.description }
  showCreate.value = true
}

async function saveProject() {
  if (!form.value.name.trim()) return
  try {
    if (editingId.value) {
      await UpdateProject(editingId.value, form.value.name, form.value.description)
    } else {
      await CreateProject(form.value.name, form.value.description)
    }
    showCreate.value = false
    editingId.value = null
    form.value = { name: '', description: '' }
    await loadProjects()
  } catch (e) { console.error(e) }
}

async function deleteProject(id) {
  if (!confirm('确定删除该项目？将同时删除关联的所有扫描结果。')) return
  try { await DeleteProject(id); await loadProjects(); await loadTasks() } catch (e) { console.error(e) }
}

async function deleteTask(id) {
  if (!confirm('确定删除此扫描记录？')) return
  try { await DeleteTask(id); await loadTasks() } catch (e) { console.error(e) }
}

async function exportTask(id) {
  try {
    const content = await ExportResults(id, 'markdown')
    const blob = new Blob([content], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `task_${id}.md`; a.click()
    URL.revokeObjectURL(url)
  } catch (e) { console.error(e) }
}

function onTaskSelect(rows) {
  compareIds.value = rows.map(r => r.id).slice(0, 2)
}

async function doCompare() {
  if (compareIds.value.length < 2) return
  try {
    compareResult.value = await CompareTasks(compareIds.value[0], compareIds.value[1])
    showCompare.value = true
  } catch (e) { alert('对比失败: ' + e.message) }
}

async function saveTemplate() {
  if (!templateForm.value.name.trim()) return
  try {
    await CreateTemplate(templateForm.value.name, templateForm.value.type, templateForm.value.config)
    showTemplateCreate.value = false
    templateForm.value = { name: '', type: 'portscan', config: '{}' }
    await loadTemplates()
  } catch (e) { console.error(e) }
}

function copyTemplate(row) {
  const config = JSON.parse(row.config)
  // Copy config to clipboard
  navigator.clipboard.writeText(JSON.stringify(config, null, 2))
}

async function deleteTemplate(id) {
  try { await DeleteTemplate(id); await loadTemplates() } catch (e) { console.error(e) }
}

onMounted(() => {
  loadProjects()
  loadTasks()
  loadTemplates()
})
</script>
