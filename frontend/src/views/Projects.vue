<template>
  <div>
    <div class="page-header">
      <h2>📁 项目管理</h2>
      <p>创建和管理安全测试项目</p>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">项目列表</span>
        <el-button type="primary" @click="showCreate = true">+ 新建项目</el-button>
      </div>
      <div v-if="projects.length === 0" style="text-align:center;padding:40px;color:var(--text-secondary)">
        暂无项目，点击"新建项目"开始
      </div>
      <div v-else>
        <div v-for="p in projects" :key="p.id" class="project-item">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div style="font-weight:600;font-size:15px">{{ p.name }}</div>
              <div style="color:var(--text-secondary);font-size:13px;margin-top:4px">{{ p.description || '暂无描述' }}</div>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
              <span style="font-size:12px;color:var(--text-secondary)">{{ p.created_at }}</span>
              <el-button text type="danger" size="small" @click="deleteProject(p.id)">删除</el-button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <el-dialog v-model="showCreate" title="新建项目" width="400px">
      <el-form :model="newProject" label-width="80px">
        <el-form-item label="项目名称"><el-input v-model="newProject.name" placeholder="我的安全测试项目" /></el-form-item>
        <el-form-item label="项目描述"><el-input v-model="newProject.description" type="textarea" :rows="3" placeholder="可选" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" @click="createProject">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { GetProjects, CreateProject, DeleteProject } from '../wailsjs/go/app/App'

const projects = ref([])
const showCreate = ref(false)
const newProject = ref({ name: '', description: '' })

async function loadProjects() { try { projects.value = await GetProjects() || [] } catch (e) { console.error(e) } }
async function createProject() {
  if (!newProject.value.name.trim()) return
  try {
    await CreateProject(newProject.value.name, newProject.value.description)
    showCreate.value = false
    newProject.value = { name: '', description: '' }
    await loadProjects()
  } catch (e) { console.error(e) }
}
async function deleteProject(id) {
  if (!confirm('确定删除该项目？')) return
  try { await DeleteProject(id); await loadProjects() } catch (e) { console.error(e) }
}

onMounted(loadProjects)
</script>

<style scoped>
.project-item { padding: 16px; border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 8px; cursor: pointer; transition: all 0.2s; }
.project-item:hover { background: var(--bg-hover); border-color: var(--accent-color); }
</style>
