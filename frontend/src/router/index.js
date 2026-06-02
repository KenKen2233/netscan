import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'Dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: '仪表盘', icon: 'DataAnalysis' } },
  { path: '/portscan', name: 'PortScan', component: () => import('../views/PortScan.vue'), meta: { title: '端口扫描', icon: 'Connection' } },
  { path: '/webfinger', name: 'WebFinger', component: () => import('../views/WebFinger.vue'), meta: { title: 'Web指纹', icon: 'Search' } },
  { path: '/poc', name: 'PocDetect', component: () => import('../views/PocDetect.vue'), meta: { title: '漏洞检测', icon: 'Warning' } },
  { path: '/brute', name: 'BruteForce', component: () => import('../views/BruteForce.vue'), meta: { title: '弱口令', icon: 'Lock' } },
  { path: '/dirscan', name: 'DirScan', component: () => import('../views/DirScan.vue'), meta: { title: '目录扫描', icon: 'FolderOpened' } },
  { path: '/osint', name: 'Osint', component: () => import('../views/Osint.vue'), meta: { title: '信息收集', icon: 'InfoFilled' } },
  { path: '/spacemapping', name: 'SpaceMapping', component: () => import('../views/SpaceMapping.vue'), meta: { title: '空间测绘', icon: 'MapLocation' } },
  { path: '/tools', name: 'Tools', component: () => import('../views/Tools.vue'), meta: { title: '工具箱', icon: 'SetUp' } },
  { path: '/projects', name: 'Projects', component: () => import('../views/Projects.vue'), meta: { title: '项目管理', icon: 'Folder' } },
  { path: '/settings', name: 'Settings', component: () => import('../views/Settings.vue'), meta: { title: '设置', icon: 'Setting' } }
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

export default router
export { routes }
