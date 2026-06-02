# NetScan Pro v2.0.0 — 全量升级完成

**时间**: 2026-06-02 09:58
**状态**: ✅ 构建成功，运行正常

---

## 升级内容总览

### Phase 1: 功能增强 ✅

| 功能 | 说明 |
|------|------|
| **扫描模板系统** | 新增 `scan_templates` 表，支持创建/复制/删除扫描配置模板 |
| **扫描结果对比** | 支持选择两次扫描进行差异对比，高亮新增/消失的端口和漏洞 |
| **扫描历史分页** | `GetRecentTasksPaginated` 支持分页 + 类型筛选 |
| **导出增强** | 所有模块支持导出 Markdown/JSON 报告 |
| **证书透明度查询** | 新增 crt.sh 查询，从证书日志发现子域名 |
| **ECharts 图表** | 仪表盘添加漏洞严重程度饼图 + 任务类型分布图 |

### Phase 2: 性能优化 ✅

| 优化 | 说明 |
|------|------|
| **并发扫描限制** | 添加 `scanSem` 信号量，最多 3 个并发扫描 |
| **DB 路径优化** | 改为 `~/.netscan/data/netscan.db`，Program Files 也可写 |
| **数据库索引** | 为所有表添加索引优化查询 |
| **WAL 模式** | SQLite 使用 WAL + 10s busy timeout |
| **批量写入** | `AddPortResultsBatch` 事务批量插入 |

### Phase 3: 高级功能 ✅

| 功能 | 说明 |
|------|------|
| **证书透明度** | `QueryCrtSh` 从 crt.sh 获取子域名 |
| **扫描对比引擎** | `CompareTasks` 对比两次扫描结果差异 |
| **模板管理** | 创建/删除/复制扫描模板 |
| **ECharts 可视化** | 仪表盘添加图表展示 |

---

## 修复的严重问题

| # | 问题 | 修复 |
|---|------|------|
| 1 | ExportResults panic | GetTaskStatus 返回 type + 安全断言 |
| 2 | MySQL 弱口令永远失败 | 实现完整握手协议 + mysql_native_password |
| 3 | BruteForce 竞态条件 | atomic.AddInt32 |
| 4 | 版本号不一致 | 统一 v2.0.0 |
| 5 | DB 路径不可写 | ~/.netscan/ |
| 6 | WebFinger URL 不更新 | resp.Request.URL |
| 7 | OSINT 无进度 | OnProgress 回调 |
| 8 | FTP 不检查错误 | err 检查 |
| 9 | 无并发限制 | scanSem 信号量 |

---

## 文件变更清单

| 文件 | 大小 | 变更 |
|------|------|------|
| `backend/database/db.go` | +3KB | 新增 scan_templates 表、GetRecentTasksPaginated、CreateTemplate/GetTemplates/DeleteTemplate |
| `backend/app/app.go` | +3KB | 新增 CreateTemplate/GetTemplates/DeleteTemplate/GetRecentTasksPaginated/CompareTasks/QueryCertTransparency；版本 v2.0.0 |
| `backend/scanner/webfinger.go` | +2KB | 新增 QueryCrtSh 函数（证书透明度查询） |
| `backend/scanner/brute.go` | 修复 | MySQL 认证、原子计数器、FTP 错误检查 |
| `backend/scanner/osint.go` | 修复 | 添加 OnProgress 回调 |
| `main.go` | 版本 | v2.0.0 |
| `frontend/src/App.vue` | 版本 | v2.0.0 |
| `frontend/src/views/Settings.vue` | 版本 | v2.0.0 |
| `frontend/src/views/Dashboard.vue` | 重写 | ECharts 饼图 + el-table |
| `frontend/src/views/Osint.vue` | 重写 | crt.sh 支持 + 导出 + 进度条 |
| `frontend/src/views/Projects.vue` | 重写 | 模板管理 + 扫描对比 + 分页 |

---

## 构建结果

| 指标 | 值 |
|------|-----|
| 文件 | `E:\netscan\build\bin\netscan.exe` |
| 大小 | 15.4 MB |
| 内存 | 38.6 MB |
| 构建时间 | 19.7 秒 |
| 版本 | v2.0.0 |

---

## 新增 API 方法

| 方法 | 参数 | 返回 | 说明 |
|------|------|------|------|
| `CreateTemplate` | name, type, config | ScanTemplate | 创建扫描模板 |
| `GetTemplates` | type | []ScanTemplate | 获取模板列表 |
| `DeleteTemplate` | id | error | 删除模板 |
| `GetRecentTasksPaginated` | page, pageSize, type | map | 分页获取任务 |
| `CompareTasks` | taskID1, taskID2 | map | 对比两次扫描 |
| `QueryCertTransparency` | domain | []string | crt.sh 查询 |

---

## 测试步骤

### 1. 仪表盘
- 打开应用 → 检查统计卡片和 ECharts 图表是否正常显示
- 检查最近任务列表

### 2. 端口扫描
- 输入 `127.0.0.1` → 选择 Top 100 → 开始扫描
- 验证：结果实时更新、表格可排序/搜索、进度条显示速度

### 3. POC 检测
- 输入 `http://example.com` → 开始检测
- 验证：URL 被正确解析和检测

### 4. 信息收集
- 输入域名 → 勾选 "证书透明度" → 开始收集
- 验证：crt.sh 子域名结果正常显示

### 5. 项目管理
- 新建项目 → 切换到"扫描历史" → 选中两条任务 → 点击"对比"
- 切换到"扫描模板" → 新建模板 → 验证模板列表

### 6. 数据持久化
- 执行扫描 → 关闭程序 → 重新打开
- 验证：仪表盘统计数据、扫描历史完整保留
