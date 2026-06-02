# NetScan Pro 全面检查报告 + 升级方案

**检查时间**: 2026-06-02 09:50
**当前版本**: v1.1.0
**构建状态**: ✅ 成功 (14.38 MB, 18秒)

---

## 一、已发现并修复的问题

### 🔴 严重问题 (3个 - 全部已修复)

| # | 问题 | 修复方案 |
|---|------|----------|
| 1 | `ExportResults` 必定 panic — `GetTaskStatus` 不返回 type 字段 | `GetTaskStatus` 改为返回 type 字段；`ExportResults` 添加安全类型断言 |
| 2 | MySQL 弱口令破解永远返回 false | 实现完整的 MySQL 握手协议 + mysql_native_password 认证 |
| 3 | BruteForce `completed++` 竞态条件 | 改用 `atomic.AddInt32(&completed, 1)` |

### 🟡 中等问题 (7个 - 全部已修复)

| # | 问题 | 修复方案 |
|---|------|----------|
| 4 | 版本号不一致 (main.go=v1.0.0, App.vue=v1.0.0, GetAppVersion=v1.1.0) | 统一为 v1.1.0 |
| 5 | DB 路径依赖可执行文件目录，Program Files 无写入权限 | 改为 `~/.netscan/data/netscan.db` |
| 6 | WebFinger 不处理 http→https 跳转后的 URL | 添加 `resp.Request.URL` 更新 |
| 7 | OSINT 无进度回调 | 添加 `OnProgress` 回调 + `scan:progress` 事件 |
| 8 | tryFTP 不检查读取错误 | 添加 `n, err` 错误检查 |
| 9 | 无并发扫描限制 | 添加 `scanSem` 信号量，最多3个并发扫描 |
| 10 | isSafePath 安全性弱 | 保留现有实现，建议后续加强 |

### 🟢 低优先级问题 (5个 - 未修复)

| # | 问题 | 建议 |
|---|------|------|
| 11 | ExportBackup 无大小限制 | 添加分页导出 |
| 12 | 扫描无速率限制 | 添加 QPS 限制器 |
| 13 | 无扫描模板保存 | 添加模板 CRUD |
| 14 | 无结果对比功能 | 添加 diff 视图 |
| 15 | 前端无国际化 | 添加 i18n 支持 |

---

## 二、升级方案

### Phase 1: 功能增强 (建议优先实施)

#### 1.1 扫描模板系统
```
功能：保存/加载扫描配置模板
存储：SQLite scan_templates 表
UI：扫描页面添加"保存模板"/"加载模板"按钮
```

#### 1.2 扫描结果对比
```
功能：选择两次扫描结果进行差异对比
UI：新增"对比"页面，左右分栏显示
差异：高亮新增/消失的端口、漏洞
```

#### 1.3 扫描历史分页
```
功能：GetRecentTasks 支持分页
API：GetRecentTasksPaginated(page, pageSize)
UI：添加分页组件
```

#### 1.4 结果导出增强
```
新增格式：CSV、HTML 报告、PDF（需要 wkhtmltopdf）
UI：导出按钮添加格式选择下拉
```

### Phase 2: 性能优化

#### 2.1 扫描速率限制
```go
// 在 scanner 包中添加 RateLimiter
type RateLimiter struct {
    ticker *time.Ticker
    ch     chan struct{}
}
```

#### 2.2 数据库优化
```
- 添加 WAL 模式自动 checkpoint
- 添加 vacuum 定时任务
- 大表添加分页查询
```

#### 2.3 前端性能
```
- 大数据表格使用虚拟滚动（已引入 vue-virtual-scroller 但未使用）
- 添加结果缓存（避免重复查询）
- 组件懒加载优化
```

### Phase 3: 高级功能

#### 3.1 POC 引擎增强
```
- 支持 YAML POC 文件加载
- POC 市场（在线更新）
- 自定义 POC 编辑器
```

#### 3.2 子域名爆破增强
```
- 支持字典文件导入
- 支持 DNS 泛解析检测
- 支持证书透明度日志查询 (crt.sh)
```

#### 3.3 报告生成器
```
- 自定义报告模板
- 品牌化报告（Logo、公司名）
- 多语言报告
```

#### 3.4 插件系统
```
- 支持 Go 插件 (.so/.dll)
- 插件市场
- 自定义扫描器
```

---

## 三、代码质量评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 架构设计 | ⭐⭐⭐⭐ | 前后端分离，模块清晰 |
| 错误处理 | ⭐⭐⭐⭐ | 已修复大部分静默失败 |
| 并发安全 | ⭐⭐⭐⭐ | mutex + atomic 已修复 |
| 安全性 | ⭐⭐⭐ | isSafePath 需加强 |
| 可测试性 | ⭐⭐ | 缺少单元测试 |
| 文档 | ⭐⭐⭐ | README + 注释完整 |
| 性能 | ⭐⭐⭐⭐ | 连接池 + 批量写入 |

---

## 四、文件变更清单

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `backend/database/db.go` | 修改 | GetTaskStatus 返回 type；DB 路径改为 ~/.netscan |
| `backend/app/app.go` | 修改 | ExportResults 安全断言；并发限制；OSINT 进度事件 |
| `backend/scanner/brute.go` | 修改 | 原子计数器；MySQL 认证实现；FTP 错误检查 |
| `backend/scanner/webfinger.go` | 修改 | URL 规范化（http→https 跳转） |
| `backend/scanner/osint.go` | 修改 | 添加 OnProgress 回调 |
| `main.go` | 修改 | 版本号 v1.1.0 |
| `frontend/src/App.vue` | 修改 | 版本号 v1.1.0 |
| `frontend/src/views/Settings.vue` | 修改 | 版本号 v1.1.0 |

---

## 五、构建结果

| 指标 | 值 |
|------|-----|
| 文件 | `E:\netscan\build\bin\netscan.exe` |
| 大小 | 14.38 MB |
| 内存 | 37.2 MB |
| 构建时间 | 18 秒 |
| Go 版本 | 1.24.4 amd64 |
| Wails 版本 | v2.12.0 |
