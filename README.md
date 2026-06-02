# NetScan Pro v2.0.0

> 跨平台网络安全扫描工具 | 作者：A_Kanaki_1 | 微信：Baiyh322

## 功能模块

| 模块 | 功能 | 状态 |
|------|------|------|
| 📊 仪表盘 | 数据总览、漏洞统计、快速扫描入口、ECharts 图表 | ✅ |
| 🔌 端口扫描 | TCP/SYN/UDP 扫描、CIDR 展开、服务版本探测、可达链接 | ✅ |
| 🔍 Web 指纹 | 100+ 指纹规则、CMS/框架/服务器/CDN/语言识别 | ✅ |
| ⚠️ 漏洞检测 | 36 内置 POC + YAML 模板引擎、在线更新、严重程度过滤 | ✅ |
| 🔒 弱口令 | SSH/FTP/MySQL/Redis/MSSQL/PostgreSQL/MongoDB/Telnet/SMB | ✅ |
| 📂 目录扫描 | 多级字典（small/medium/large）、自定义字典、递归扫描 | ✅ |
| 📈 信息收集 | DNS/WHOIS/子域名枚举/子域名爆破/crt.sh/SSL 证书/IP 归属 | ✅ |
| 🌐 空间测绘 | Fofa/Hunter/Quake/ZoomEye/Shodan 多平台统一查询 | ✅ |
| 🛠️ 工具箱 | 编解码/Hash/AES/DES/JSON 格式化/CIDR/JWT 解析 | ✅ |
| 📁 项目管理 | 扫描模板、扫描对比、分页历史、HTML 报告导出 | ✅ |
| ⚙️ 系统设置 | 代理/主题/API Key 配置/参数配置 | ✅ |

## 技术栈

| 组件 | 技术 |
|------|------|
| 桌面框架 | Wails v2.12.0 |
| 后端 | Go 1.24.4 (amd64) |
| 前端 | Vue 3 + Vite 5 |
| UI | Element Plus |
| 数据库 | SQLite 3 (WAL 模式) |
| 图表 | ECharts 5 |

## 快速开始

### 开发环境

```bash
# 安装前端依赖
cd frontend && npm install && cd ..

# 开发模式运行
wails dev
```

### 构建发布

```bash
# Windows
wails build

# 构建产物
build/bin/netscan.exe
```

### 运行

```bash
# 直接运行
./build/bin/netscan.exe
```

## 项目结构

```
netscan/
├── main.go                          # Wails 入口
├── wails.json                       # Wails 配置
├── go.mod / go.sum                  # Go 依赖
├── assets/
│   ├── pocs/                        # YAML POC 模板
│   └── wordlists/                   # 多级目录字典
├── backend/
│   ├── app/app.go                   # Wails 绑定层 (61 个 API)
│   ├── scanner/
│   │   ├── portscan.go              # 端口扫描 + 版本探测
│   │   ├── webfinger.go             # Web 指纹识别
│   │   ├── poc.go                   # POC 漏洞检测
│   │   ├── poc_templates.go         # YAML POC 模板引擎
│   │   ├── brute.go                 # 弱口令破解 (9 协议)
│   │   ├── dirscan.go               # 目录扫描
│   │   ├── osint.go                 # 信息收集 (8 模块)
│   │   ├── apis.go                  # 第三方 API 集成
│   │   ├── fingerprint_ext.go       # 扩展指纹规则
│   │   ├── report.go                # HTML 报告生成
│   │   └── subdomain.go             # 子域名字典
│   ├── database/db.go               # SQLite 数据库
│   └── tools/tools.go               # 工具箱
└── frontend/
    └── src/
        ├── App.vue                  # 主布局
        ├── router/index.js          # 路由 (11 页面)
        ├── stores/app.js            # 状态管理
        └── views/
            ├── Dashboard.vue        # 仪表盘 + 快速扫描
            ├── PortScan.vue         # 端口扫描
            ├── WebFinger.vue        # Web 指纹
            ├── PocDetect.vue        # 漏洞检测
            ├── BruteForce.vue       # 弱口令
            ├── DirScan.vue          # 目录扫描
            ├── Osint.vue            # 信息收集
            ├── SpaceMapping.vue     # 空间测绘
            ├── Tools.vue            # 工具箱
            ├── Projects.vue         # 项目管理
            └── Settings.vue         # 系统设置
```

## 核心特性

### 结果持久化
所有扫描结果自动保存到 localStorage + SQLite，切换页面不丢失，再次扫描时提示保留或清空。

### 可点击链接
端口扫描自动探测 HTTP/HTTPS 服务可达性，只对可达端口生成可点击链接，点击在系统浏览器打开。

### YAML POC 模板
支持自定义 YAML 格式 POC 模板，兼容多种匹配器（word/regex/status），支持在线更新。

### 空间测绘
集成 Fofa、Hunter、Quake、ZoomEye、Shodan 五大平台，页面内直接配置 API Key，统一查询展示。

### 服务版本探测
端口扫描自动发送协议探测包，获取 SSH/HTTP/FTP/MySQL/Redis 等服务的版本信息。

### HTML 报告
支持生成专业渗透测试报告，包含统计卡片、漏洞严重程度分布、详细结果表格。

## 空间测绘 API 配置

在「空间测绘」页面顶部展开 API 配置区域：

| 平台 | 获取地址 | 免费额度 |
|------|----------|----------|
| Shodan | https://account.shodan.io/ | 1 次/秒 |
| Fofa | https://fofa.info/myProfile | 100 次/天 |
| Hunter | https://hunter.qianxin.com/home/userInfo | 15 次/天 |
| Quake | https://quake.360.net/quake/#/personal | 有限 |
| ZoomEye | https://www.zoomeye.org/profile | 有限 |

## 安全说明

- 文件操作已限制目录遍历
- 数据库使用参数化查询防止 SQL 注入
- 首次运行显示免责声明
- 仅用于合法授权的安全测试

## 免责声明

⚠️ 本工具仅用于合法授权的安全测试和渗透测试。使用本工具进行未经授权的网络扫描、漏洞检测或任何非法活动，后果由使用者自行承担。使用前请确保已获得目标系统所有者的书面授权。

## 作者

- **作者**: A_Kanaki_1
- **联系方式**: 微信 Baiyh322
- **GitHub**: https://github.com/KenKen2233/netscan
