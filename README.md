# NetScan Pro - 网络安全扫描工具

> 作者：A_Kanaki_1 | 联系方式：微信 Baiyh322

## 功能模块

| 模块 | 功能 | 状态 |
|------|------|------|
| 📊 仪表盘 | 数据总览、漏洞统计、最近任务 | ✅ |
| 🔌 端口扫描 | TCP全连接扫描、CIDR展开、并发控制 | ✅ |
| 🔍 Web指纹 | CMS/框架/服务器/CDN识别 | ✅ |
| ⚠️ 漏洞检测 | 36个内置POC检查、严重程度过滤 | ✅ |
| 🔒 弱口令 | SSH/FTP/MySQL/Redis弱口令检测 | ✅ |
| 📂 目录扫描 | 100+内置字典、递归扫描 | ✅ |
| 📈 信息收集 | DNS/WHOIS/子域名/IP归属 | ✅ |
| 🔧 工具箱 | 编码/哈希/AES/DES/JSON/JWT/IP计算 | ✅ |
| 📁 项目管理 | 项目CRUD、数据关联 | ✅ |
| ⚙️ 系统设置 | 代理/主题/参数配置 | ✅ |

## 技术栈

- **桌面框架**: Wails v2.12.0
- **后端**: Go 1.22+
- **前端**: Vue 3.4+ + Vite 5+
- **UI库**: Element Plus
- **数据库**: SQLite 3
- **图表**: ECharts 5.5+

## 快速开始

### 开发模式

```bash
cd frontend
npm install
cd ..
wails dev
```

### 构建发布版

```bash
# Windows
build.bat

# Linux/macOS
chmod +x build.sh
./build.sh
```

## 运行

```bash
# 直接运行
E:\netscan\build\bin\netscan.exe
```

## 项目结构

```
netscan/
├── main.go                    # Wails入口
├── wails.json                 # Wails配置
├── go.mod                     # Go依赖
├── build.bat / build.sh       # 构建脚本
├── backend/
│   ├── app/app.go             # Wails绑定层
│   ├── scanner/
│   │   ├── portscan.go        # 端口扫描
│   │   ├── webfinger.go       # Web指纹
│   │   ├── poc.go             # 漏洞检测
│   │   ├── brute.go           # 弱口令
│   │   ├── dirscan.go         # 目录扫描
│   │   └── osint.go           # 信息收集
│   ├── database/db.go         # SQLite数据库
│   └── tools/tools.go         # 工具箱
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.vue            # 主布局+免责声明
        ├── main.js            # 入口
        ├── router/index.js    # 路由
        ├── stores/app.js      # 状态管理
        ├── styles/main.css    # 主题CSS
        └── views/             # 10个功能页面
```

## 安全说明

- 所有文件操作已限制目录遍历
- 数据库使用参数化查询防止SQL注入
- 首次运行显示免责声明
- 仅用于合法授权的安全测试

## 免责声明

⚠️ 本工具仅用于合法授权的安全测试和渗透测试。使用本工具进行未经授权的网络扫描、漏洞检测或任何非法活动，后果由使用者自行承担。使用前请确保已获得目标系统所有者的书面授权。

## 作者

- **作者**: A_Kanaki_1
- **联系方式**: 微信 Baiyh322
