package scanner

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

// ReportData holds all data needed for report generation
type ReportData struct {
	Title       string
	GeneratedAt string
	Author      string
	Summary     ReportSummary
	PortResults []PortReportEntry
	WebResults  []WebReportEntry
	PocResults  []PocReportEntry
	BruteResults []BruteReportEntry
	DirResults  []DirReportEntry
	OsintResults []OsintReportEntry
}

type ReportSummary struct {
	TotalPorts   int
	OpenPorts    int
	TotalVulns   int
	CriticalVulns int
	HighVulns    int
	MediumVulns  int
	LowVulns     int
	TotalTargets int
	ScanDuration string
}

type PortReportEntry struct {
	IP           string
	Port         int
	Service      string
	Version      string
	State        string
	ResponseTime int64
	URL          string
	Accessible   bool
}

type WebReportEntry struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	CMS        string
	Language   string
}

type PocReportEntry struct {
	URL        string
	PocName    string
	CveID      string
	Severity   string
	Vulnerable bool
}

type BruteReportEntry struct {
	Target   string
	Service  string
	Username string
	Password string
}

type DirReportEntry struct {
	URL           string
	StatusCode    int
	ContentLength int
	Title         string
}

type OsintReportEntry struct {
	Module string
	Target string
	Data   map[string]interface{}
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}} - NetScan Pro Report</title>
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --success: #3fb950; --warning: #d29922; --danger: #f85149; --critical: #ff7b72; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
.header { background: linear-gradient(135deg, #1a1f2e, #2d333b); border: 1px solid var(--border); border-radius: 12px; padding: 32px; margin-bottom: 24px; }
.header h1 { font-size: 28px; margin-bottom: 8px; }
.header .meta { color: var(--muted); font-size: 14px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
.stat-card .value { font-size: 32px; font-weight: 700; }
.stat-card .label { font-size: 13px; color: var(--muted); margin-top: 4px; }
.stat-card.critical .value { color: var(--critical); }
.stat-card.high .value { color: var(--danger); }
.stat-card.medium .value { color: var(--warning); }
.stat-card.success .value { color: var(--success); }
.section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; overflow: hidden; }
.section-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
.section-header h2 { font-size: 18px; }
.badge { padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-danger { background: rgba(248,81,73,0.15); color: var(--danger); }
.badge-warning { background: rgba(210,153,34,0.15); color: var(--warning); }
.badge-success { background: rgba(63,185,80,0.15); color: var(--success); }
.badge-info { background: rgba(88,166,255,0.15); color: var(--accent); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }
th { background: rgba(255,255,255,0.03); color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
tr:hover { background: rgba(255,255,255,0.02); }
.severity { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.severity-critical { background: #ff7b72; color: #000; }
.severity-high { background: #f85149; color: #fff; }
.severity-medium { background: #d29922; color: #000; }
.severity-low { background: #3fb950; color: #000; }
.severity-info { background: #58a6ff; color: #000; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.footer { text-align: center; color: var(--muted); font-size: 12px; padding: 24px; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🔍 {{.Title}}</h1>
<div class="meta">
<p>Generated: {{.GeneratedAt}} | Author: {{.Author}}</p>
</div>
</div>

<div class="summary">
<div class="stat-card success"><div class="value">{{.Summary.OpenPorts}}</div><div class="label">Open Ports</div></div>
<div class="stat-card"><div class="value">{{.Summary.TotalTargets}}</div><div class="label">Targets</div></div>
<div class="stat-card critical"><div class="value">{{.Summary.CriticalVulns}}</div><div class="label">Critical</div></div>
<div class="stat-card high"><div class="value">{{.Summary.HighVulns}}</div><div class="label">High</div></div>
<div class="stat-card medium"><div class="value">{{.Summary.MediumVulns}}</div><div class="label">Medium</div></div>
<div class="stat-card"><div class="value">{{.Summary.TotalVulns}}</div><div class="label">Total Vulns</div></div>
</div>

{{if .PortResults}}
<div class="section">
<div class="section-header"><h2>🔌 Port Scan Results</h2><span class="badge badge-info">{{len .PortResults}} ports</span></div>
<table>
<tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th><th>State</th><th>Response</th><th>Link</th></tr>
{{range .PortResults}}
<tr>
<td>{{.IP}}</td><td>{{.Port}}</td><td>{{.Service}}</td><td>{{.Version}}</td>
<td>{{if eq .State "open"}}<span class="badge badge-success">open</span>{{else}}{{.State}}{{end}}</td>
<td>{{.ResponseTime}}ms</td>
<td>{{if .URL}}<a href="{{.URL}}" target="_blank">{{.URL}}</a>{{else}}-{{end}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}

{{if .PocResults}}
<div class="section">
<div class="section-header"><h2>⚠️ Vulnerability Detection</h2><span class="badge badge-danger">{{len .PocResults}} findings</span></div>
<table>
<tr><th>URL</th><th>Vulnerability</th><th>CVE</th><th>Severity</th><th>Status</th></tr>
{{range .PocResults}}
<tr>
<td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
<td>{{.PocName}}</td><td>{{.CveID}}</td>
<td><span class="severity severity-{{.Severity}}">{{.Severity}}</span></td>
<td>{{if .Vulnerable}}<span class="badge badge-danger">VULNERABLE</span>{{else}}<span class="badge badge-success">Safe</span>{{end}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}

{{if .BruteResults}}
<div class="section">
<div class="section-header"><h2>🔓 Brute Force Results</h2><span class="badge badge-warning">{{len .BruteResults}} credentials</span></div>
<table>
<tr><th>Target</th><th>Service</th><th>Username</th><th>Password</th></tr>
{{range .BruteResults}}
<tr><td>{{.Target}}</td><td>{{.Service}}</td><td style="color:var(--warning)">{{.Username}}</td><td style="color:var(--danger);font-weight:700">{{.Password}}</td></tr>
{{end}}
</table>
</div>
{{end}}

{{if .WebResults}}
<div class="section">
<div class="section-header"><h2>🌐 Web Fingerprint Results</h2><span class="badge badge-info">{{len .WebResults}} targets</span></div>
<table>
<tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>CMS</th><th>Language</th></tr>
{{range .WebResults}}
<tr>
<td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
<td>{{.StatusCode}}</td><td>{{.Title}}</td><td>{{.Server}}</td><td>{{.CMS}}</td><td>{{.Language}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}

{{if .DirResults}}
<div class="section">
<div class="section-header"><h2>📂 Directory Scan Results</h2><span class="badge badge-info">{{len .DirResults}} paths</span></div>
<table>
<tr><th>URL</th><th>Status</th><th>Size</th><th>Title</th></tr>
{{range .DirResults}}
<tr>
<td><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
<td>{{.StatusCode}}</td><td>{{.ContentLength}}B</td><td>{{.Title}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}

{{if .OsintResults}}
<div class="section">
<div class="section-header"><h2>🕵️ OSINT Results</h2><span class="badge badge-info">{{len .OsintResults}} modules</span></div>
{{range .OsintResults}}
<div style="padding:16px;border-bottom:1px solid var(--border)">
<h3 style="margin-bottom:8px">{{.Module}} — {{.Target}}</h3>
<pre style="font-size:12px;color:var(--muted);white-space:pre-wrap">{{printf "%v" .Data}}</pre>
</div>
{{end}}
</div>
{{end}}

<div class="footer">
<p>Generated by NetScan Pro v2.0.0 | Author: A_Kanaki_1 | WeChat: Baiyh322</p>
<p>{{.GeneratedAt}}</p>
</div>
</div>
</body>
</html>`

// GenerateHTMLReport generates an HTML report from scan results
func GenerateHTMLReport(data ReportData, outputPath string) error {
	data.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	if data.Author == "" {
		data.Author = "NetScan Pro"
	}

	tmpl, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	return tmpl.Execute(file, data)
}

// GenerateReportFromJSON generates a report from JSON scan data
func GenerateReportFromJSON(jsonData string, outputPath string) error {
	var data ReportData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	return GenerateHTMLReport(data, outputPath)
}

// FormatSeverity returns CSS class for severity level
func FormatSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "severity-critical"
	case "high":
		return "severity-high"
	case "medium":
		return "severity-medium"
	case "low":
		return "severity-low"
	default:
		return "severity-info"
	}
}
