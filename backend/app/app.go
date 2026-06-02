package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"netscan/backend/database"
	"netscan/backend/scanner"
	"netscan/backend/tools"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the main application struct
type App struct {
	ctx        context.Context
	db         *database.DB
	mu         sync.Mutex
	stops      map[int64]chan struct{}
	scanSem    chan struct{} // limits concurrent scans
}

// New creates a new App instance
func New() *App {
	return &App{
		stops:   make(map[int64]chan struct{}),
		scanSem: make(chan struct{}, 3), // max 3 concurrent scans
	}
}

// Startup is called when the app starts
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	db, err := database.New()
	if err != nil {
		runtime.LogError(ctx, "Database init failed: "+err.Error())
		runtime.EventsEmit(ctx, "app:error", "数据库初始化失败: "+err.Error())
		return
	}
	a.db = db

	// Load API keys from DB into environment variables
	allSettings := db.GetAllSettings()
	if allSettings != nil {
		for _, kv := range []struct{ k, e string }{
			{"shodan_key", "SHODAN_API_KEY"},
			{"fofa_email", "FOFA_EMAIL"},
			{"fofa_key", "FOFA_KEY"},
			{"hunter_key", "HUNTER_KEY"},
			{"quake_key", "QUAKE_KEY"},
			{"zoomeye_key", "ZOOMYE_KEY"},
		} {
			if v, ok := allSettings[kv.k]; ok && v != "" {
				os.Setenv(kv.e, v)
			}
		}
	}

	runtime.LogInfo(ctx, "NetScan Pro started - Database connected")
}

// Shutdown is called when the app shuts down
func (a *App) Shutdown(ctx context.Context) {
	if a.db != nil {
		a.db.Close()
	}
}

// IsReady returns whether the app is ready
func (a *App) IsReady() bool {
	return a.db != nil
}

// ========== Project Management ==========

func (a *App) CreateProject(name, desc string) (database.Project, error) {
	if a.db == nil {
		return database.Project{}, fmt.Errorf("数据库未初始化")
	}
	p, err := a.db.CreateProject(name, desc)
	if err != nil {
		runtime.LogError(a.ctx, "CreateProject: "+err.Error())
		return database.Project{}, err
	}
	runtime.EventsEmit(a.ctx, "project:created", p)
	return p, nil
}

func (a *App) UpdateProject(id int64, name, desc string) error {
	if a.db == nil {
		return fmt.Errorf("数据库未初始化")
	}
	return a.db.UpdateProject(id, name, desc)
}

func (a *App) GetProjects() ([]database.Project, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetProjects()
}

func (a *App) GetProject(id int64) (database.Project, error) {
	if a.db == nil {
		return database.Project{}, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetProject(id)
}

func (a *App) DeleteProject(id int64) error {
	if a.db == nil {
		return fmt.Errorf("数据库未初始化")
	}
	err := a.db.DeleteProject(id)
	if err != nil {
		runtime.LogError(a.ctx, "DeleteProject: "+err.Error())
		return err
	}
	runtime.EventsEmit(a.ctx, "project:deleted", id)
	return nil
}

// ========== Port Scanning ==========

func (a *App) StartPortScan(targets []string, ports string, mode string, timeout int, maxConn int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("portscan", string(targetsJSON))
	if err != nil {
		return 0, fmt.Errorf("创建任务失败: %w", err)
	}

	// Acquire scan semaphore (limit concurrent scans)
	select {
	case a.scanSem <- struct{}{}:
	default:
		return 0, fmt.Errorf("扫描并发数已达上限(3)，请等待其他扫描完成")
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		defer func() { <-a.scanSem }()
		portList := scanner.ParsePorts(ports)

		cfg := scanner.PortScanConfig{
			Targets: targets,
			Ports:   portList,
			Mode:    mode,
			Timeout: timeout,
			MaxConn: maxConn,
			OnResult: func(r scanner.PortScanResult) {
				// Save to database with error handling
				dbErr := a.db.AddPortResult(database.PortResult{
					TaskID: taskID, IP: r.IP, Port: r.Port,
					Protocol: r.Protocol, Service: r.Service,
					Version: r.Version, State: r.State,
					Banner: r.Banner, ResponseTime: r.ResponseTime,
				})
				if dbErr != nil {
					runtime.LogError(a.ctx, "Save port result failed: "+dbErr.Error())
				}
				// Emit real-time event for frontend
				runtime.EventsEmit(a.ctx, "portscan:result", map[string]interface{}{
					"task_id":       taskID,
					"ip":            r.IP,
					"port":          r.Port,
					"protocol":      r.Protocol,
					"service":       r.Service,
					"version":       r.Version,
					"state":         r.State,
					"banner":        r.Banner,
					"response_time": r.ResponseTime,
				})
			},
			OnProgress: func(completed, total int) {
				progress := 0
				if total > 0 {
					progress = completed * 100 / total
				}
				a.db.UpdateTaskProgress(taskID, progress, total, 0)
				runtime.EventsEmit(a.ctx, "scan:progress", map[string]interface{}{
					"task_id":   taskID,
					"progress":  progress,
					"total":     total,
					"completed": completed,
				})
			},
			IsStopped: func() bool {
				select {
				case <-stopCh:
					return true
				default:
					return false
				}
			},
		}

		scanner.PortScan(cfg)
		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{
			"task_id": taskID,
			"type":    "portscan",
		})

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) StopScanTask(taskID int64) error {
	a.mu.Lock()
	ch, ok := a.stops[taskID]
	a.mu.Unlock()
	if ok {
		close(ch)
	}
	if a.db != nil {
		a.db.StopTask(taskID)
	}
	runtime.EventsEmit(a.ctx, "scan:stopped", taskID)
	return nil
}

func (a *App) GetPortResults(taskID int64) ([]database.PortResult, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetPortResults(taskID)
}

func (a *App) GetPortResultsPaginated(taskID int64, offset int, limit int) (map[string]interface{}, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	results, total, err := a.db.GetPortResultsPaginated(taskID, offset, limit)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"results": results,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	}, nil
}

// ========== Web Fingerprinting ==========

func (a *App) StartWebFinger(targets []string, timeout int, maxConn int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("webfinger", string(targetsJSON))
	if err != nil {
		return 0, fmt.Errorf("创建任务失败: %w", err)
	}

	select {
	case a.scanSem <- struct{}{}:
	default:
		return 0, fmt.Errorf("扫描并发数已达上限(3)，请等待其他扫描完成")
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		defer func() { <-a.scanSem }()
		cfg := scanner.WebFingerConfig{
			Targets: targets,
			Timeout: timeout,
			MaxConn: maxConn,
			OnResult: func(r scanner.WebFingerResult) {
				a.db.AddWebFingerResult(database.WebFingerResult{
					TaskID: taskID, URL: r.URL, StatusCode: r.StatusCode,
					Title: r.Title, Server: r.Server, CMS: r.CMS,
					CMSVersion: r.CMSVersion, Language: r.Language,
					Framework: r.Framework, CDN: r.CDN,
				})
				runtime.EventsEmit(a.ctx, "webfinger:result", r)
			},
			OnProgress: func(completed, total int) {
				progress := 0
				if total > 0 {
					progress = completed * 100 / total
				}
				a.db.UpdateTaskProgress(taskID, progress, total, 0)
				runtime.EventsEmit(a.ctx, "scan:progress", map[string]interface{}{
					"task_id": taskID, "progress": progress, "total": total,
				})
			},
			IsStopped: func() bool {
				select {
				case <-stopCh:
					return true
				default:
					return false
				}
			},
		}

		scanner.WebFinger(cfg)
		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{
			"task_id": taskID, "type": "webfinger",
		})

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetWebFingerResults(taskID int64) ([]database.WebFingerResult, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetWebFingerResults(taskID)
}

// ========== POC Vulnerability Detection ==========

func (a *App) StartPocScan(targets []string, severity string, maxConn int, timeout int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	// Validate targets before scanning
	var validTargets []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if err := scanner.ValidateTarget(t); err != nil {
			runtime.LogError(a.ctx, fmt.Sprintf("Invalid target '%s': %v", t, err))
			continue
		}
		validTargets = append(validTargets, t)
	}

	if len(validTargets) == 0 {
		return 0, fmt.Errorf("没有有效的目标地址")
	}

	targetsJSON, _ := json.Marshal(validTargets)
	taskID, err := a.db.CreateTask("poc", string(targetsJSON))
	if err != nil {
		return 0, fmt.Errorf("创建任务失败: %w", err)
	}

	select {
	case a.scanSem <- struct{}{}:
	default:
		return 0, fmt.Errorf("扫描并发数已达上限(3)，请等待其他扫描完成")
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		defer func() { <-a.scanSem }()
		cfg := scanner.PocScanConfig{
			Targets:  validTargets,
			Severity: severity,
			Timeout:  timeout,
			MaxConn:  maxConn,
			SkipSSL:  true,
			OnResult: func(r scanner.PocResult) {
				a.db.AddPocResult(database.PocResult{
					TaskID: taskID, URL: r.URL, PocName: r.PocName,
					CveID: r.CveID, Severity: r.Severity,
					Vulnerable: r.Vulnerable, Request: r.Request,
					Response: r.Response, Description: r.Description,
				})
				runtime.EventsEmit(a.ctx, "poc:result", r)
			},
			OnProgress: func(completed, total int) {
				progress := 0
				if total > 0 {
					progress = completed * 100 / total
				}
				a.db.UpdateTaskProgress(taskID, progress, total, 0)
				runtime.EventsEmit(a.ctx, "scan:progress", map[string]interface{}{
					"task_id": taskID, "progress": progress, "total": total,
				})
			},
			IsStopped: func() bool {
				select {
				case <-stopCh:
					return true
				default:
					return false
				}
			},
		}

		scanner.PocScan(cfg)
		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{
			"task_id": taskID, "type": "poc",
		})

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetPocResults(taskID int64) ([]database.PocResult, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetPocResults(taskID)
}

// ========== Brute Force ==========

func (a *App) StartBruteForce(targets []string, service string, usernames []string, passwords []string, maxConn int, timeout int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("brute", string(targetsJSON))
	if err != nil {
		return 0, fmt.Errorf("创建任务失败: %w", err)
	}

	select {
	case a.scanSem <- struct{}{}:
	default:
		return 0, fmt.Errorf("扫描并发数已达上限(3)，请等待其他扫描完成")
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		defer func() { <-a.scanSem }()
		cfg := scanner.BruteConfig{
			Targets:   targets,
			Service:   service,
			Usernames: usernames,
			Passwords: passwords,
			Timeout:   timeout,
			MaxConn:   maxConn,
			OnResult: func(r scanner.BruteResult) {
				a.db.AddBruteResult(database.BruteResult{
					TaskID: taskID, Target: r.Target, Service: r.Service,
					Username: r.Username, Password: r.Password, Status: r.Status,
				})
				runtime.EventsEmit(a.ctx, "brute:result", r)
			},
			OnProgress: func(completed, total int) {
				progress := 0
				if total > 0 {
					progress = completed * 100 / total
				}
				a.db.UpdateTaskProgress(taskID, progress, total, 0)
				runtime.EventsEmit(a.ctx, "scan:progress", map[string]interface{}{
					"task_id": taskID, "progress": progress, "total": total,
				})
			},
			IsStopped: func() bool {
				select {
				case <-stopCh:
					return true
				default:
					return false
				}
			},
		}

		scanner.BruteForce(cfg)
		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{
			"task_id": taskID, "type": "brute",
		})

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetBruteResults(taskID int64) ([]database.BruteResult, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetBruteResults(taskID)
}

// ========== Directory Scanning ==========

func (a *App) StartDirScan(targets []string, wordlist string, maxConn int, timeout int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("dirscan", string(targetsJSON))
	if err != nil {
		return 0, fmt.Errorf("创建任务失败: %w", err)
	}

	select {
	case a.scanSem <- struct{}{}:
	default:
		return 0, fmt.Errorf("扫描并发数已达上限(3)，请等待其他扫描完成")
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		defer func() { <-a.scanSem }()
		words := scanner.DefaultWordlist
		if wordlist != "" {
			words = strings.Split(wordlist, "\n")
		}

		cfg := scanner.DirScanConfig{
			Targets:  targets,
			Wordlist: words,
			Timeout:  timeout,
			MaxConn:  maxConn,
			OnResult: func(r scanner.DirResult) {
				a.db.AddDirResult(database.DirResult{
					TaskID: taskID, URL: r.URL, StatusCode: r.StatusCode,
					ContentLength: r.ContentLength, Title: r.Title,
					ResponseTime: r.ResponseTime,
				})
				runtime.EventsEmit(a.ctx, "dirscan:result", r)
			},
			OnProgress: func(completed, total int) {
				progress := 0
				if total > 0 {
					progress = completed * 100 / total
				}
				a.db.UpdateTaskProgress(taskID, progress, total, 0)
				runtime.EventsEmit(a.ctx, "scan:progress", map[string]interface{}{
					"task_id": taskID, "progress": progress, "total": total,
				})
			},
			IsStopped: func() bool {
				select {
				case <-stopCh:
					return true
				default:
					return false
				}
			},
		}

		scanner.DirScan(cfg)
		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{
			"task_id": taskID, "type": "dirscan",
		})

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetDirResults(taskID int64) ([]database.DirResult, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetDirResults(taskID)
}

// ========== OSINT ==========

func (a *App) StartOsint(target string, modules []string) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	taskID, err := a.db.CreateTask("osint", target)
	if err != nil {
		return 0, fmt.Errorf("创建任务失败: %w", err)
	}

	select {
	case a.scanSem <- struct{}{}:
	default:
		return 0, fmt.Errorf("扫描并发数已达上限(3)，请等待其他扫描完成")
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		defer func() { <-a.scanSem }()
		cfg := scanner.OsintConfig{
			Target:  target,
			Modules: modules,
			OnProgress: func(completed, total int) {
				progress := 0
				if total > 0 {
					progress = completed * 100 / total
				}
				a.db.UpdateTaskProgress(taskID, progress, total, 0)
				runtime.EventsEmit(a.ctx, "scan:progress", map[string]interface{}{
					"task_id": taskID, "progress": progress, "total": total,
				})
			},
			IsStopped: func() bool {
				select {
				case <-stopCh:
					return true
				default:
					return false
				}
			},
		}

		results := scanner.OsintCollect(cfg)
		for _, r := range results {
			a.db.AddOsintResult(database.OsintResult{
				TaskID: taskID, Module: r.Module, Target: r.Target, Data: r.Data,
			})
		}

		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{
			"task_id": taskID, "type": "osint",
		})

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetOsintResults(taskID int64) ([]database.OsintResult, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetOsintResults(taskID)
}

// ========== Task Management ==========

func (a *App) GetScanTaskStatus(taskID int64) (map[string]interface{}, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetTaskStatus(taskID)
}

func (a *App) GetRecentTasks(limit int) ([]database.ScanTask, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetRecentTasks(limit)
}

func (a *App) DeleteTask(taskID int64) error {
	if a.db == nil {
		return fmt.Errorf("数据库未初始化")
	}
	return a.db.DeleteTask(taskID)
}

func (a *App) GetScanStats() (map[string]interface{}, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetStats(), nil
}

// ========== Settings ==========

type Settings struct {
	Proxy          string `json:"proxy"`
	DefaultTimeout int    `json:"default_timeout"`
	DefaultMaxConn int    `json:"default_max_conn"`
	Theme          string `json:"theme"`
	ThemeColor     string `json:"theme_color"`
	// API Keys
	ShodanKey  string `json:"shodan_key"`
	FofaEmail  string `json:"fofa_email"`
	FofaKey    string `json:"fofa_key"`
	HunterKey  string `json:"hunter_key"`
	QuakeKey   string `json:"quake_key"`
	ZoomEyeKey string `json:"zoomeye_key"`
}

func (a *App) GetSettings() (Settings, error) {
	s := Settings{
		Proxy:          "",
		DefaultTimeout: 5000,
		DefaultMaxConn: 100,
		Theme:          "dark",
		ThemeColor:     "#409EFF",
	}
	if a.db == nil {
		return s, nil
	}
	all := a.db.GetAllSettings()
	if all == nil {
		return s, nil
	}
	if v, ok := all["proxy"]; ok {
		s.Proxy = v
	}
	if v, ok := all["default_timeout"]; ok {
		fmt.Sscanf(v, "%d", &s.DefaultTimeout)
	}
	if v, ok := all["default_max_conn"]; ok {
		fmt.Sscanf(v, "%d", &s.DefaultMaxConn)
	}
	if v, ok := all["theme"]; ok {
		s.Theme = v
	}
	if v, ok := all["theme_color"]; ok {
		s.ThemeColor = v
	}
	if v, ok := all["shodan_key"]; ok {
		s.ShodanKey = v
	}
	if v, ok := all["fofa_email"]; ok {
		s.FofaEmail = v
	}
	if v, ok := all["fofa_key"]; ok {
		s.FofaKey = v
	}
	if v, ok := all["hunter_key"]; ok {
		s.HunterKey = v
	}
	if v, ok := all["quake_key"]; ok {
		s.QuakeKey = v
	}
	if v, ok := all["zoomeye_key"]; ok {
		s.ZoomEyeKey = v
	}
	return s, nil
}

func (a *App) SaveSettings(s Settings) error {
	if a.db == nil {
		return fmt.Errorf("数据库未初始化")
	}
	a.db.SetSetting("proxy", s.Proxy)
	a.db.SetSetting("default_timeout", fmt.Sprintf("%d", s.DefaultTimeout))
	a.db.SetSetting("default_max_conn", fmt.Sprintf("%d", s.DefaultMaxConn))
	a.db.SetSetting("theme", s.Theme)
	a.db.SetSetting("theme_color", s.ThemeColor)
	a.db.SetSetting("shodan_key", s.ShodanKey)
	a.db.SetSetting("fofa_email", s.FofaEmail)
	a.db.SetSetting("fofa_key", s.FofaKey)
	a.db.SetSetting("hunter_key", s.HunterKey)
	a.db.SetSetting("quake_key", s.QuakeKey)
	a.db.SetSetting("zoomeye_key", s.ZoomEyeKey)
	// Set environment variables for scanner use
	os.Setenv("SHODAN_API_KEY", s.ShodanKey)
	os.Setenv("FOFA_EMAIL", s.FofaEmail)
	os.Setenv("FOFA_KEY", s.FofaKey)
	os.Setenv("HUNTER_KEY", s.HunterKey)
	os.Setenv("QUAKE_KEY", s.QuakeKey)
	os.Setenv("ZOOMEYE_KEY", s.ZoomEyeKey)
	return nil
}

// ========== Tools ==========

func (a *App) EncodeText(text, mode string) tools.EncodeResult {
	switch mode {
	case "base64":
		return tools.Base64Encode(text)
	case "url":
		return tools.URLEncode(text)
	case "hex":
		return tools.HexEncode(text)
	case "html":
		return tools.HTMLEncode(text)
	case "unicode":
		return tools.UnicodeEncode(text)
	case "base32":
		return tools.Base32Encode(text)
	default:
		return tools.EncodeResult{Input: text, Output: "Unknown mode", Type: mode}
	}
}

func (a *App) DecodeText(text, mode string) tools.EncodeResult {
	switch mode {
	case "base64":
		return tools.Base64Decode(text)
	case "url":
		return tools.URLDecode(text)
	case "hex":
		return tools.HexDecode(text)
	case "html":
		return tools.HTMLDecode(text)
	case "unicode":
		return tools.UnicodeDecode(text)
	case "base32":
		return tools.Base32Decode(text)
	default:
		return tools.EncodeResult{Input: text, Output: "Unknown mode", Type: mode}
	}
}

func (a *App) HashText(text string) tools.HashResult {
	return tools.Hash(text)
}

func (a *App) AESEncrypt(plaintext, key string) (string, error) {
	return tools.AESEncrypt(plaintext, key)
}

func (a *App) AESDecrypt(ciphertext, key string) (string, error) {
	return tools.AESDecrypt(ciphertext, key)
}

// EncryptField encrypts a string field using a default key
func (a *App) EncryptField(plaintext string) string {
	key := "netscan-pro-v3-default-key!"
	enc, err := tools.AESEncrypt(plaintext, key)
	if err != nil {
		return plaintext
	}
	return enc
}

// DecryptField decrypts a string field using a default key
func (a *App) DecryptField(ciphertext string) string {
	key := "netscan-pro-v3-default-key!"
	dec, err := tools.AESDecrypt(ciphertext, key)
	if err != nil {
		return ciphertext
	}
	return dec
}

func (a *App) DESEncrypt(plaintext, key string) (string, error) {
	return tools.DESEncrypt(plaintext, key)
}

func (a *App) DESDecrypt(ciphertext, key string) (string, error) {
	return tools.DESDecrypt(ciphertext, key)
}

func (a *App) FormatJSON(input string) (string, error) {
	return tools.FormatJSON(input)
}

func (a *App) CompressJSON(input string) (string, error) {
	return tools.CompressJSON(input)
}

func (a *App) CalculateCIDR(cidr string) (tools.IPInfo, error) {
	return tools.CalculateCIDR(cidr)
}

func (a *App) ParseJWT(token string) (tools.JWTClaims, error) {
	return tools.ParseJWT(token)
}

// ========== File Dialogs ==========

func (a *App) SelectFile(title string) (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: title,
	})
}

func (a *App) SelectDirectory(title string) (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: title,
	})
}

func (a *App) SaveFile(title string) (string, error) {
	return runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title: title,
	})
}

// ReadFile reads a file - restricted to safe paths
func (a *App) ReadFile(path string) (string, error) {
	if !isSafePath(path) {
		return "", fmt.Errorf("access denied: path not allowed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteFile writes a file - restricted to safe paths
func (a *App) WriteFile(path, content string) error {
	if !isSafePath(path) {
		return fmt.Errorf("access denied: path not allowed")
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ========== Backup & Export ==========

func (a *App) ExportBackup() (string, error) {
	if a.db == nil {
		return "", fmt.Errorf("数据库未初始化")
	}
	data, err := a.db.ExportBackup()
	if err != nil {
		return "", err
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (a *App) ExportResults(taskID int64, format string) (string, error) {
	if a.db == nil {
		return "", fmt.Errorf("数据库未初始化")
	}

	task, err := a.db.GetTaskStatus(taskID)
	if err != nil {
		return "", fmt.Errorf("获取任务信息失败: %w", err)
	}

	var content string
	taskType, _ := task["type"].(string)
	if taskType == "" {
		return "", fmt.Errorf("未知的任务类型")
	}

	switch taskType {
	case "portscan":
		results, _ := a.db.GetPortResults(taskID)
		content = formatPortResults(results, format)
	case "webfinger":
		results, _ := a.db.GetWebFingerResults(taskID)
		content = formatWebFingerResults(results, format)
	case "poc":
		results, _ := a.db.GetPocResults(taskID)
		content = formatPocResults(results, format)
	case "brute":
		results, _ := a.db.GetBruteResults(taskID)
		content = formatBruteResults(results, format)
	case "dirscan":
		results, _ := a.db.GetDirResults(taskID)
		content = formatDirResults(results, format)
	case "osint":
		results, _ := a.db.GetOsintResults(taskID)
		content = formatOsintResults(results, format)
	default:
		return "", fmt.Errorf("unsupported task type: %s", taskType)
	}

	return content, nil
}

func formatPortResults(results []database.PortResult, format string) string {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		return string(data)
	}
	// Markdown format
	var sb strings.Builder
	sb.WriteString("# 端口扫描结果\n\n")
	sb.WriteString("| IP | 端口 | 协议 | 服务 | 版本 | 状态 | 响应时间 |\n")
	sb.WriteString("|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %dms |\n",
			r.IP, r.Port, r.Protocol, r.Service, r.Version, r.State, r.ResponseTime))
	}
	return sb.String()
}

func formatWebFingerResults(results []database.WebFingerResult, format string) string {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		return string(data)
	}
	var sb strings.Builder
	sb.WriteString("# Web指纹识别结果\n\n")
	sb.WriteString("| URL | 状态码 | 标题 | 服务器 | CMS | 语言 |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s | %s |\n",
			r.URL, r.StatusCode, r.Title, r.Server, r.CMS, r.Language))
	}
	return sb.String()
}

func formatPocResults(results []database.PocResult, format string) string {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		return string(data)
	}
	var sb strings.Builder
	sb.WriteString("# POC漏洞检测结果\n\n")
	sb.WriteString("| URL | 漏洞名称 | CVE | 严重程度 | 状态 |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, r := range results {
		status := "未发现"
		if r.Vulnerable {
			status = "⚠️ 存在"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			r.URL, r.PocName, r.CveID, r.Severity, status))
	}
	return sb.String()
}

func formatBruteResults(results []database.BruteResult, format string) string {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		return string(data)
	}
	var sb strings.Builder
	sb.WriteString("# 弱口令破解结果\n\n")
	sb.WriteString("| 目标 | 服务 | 用户名 | 密码 | 状态 |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			r.Target, r.Service, r.Username, r.Password, r.Status))
	}
	return sb.String()
}

func formatDirResults(results []database.DirResult, format string) string {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		return string(data)
	}
	var sb strings.Builder
	sb.WriteString("# 目录扫描结果\n\n")
	sb.WriteString("| URL | 状态码 | 大小 | 标题 | 响应时间 |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("| %s | %d | %d B | %s | %dms |\n",
			r.URL, r.StatusCode, r.ContentLength, r.Title, r.ResponseTime))
	}
	return sb.String()
}

func formatOsintResults(results []database.OsintResult, format string) string {
	if format == "json" {
		data, _ := json.MarshalIndent(results, "", "  ")
		return string(data)
	}
	var sb strings.Builder
	sb.WriteString("# 信息收集结果\n\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("## %s - %s\n\n", r.Module, r.Target))
		// Try to pretty-print JSON data
		var pretty map[string]interface{}
		if err := json.Unmarshal([]byte(r.Data), &pretty); err == nil {
			for k, v := range pretty {
				sb.WriteString(fmt.Sprintf("- **%s**: %v\n", k, v))
			}
		} else {
			sb.WriteString(r.Data + "\n")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// isSafePath validates file paths to prevent directory traversal and access to sensitive files
func isSafePath(path string) bool {
	// Clean and normalize the path
	path = filepath.Clean(path)
	lower := strings.ToLower(filepath.ToSlash(path))

	// Block directory traversal
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") || lower == ".." {
		return false
	}

	// Block sensitive system paths
	blocked := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts",
		"c:/windows/system32", "c:/windows/system/config",
		"c:/windows/system", "c:/windows/win.ini",
		"/proc/self", "/dev/mem",
	}
	for _, b := range blocked {
		if strings.HasPrefix(lower, b) || strings.Contains(lower, b+"/") {
			return false
		}
	}

	return true
}

// GetAppVersion returns the app version info
func (a *App) GetAppVersion() map[string]interface{} {
	return map[string]interface{}{
		"version":   "2.0.0",
		"author":    "A_Kanaki_1",
		"wechat":    "Baiyh322",
		"buildTime": time.Now().Format("2006-01-02"),
	}
}

// ========== Scan Templates ==========

func (a *App) CreateTemplate(name, typ, config string) (database.ScanTemplate, error) {
	if a.db == nil {
		return database.ScanTemplate{}, fmt.Errorf("数据库未初始化")
	}
	return a.db.CreateTemplate(name, typ, config)
}

func (a *App) GetTemplates(typ string) ([]database.ScanTemplate, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return a.db.GetTemplates(typ)
}

// UpdatePocTemplates downloads latest POC templates
func (a *App) UpdatePocTemplates() (int, error) {
	home, _ := os.UserHomeDir()
	localDir := filepath.Join(home, ".netscan", "pocs")
	return scanner.UpdatePocTemplates(localDir)
}

func (a *App) DeleteTemplate(id int64) error {
	if a.db == nil {
		return fmt.Errorf("数据库未初始化")
	}
	return a.db.DeleteTemplate(id)
}

// ========== Paginated Tasks ==========

func (a *App) GetRecentTasksPaginated(page int, pageSize int, taskType string) (map[string]interface{}, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	tasks, total, err := a.db.GetRecentTasksPaginated(offset, pageSize, taskType)
	if err != nil {
		return nil, err
	}
	totalPages := (total + pageSize - 1) / pageSize
	return map[string]interface{}{
		"tasks":       tasks,
		"total":       total,
		"page":        page,
		"pageSize":    pageSize,
		"totalPages":  totalPages,
	}, nil
}

// ========== Scan Comparison ==========

func (a *App) CompareTasks(taskID1, taskID2 int64) (map[string]interface{}, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	status1, err := a.db.GetTaskStatus(taskID1)
	if err != nil {
		return nil, fmt.Errorf("获取任务1失败: %w", err)
	}
	status2, err := a.db.GetTaskStatus(taskID2)
	if err != nil {
		return nil, fmt.Errorf("获取任务2失败: %w", err)
	}

	taskType1, _ := status1["type"].(string)
	taskType2, _ := status2["type"].(string)

	if taskType1 != taskType2 {
		return nil, fmt.Errorf("只能对比相同类型的任务")
	}

	result := map[string]interface{}{
		"task1": status1,
		"task2": status2,
		"type":  taskType1,
	}

	switch taskType1 {
	case "portscan":
		r1, _ := a.db.GetPortResults(taskID1)
		r2, _ := a.db.GetPortResults(taskID2)
		result["results1"] = len(r1)
		result["results2"] = len(r2)
		// Find differences
		set1 := make(map[string]bool)
		for _, r := range r1 {
			set1[fmt.Sprintf("%s:%d", r.IP, r.Port)] = true
		}
		set2 := make(map[string]bool)
		for _, r := range r2 {
			set2[fmt.Sprintf("%s:%d", r.IP, r.Port)] = true
		}
		var added, removed []string
		for k := range set2 {
			if !set1[k] {
				added = append(added, k)
			}
		}
		for k := range set1 {
			if !set2[k] {
				removed = append(removed, k)
			}
		}
		result["added"] = added
		result["removed"] = removed
	case "poc":
		r1, _ := a.db.GetPocResults(taskID1)
		r2, _ := a.db.GetPocResults(taskID2)
		result["results1"] = len(r1)
		result["results2"] = len(r2)
		set1 := make(map[string]bool)
		for _, r := range r1 {
			if r.Vulnerable {
				set1[r.URL+"|"+r.PocName] = true
			}
		}
		set2 := make(map[string]bool)
		for _, r := range r2 {
			if r.Vulnerable {
				set2[r.URL+"|"+r.PocName] = true
			}
		}
		var added, removed []string
		for k := range set2 {
			if !set1[k] {
				added = append(added, k)
			}
		}
		for k := range set1 {
			if !set2[k] {
				removed = append(removed, k)
			}
		}
		result["added"] = added
		result["removed"] = removed
	default:
		return nil, fmt.Errorf("暂不支持对比 %s 类型", taskType1)
	}

	return result, nil
}

// ========== Certificate Transparency ==========

func (a *App) QueryCertTransparency(domain string) ([]string, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	return scanner.QueryCrtSh(domain)
}

// ========== Port Probing & URL Generation ==========

// ProbeResult represents a probed port result with URL
// type ProbeResult struct {
// 	URL       string `json:"url"`
// 	Protocol  string `json:"protocol"`
// 	Accessible bool   `json:"accessible"`
// }

// ProbePort probes a single port and returns a clickable URL
func (a *App) ProbePort(ip string, port int, service string) map[string]interface{} {
	result := map[string]interface{}{
		"ip":         ip,
		"port":       port,
		"service":    service,
		"url":        "",
		"protocol":   "",
		"accessible": false,
	}

	proto, url := scanner.GetProtocolAndURL(ip, port, service)
	result["protocol"] = proto
	result["url"] = url

	// Quick connectivity check
	accessible := scanner.QuickProbe(ip, port)
	result["accessible"] = accessible

	return result
}

// ProbePorts batch probes port scan results and returns enriched results
func (a *App) ProbePorts(taskID int64) ([]map[string]interface{}, error) {
	if a.db == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	results, err := a.db.GetPortResults(taskID)
	if err != nil {
		return nil, err
	}

	var probed []map[string]interface{}
	for _, r := range results {
		proto, url := scanner.GetProtocolAndURL(r.IP, r.Port, r.Service)
		accessible := false
		// Only probe HTTP-capable ports for accessibility
		if url != "" {
			accessible = scanner.QuickProbe(r.IP, r.Port)
		}
		probed = append(probed, map[string]interface{}{
			"id":            r.ID,
			"ip":            r.IP,
			"port":          r.Port,
			"protocol":      r.Protocol,
			"service":       r.Service,
			"version":       r.Version,
			"state":         r.State,
			"banner":        r.Banner,
			"response_time": r.ResponseTime,
			"url":           url,
			"url_protocol":  proto,
			"accessible":    accessible,
		})
	}

	runtime.EventsEmit(a.ctx, "portscan:probed", probed)
	return probed, nil
}

// OpenURL opens a URL in the system default browser
func (a *App) OpenURL(url string) error {
	runtime.BrowserOpenURL(a.ctx, url)
	return nil
}

// ========== HTML Report Generation ==========

func (a *App) GenerateHTMLReport(taskID int64, outputPath string) (string, error) {
	if a.db == nil {
		return "", fmt.Errorf("数据库未初始化")
	}
	task, err := a.db.GetTaskStatus(taskID)
	if err != nil {
		return "", err
	}
	taskType, _ := task["type"].(string)
	reportData := scanner.ReportData{
		Title:  fmt.Sprintf("%s Scan Report - Task #%d", strings.ToUpper(taskType), taskID),
		Author: "NetScan Pro",
	}
	switch taskType {
	case "portscan":
		results, _ := a.db.GetPortResults(taskID)
		for _, r := range results {
			_, url := scanner.GetProtocolAndURL(r.IP, r.Port, r.Service)
			acc := false
			if url != "" {
				acc = scanner.QuickProbe(r.IP, r.Port)
			}
			reportData.PortResults = append(reportData.PortResults, scanner.PortReportEntry{IP: r.IP, Port: r.Port, Service: r.Service, Version: r.Version, State: r.State, ResponseTime: r.ResponseTime, URL: url, Accessible: acc})
		}
		reportData.Summary.OpenPorts = len(results)
	case "poc":
		results, _ := a.db.GetPocResults(taskID)
		for _, r := range results {
			reportData.PocResults = append(reportData.PocResults, scanner.PocReportEntry{URL: r.URL, PocName: r.PocName, CveID: r.CveID, Severity: r.Severity, Vulnerable: r.Vulnerable})
			if r.Vulnerable {
				reportData.Summary.TotalVulns++
				switch strings.ToLower(r.Severity) {
				case "critical": reportData.Summary.CriticalVulns++
				case "high": reportData.Summary.HighVulns++
				case "medium": reportData.Summary.MediumVulns++
				}
			}
		}
	case "brute":
		results, _ := a.db.GetBruteResults(taskID)
		for _, r := range results {
			reportData.BruteResults = append(reportData.BruteResults, scanner.BruteReportEntry{Target: r.Target, Service: r.Service, Username: r.Username, Password: r.Password})
		}
	case "webfinger":
		results, _ := a.db.GetWebFingerResults(taskID)
		for _, r := range results {
			reportData.WebResults = append(reportData.WebResults, scanner.WebReportEntry{URL: r.URL, StatusCode: r.StatusCode, Title: r.Title, Server: r.Server, CMS: r.CMS, Language: r.Language})
		}
	case "dirscan":
		results, _ := a.db.GetDirResults(taskID)
		for _, r := range results {
			reportData.DirResults = append(reportData.DirResults, scanner.DirReportEntry{URL: r.URL, StatusCode: r.StatusCode, ContentLength: r.ContentLength, Title: r.Title})
		}
	case "osint":
		results, _ := a.db.GetOsintResults(taskID)
		for _, r := range results {
			var d map[string]interface{}
			json.Unmarshal([]byte(r.Data), &d)
			reportData.OsintResults = append(reportData.OsintResults, scanner.OsintReportEntry{Module: r.Module, Target: r.Target, Data: d})
		}
	default:
		return "", fmt.Errorf("unsupported: %s", taskType)
	}
	if outputPath == "" {
		outputPath = fmt.Sprintf("netscan_report_%d_%d.html", taskID, time.Now().Unix())
	}
	if err := scanner.GenerateHTMLReport(reportData, outputPath); err != nil {
		return "", err
	}
	return outputPath, nil
}

func (a *App) SubdomainBruteForce(domain string, wordlist []string) ([]map[string]interface{}, error) {
	if len(wordlist) == 0 {
		wordlist = scanner.DefaultSubdomainWordlist
	}
	var results []map[string]interface{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)
	for _, word := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			fqdn := w + "." + domain
			ips, err := net.LookupHost(fqdn)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				results = append(results, map[string]interface{}{"domain": fqdn, "ip": strings.Join(ips, ", ")})
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
	return results, nil
}

// ========== Space Mapping ==========

func (a *App) SpaceMappingQuery(query string, platforms []string, size int) ([]map[string]interface{}, error) {
	var allResults []map[string]interface{}

	for _, platform := range platforms {
		switch platform {
		case "fofa":
			results, err := scanner.FofaSearch(query, size)
			if err == nil {
				for _, r := range results {
					portNum := 0
					fmt.Sscanf(r.Port, "%d", &portNum)
					allResults = append(allResults, map[string]interface{}{
						"platform": "fofa", "host": r.Host, "ip": r.IP, "port": r.Port,
						"title": r.Title, "country": r.Country,
						"url": buildURL(r.Host, portNum),
					})
				}
			}
		case "hunter":
			results, err := scanner.HunterSearch(query, size)
			if err == nil {
				for _, r := range results {
					port := r.Port
					if port == 0 {
						port = 80
					}
					allResults = append(allResults, map[string]interface{}{
						"platform": "hunter", "host": r.Host, "ip": r.IP, "port": port,
						"title": r.Title, "country": r.Country,
						"url": buildURL(r.Host, port),
					})
				}
			}
		case "quake":
			results, err := scanner.QuakeSearch(query, size)
			if err == nil {
				for _, r := range results {
					allResults = append(allResults, map[string]interface{}{
						"platform": "quake", "host": r.Host, "ip": r.IP, "port": r.Port,
						"title": r.Title, "country": r.Country, "os": r.OS,
						"url": buildURL(r.Host, r.Port),
					})
				}
			}
		case "zoomeye":
			results, err := scanner.ZoomEyeSearch(query, size)
			if err == nil {
				for _, r := range results {
					allResults = append(allResults, map[string]interface{}{
						"platform": "zoomeye", "host": r.Host, "ip": r.IP, "port": r.Port,
						"title": r.Title, "server": r.Server, "country": r.Country,
						"url": buildURL(r.Host, r.Port),
					})
				}
			}
		case "shodan":
			results, err := scanner.ShodanLookup(query)
			if err == nil {
				for _, port := range results.Ports {
					allResults = append(allResults, map[string]interface{}{
						"platform": "shodan", "host": query, "ip": results.IP, "port": port,
						"os": results.OS, "country": "",
						"url": buildURL(results.IP, port),
					})
				}
			}
		}
	}

	return allResults, nil
}

func buildURL(host string, port int) string {
	if host == "" {
		return ""
	}
	httpsPorts := map[int]bool{443: true, 8443: true, 9443: true}
	if httpsPorts[port] {
		return fmt.Sprintf("https://%s:%d", host, port)
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

func (a *App) ParseSSLCertificate(host string) (map[string]interface{}, error) {
	info, err := scanner.ParseSSLCertificate(host)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"subject": info.Subject, "issuer": info.Issuer, "not_before": info.NotBefore, "not_after": info.NotAfter, "sans": info.SANs, "is_valid": info.IsValid, "days_left": info.DaysLeft}, nil
}
