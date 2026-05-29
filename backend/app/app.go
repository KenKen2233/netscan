package app

import (
	"context"
	"encoding/json"
	"fmt"
	"netscan/backend/database"
	"netscan/backend/scanner"
	"netscan/backend/tools"
	"os"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the main application struct
type App struct {
	ctx    context.Context
	db     *database.DB
	mu     sync.Mutex
	stops  map[int64]chan struct{}
}

// New creates a new App instance
func New() *App {
	return &App{
		stops: make(map[int64]chan struct{}),
	}
}

// Startup is called when the app starts
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	db, err := database.New()
	if err != nil {
		runtime.LogError(ctx, "Database init failed: "+err.Error())
		return
	}
	a.db = db
	runtime.LogInfo(ctx, "NetScan Pro started")
}

// Shutdown is called when the app shuts down
func (a *App) Shutdown(ctx context.Context) {
	if a.db != nil {
		a.db.Close()
	}
}

// ========== Project Management ==========

func (a *App) CreateProject(name, desc string) (database.Project, error) {
	return a.db.CreateProject(name, desc)
}

func (a *App) GetProjects() ([]database.Project, error) {
	return a.db.GetProjects()
}

func (a *App) GetProject(id int64) (database.Project, error) {
	return a.db.GetProject(id)
}

func (a *App) DeleteProject(id int64) error {
	return a.db.DeleteProject(id)
}

// ========== Port Scanning ==========

func (a *App) StartPortScan(targets []string, ports string, mode string, timeout int, maxConn int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("portscan", string(targetsJSON))
	if err != nil {
		return 0, err
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		portList := scanner.ParsePorts(ports)
		total := len(targets) * len(portList)

		cfg := scanner.PortScanConfig{
			Targets: targets,
			Ports:   portList,
			Mode:    mode,
			Timeout: timeout,
			MaxConn: maxConn,
			OnResult: func(r scanner.PortScanResult) {
				a.db.AddPortResult(database.PortResult{
					TaskID: taskID, IP: r.IP, Port: r.Port,
					Protocol: r.Protocol, Service: r.Service,
					Version: r.Version, State: r.State,
					Banner: r.Banner, ResponseTime: r.ResponseTime,
				})
				runtime.EventsEmit(a.ctx, "portscan:result", r)
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

		scanner.PortScan(cfg)
		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", taskID)

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()

		_ = total
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
	a.db.StopTask(taskID)
	return nil
}

func (a *App) GetPortResults(taskID int64) ([]database.PortResult, error) {
	return a.db.GetPortResults(taskID)
}

// ========== Web Fingerprinting ==========

func (a *App) StartWebFinger(targets []string, timeout int, maxConn int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("webfinger", string(targetsJSON))
	if err != nil {
		return 0, err
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
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
		runtime.EventsEmit(a.ctx, "scan:complete", taskID)

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetWebFingerResults(taskID int64) ([]database.WebFingerResult, error) {
	return a.db.GetWebFingerResults(taskID)
}

// ========== POC Vulnerability Detection ==========

func (a *App) StartPocScan(targets []string, severity string, maxConn int, timeout int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("poc", string(targetsJSON))
	if err != nil {
		return 0, err
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
		cfg := scanner.PocScanConfig{
			Targets:  targets,
			Severity: severity,
			Timeout:  timeout,
			MaxConn:  maxConn,
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
		runtime.EventsEmit(a.ctx, "scan:complete", taskID)

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetPocResults(taskID int64) ([]database.PocResult, error) {
	return a.db.GetPocResults(taskID)
}

// ========== Brute Force ==========

func (a *App) StartBruteForce(targets []string, service string, usernames []string, passwords []string, maxConn int, timeout int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("brute", string(targetsJSON))
	if err != nil {
		return 0, err
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
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
		runtime.EventsEmit(a.ctx, "scan:complete", taskID)

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetBruteResults(taskID int64) ([]database.BruteResult, error) {
	return a.db.GetBruteResults(taskID)
}

// ========== Directory Scanning ==========

func (a *App) StartDirScan(targets []string, wordlist string, maxConn int, timeout int) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	targetsJSON, _ := json.Marshal(targets)
	taskID, err := a.db.CreateTask("dirscan", string(targetsJSON))
	if err != nil {
		return 0, err
	}

	stopCh := make(chan struct{})
	a.mu.Lock()
	a.stops[taskID] = stopCh
	a.mu.Unlock()

	go func() {
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
		runtime.EventsEmit(a.ctx, "scan:complete", taskID)

		a.mu.Lock()
		delete(a.stops, taskID)
		a.mu.Unlock()
	}()

	return taskID, nil
}

func (a *App) GetDirResults(taskID int64) ([]database.DirResult, error) {
	return a.db.GetDirResults(taskID)
}

// ========== OSINT ==========

func (a *App) StartOsint(target string, modules []string) (int64, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	taskID, err := a.db.CreateTask("osint", target)
	if err != nil {
		return 0, err
	}

	go func() {
		cfg := scanner.OsintConfig{
			Target:  target,
			Modules: modules,
		}

		results := scanner.OsintCollect(cfg)
		for _, r := range results {
			a.db.AddOsintResult(database.OsintResult{
				TaskID: taskID, Module: r.Module, Target: r.Target, Data: r.Data,
			})
		}

		a.db.CompleteTask(taskID)
		runtime.EventsEmit(a.ctx, "scan:complete", taskID)
	}()

	return taskID, nil
}

func (a *App) GetOsintResults(taskID int64) ([]database.OsintResult, error) {
	return a.db.GetOsintResults(taskID)
}

// ========== Task Management ==========

func (a *App) GetScanTaskStatus(taskID int64) (map[string]interface{}, error) {
	return a.db.GetTaskStatus(taskID)
}

func (a *App) GetRecentTasks(limit int) ([]database.ScanTask, error) {
	return a.db.GetRecentTasks(limit)
}

func (a *App) GetScanStats() (map[string]interface{}, error) {
	return a.db.GetStats(), nil
}

// ========== Settings ==========

type Settings struct {
	Proxy          string `json:"proxy"`
	DefaultTimeout int    `json:"default_timeout"`
	DefaultMaxConn int    `json:"default_max_conn"`
	Theme          string `json:"theme"`
	ThemeColor     string `json:"theme_color"`
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
	return s, nil
}

func (a *App) SaveSettings(s Settings) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	a.db.SetSetting("proxy", s.Proxy)
	a.db.SetSetting("default_timeout", fmt.Sprintf("%d", s.DefaultTimeout))
	a.db.SetSetting("default_max_conn", fmt.Sprintf("%d", s.DefaultMaxConn))
	a.db.SetSetting("theme", s.Theme)
	a.db.SetSetting("theme_color", s.ThemeColor)
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

// isSafePath validates file paths to prevent directory traversal
func isSafePath(path string) bool {
	// Normalize path
	path = strings.ReplaceAll(path, "\\", "/")
	// Block sensitive system paths
	blocked := []string{"/etc/passwd", "/etc/shadow", "/etc/hosts", "c:/windows/system32", "c:/windows/system/config"}
	lower := strings.ToLower(path)
	for _, b := range blocked {
		if strings.Contains(lower, b) {
			return false
		}
	}
	// Block directory traversal
	if strings.Contains(path, "..") {
		return false
	}
	return true
}
