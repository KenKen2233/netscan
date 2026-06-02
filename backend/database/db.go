package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite database connection with thread-safe operations
type DB struct {
	conn *sql.DB
	mu   sync.RWMutex
}

// New creates a new database connection and initializes tables
func New() (*DB, error) {
	// Use user home directory for reliable writable DB path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dbPath := filepath.Join(homeDir, ".netscan", "data", "netscan.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	conn, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=10000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	db := &DB{conn: conn}
	if err := db.initTables(); err != nil {
		return nil, fmt.Errorf("init tables: %w", err)
	}

	// Verify DB is writable
	if _, err := conn.Exec("CREATE TABLE IF NOT EXISTS _verify (id INTEGER)"); err != nil {
		return nil, fmt.Errorf("database not writable: %w", err)
	}
	conn.Exec("DROP TABLE IF EXISTS _verify")

	return db, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.conn.Close()
}

func (db *DB) initTables() error {
	_, err := db.conn.Exec(`
	CREATE TABLE IF NOT EXISTS projects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS scan_tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		project_id INTEGER DEFAULT 0,
		targets TEXT DEFAULT '[]',
		params TEXT DEFAULT '{}',
		status TEXT DEFAULT 'pending',
		progress INTEGER DEFAULT 0,
		total INTEGER DEFAULT 0,
		found INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS port_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		service TEXT DEFAULT '',
		version TEXT DEFAULT '',
		state TEXT DEFAULT 'open',
		banner TEXT DEFAULT '',
		response_time INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS webfinger_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		status_code INTEGER DEFAULT 0,
		title TEXT DEFAULT '',
		server TEXT DEFAULT '',
		cms TEXT DEFAULT '',
		cms_version TEXT DEFAULT '',
		language TEXT DEFAULT '',
		framework TEXT DEFAULT '',
		cdn TEXT DEFAULT '',
		fingerprint TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS poc_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		poc_name TEXT NOT NULL,
		cve_id TEXT DEFAULT '',
		severity TEXT DEFAULT 'info',
		vulnerable INTEGER DEFAULT 0,
		request TEXT DEFAULT '',
		response TEXT DEFAULT '',
		description TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS brute_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		target TEXT NOT NULL,
		service TEXT NOT NULL,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		status TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS dir_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		status_code INTEGER DEFAULT 0,
		content_length INTEGER DEFAULT 0,
		title TEXT DEFAULT '',
		response_time INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS osint_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		module TEXT NOT NULL,
		target TEXT NOT NULL,
		data TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_port_task ON port_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_port_ip ON port_results(ip);
	CREATE INDEX IF NOT EXISTS idx_port_state ON port_results(state);
	CREATE INDEX IF NOT EXISTS idx_task_status ON scan_tasks(status);
	CREATE INDEX IF NOT EXISTS idx_task_type ON scan_tasks(type);
	CREATE INDEX IF NOT EXISTS idx_task_project ON scan_tasks(project_id);
	CREATE INDEX IF NOT EXISTS idx_webfinger_task ON webfinger_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_poc_task ON poc_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_poc_severity ON poc_results(severity);
	CREATE INDEX IF NOT EXISTS idx_brute_task ON brute_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_dir_task ON dir_results(task_id);
	CREATE INDEX IF NOT EXISTS idx_osint_task ON osint_results(task_id);

	CREATE TABLE IF NOT EXISTS scan_templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		config TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_templates_type ON scan_templates(type);
	`)
	return err
}

// ========== Project Operations ==========

type Project struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (db *DB) CreateProject(name, desc string) (Project, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	r, err := db.conn.Exec("INSERT INTO projects (name,description) VALUES (?,?)", name, desc)
	if err != nil {
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	id, _ := r.LastInsertId()
	return db.getProjectLocked(id)
}

func (db *DB) GetProjects() ([]Project, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,name,description,created_at,updated_at FROM projects ORDER BY updated_at DESC")
	if err != nil {
		return nil, fmt.Errorf("get projects: %w", err)
	}
	defer rows.Close()
	var list []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		list = append(list, p)
	}
	return list, nil
}

func (db *DB) GetProject(id int64) (Project, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.getProjectLocked(id)
}

func (db *DB) getProjectLocked(id int64) (Project, error) {
	var p Project
	err := db.conn.QueryRow("SELECT id,name,description,created_at,updated_at FROM projects WHERE id=?", id).
		Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return p, fmt.Errorf("get project %d: %w", id, err)
	}
	return p, nil
}

func (db *DB) UpdateProject(id int64, name, desc string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("UPDATE projects SET name=?,description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", name, desc, id)
	return err
}

func (db *DB) DeleteProject(id int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	// Delete project and all related scan results
	tx.Exec("DELETE FROM port_results WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)", id)
	tx.Exec("DELETE FROM webfinger_results WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)", id)
	tx.Exec("DELETE FROM poc_results WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)", id)
	tx.Exec("DELETE FROM brute_results WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)", id)
	tx.Exec("DELETE FROM dir_results WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)", id)
	tx.Exec("DELETE FROM osint_results WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)", id)
	tx.Exec("DELETE FROM scan_tasks WHERE project_id=?", id)
	_, err = tx.Exec("DELETE FROM projects WHERE id=?", id)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ========== Task Operations ==========

type ScanTask struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	ProjectID int64  `json:"project_id"`
	Targets   string `json:"targets"`
	Status    string `json:"status"`
	Progress  int    `json:"progress"`
	Total     int    `json:"total"`
	Found     int    `json:"found"`
	CreatedAt string `json:"created_at"`
}

func (db *DB) CreateTask(taskType, targets string) (int64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	r, err := db.conn.Exec("INSERT INTO scan_tasks (type,targets,status) VALUES (?,?,'running')", taskType, targets)
	if err != nil {
		return 0, fmt.Errorf("create task: %w", err)
	}
	return r.LastInsertId()
}

func (db *DB) CreateTaskWithProject(taskType, targets string, projectID int64) (int64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	r, err := db.conn.Exec("INSERT INTO scan_tasks (type,targets,project_id,status) VALUES (?,?,?,'running')", taskType, targets, projectID)
	if err != nil {
		return 0, fmt.Errorf("create task: %w", err)
	}
	return r.LastInsertId()
}

func (db *DB) UpdateTaskProgress(id int64, progress, total, found int) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.conn.Exec("UPDATE scan_tasks SET progress=?,total=?,found=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", progress, total, found, id)
}

func (db *DB) CompleteTask(id int64) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.conn.Exec("UPDATE scan_tasks SET status='completed',progress=100,updated_at=CURRENT_TIMESTAMP WHERE id=?", id)
}

func (db *DB) StopTask(id int64) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.conn.Exec("UPDATE scan_tasks SET status='stopped',updated_at=CURRENT_TIMESTAMP WHERE id=?", id)
}

func (db *DB) GetTaskStatus(id int64) (map[string]interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var status, taskType string
	var progress, total, found int
	err := db.conn.QueryRow("SELECT type,status,progress,total,found FROM scan_tasks WHERE id=?", id).
		Scan(&taskType, &status, &progress, &total, &found)
	if err != nil {
		return nil, fmt.Errorf("get task status: %w", err)
	}
	return map[string]interface{}{
		"type": taskType, "status": status, "progress": progress, "total": total, "found": found,
	}, nil
}

func (db *DB) GetRecentTasks(limit int) ([]ScanTask, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,type,project_id,targets,status,progress,total,found,created_at FROM scan_tasks ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []ScanTask
	for rows.Next() {
		var t ScanTask
		if err := rows.Scan(&t.ID, &t.Type, &t.ProjectID, &t.Targets, &t.Status, &t.Progress, &t.Total, &t.Found, &t.CreatedAt); err != nil {
			continue
		}
		list = append(list, t)
	}
	return list, nil
}

func (db *DB) DeleteTask(id int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	tx.Exec("DELETE FROM port_results WHERE task_id=?", id)
	tx.Exec("DELETE FROM webfinger_results WHERE task_id=?", id)
	tx.Exec("DELETE FROM poc_results WHERE task_id=?", id)
	tx.Exec("DELETE FROM brute_results WHERE task_id=?", id)
	tx.Exec("DELETE FROM dir_results WHERE task_id=?", id)
	tx.Exec("DELETE FROM osint_results WHERE task_id=?", id)
	_, err = tx.Exec("DELETE FROM scan_tasks WHERE id=?", id)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ========== Port Results ==========

type PortResult struct {
	ID           int64  `json:"id"`
	TaskID       int64  `json:"task_id"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	State        string `json:"state"`
	Banner       string `json:"banner"`
	ResponseTime int64  `json:"response_time"`
}

func (db *DB) AddPortResult(r PortResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("INSERT INTO port_results (task_id,ip,port,protocol,service,version,state,banner,response_time) VALUES (?,?,?,?,?,?,?,?,?)",
		r.TaskID, r.IP, r.Port, r.Protocol, r.Service, r.Version, r.State, r.Banner, r.ResponseTime)
	if err != nil {
		return fmt.Errorf("add port result: %w", err)
	}
	return nil
}

func (db *DB) AddPortResultsBatch(results []PortResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO port_results (task_id,ip,port,protocol,service,version,state,banner,response_time) VALUES (?,?,?,?,?,?,?,?,?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range results {
		if _, err := stmt.Exec(r.TaskID, r.IP, r.Port, r.Protocol, r.Service, r.Version, r.State, r.Banner, r.ResponseTime); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetPortResults(taskID int64) ([]PortResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,task_id,ip,port,protocol,service,version,state,banner,response_time FROM port_results WHERE task_id=? ORDER BY ip,port", taskID)
	if err != nil {
		return nil, fmt.Errorf("get port results: %w", err)
	}
	defer rows.Close()
	var list []PortResult
	for rows.Next() {
		var r PortResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.IP, &r.Port, &r.Protocol, &r.Service, &r.Version, &r.State, &r.Banner, &r.ResponseTime); err != nil {
			continue
		}
		list = append(list, r)
	}
	return list, nil
}

func (db *DB) GetPortResultsPaginated(taskID int64, offset, limit int) ([]PortResult, int, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var total int
	db.conn.QueryRow("SELECT COUNT(*) FROM port_results WHERE task_id=?", taskID).Scan(&total)
	rows, err := db.conn.Query("SELECT id,task_id,ip,port,protocol,service,version,state,banner,response_time FROM port_results WHERE task_id=? ORDER BY ip,port LIMIT ? OFFSET ?", taskID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var list []PortResult
	for rows.Next() {
		var r PortResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.IP, &r.Port, &r.Protocol, &r.Service, &r.Version, &r.State, &r.Banner, &r.ResponseTime); err != nil {
			continue
		}
		list = append(list, r)
	}
	return list, total, nil
}

// ========== Web Finger Results ==========

type WebFingerResult struct {
	ID          int64  `json:"id"`
	TaskID      int64  `json:"task_id"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title"`
	Server      string `json:"server"`
	CMS         string `json:"cms"`
	CMSVersion  string `json:"cms_version"`
	Language    string `json:"language"`
	Framework   string `json:"framework"`
	CDN         string `json:"cdn"`
	Fingerprint string `json:"fingerprint"`
}

func (db *DB) AddWebFingerResult(r WebFingerResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("INSERT INTO webfinger_results (task_id,url,status_code,title,server,cms,cms_version,language,framework,cdn,fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
		r.TaskID, r.URL, r.StatusCode, r.Title, r.Server, r.CMS, r.CMSVersion, r.Language, r.Framework, r.CDN, r.Fingerprint)
	return err
}

func (db *DB) GetWebFingerResults(taskID int64) ([]WebFingerResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,task_id,url,status_code,title,server,cms,cms_version,language,framework,cdn,fingerprint FROM webfinger_results WHERE task_id=?", taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []WebFingerResult
	for rows.Next() {
		var r WebFingerResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.URL, &r.StatusCode, &r.Title, &r.Server, &r.CMS, &r.CMSVersion, &r.Language, &r.Framework, &r.CDN, &r.Fingerprint); err != nil {
			continue
		}
		list = append(list, r)
	}
	return list, nil
}

// ========== POC Results ==========

type PocResult struct {
	ID          int64  `json:"id"`
	TaskID      int64  `json:"task_id"`
	URL         string `json:"url"`
	PocName     string `json:"poc_name"`
	CveID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Vulnerable  bool   `json:"vulnerable"`
	Request     string `json:"request"`
	Response    string `json:"response"`
	Description string `json:"description"`
}

func (db *DB) AddPocResult(r PocResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	v := 0
	if r.Vulnerable {
		v = 1
	}
	_, err := db.conn.Exec("INSERT INTO poc_results (task_id,url,poc_name,cve_id,severity,vulnerable,request,response,description) VALUES (?,?,?,?,?,?,?,?,?)",
		r.TaskID, r.URL, r.PocName, r.CveID, r.Severity, v, r.Request, r.Response, r.Description)
	return err
}

func (db *DB) GetPocResults(taskID int64) ([]PocResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,task_id,url,poc_name,cve_id,severity,vulnerable,request,response,description FROM poc_results WHERE task_id=?", taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []PocResult
	for rows.Next() {
		var r PocResult
		var v int
		if err := rows.Scan(&r.ID, &r.TaskID, &r.URL, &r.PocName, &r.CveID, &r.Severity, &v, &r.Request, &r.Response, &r.Description); err != nil {
			continue
		}
		r.Vulnerable = v == 1
		list = append(list, r)
	}
	return list, nil
}

// ========== Brute Results ==========

type BruteResult struct {
	ID       int64  `json:"id"`
	TaskID   int64  `json:"task_id"`
	Target   string `json:"target"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Status   string `json:"status"`
}

func (db *DB) AddBruteResult(r BruteResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("INSERT INTO brute_results (task_id,target,service,username,password,status) VALUES (?,?,?,?,?,?)",
		r.TaskID, r.Target, r.Service, r.Username, r.Password, r.Status)
	return err
}

func (db *DB) GetBruteResults(taskID int64) ([]BruteResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,task_id,target,service,username,password,status FROM brute_results WHERE task_id=?", taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []BruteResult
	for rows.Next() {
		var r BruteResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Target, &r.Service, &r.Username, &r.Password, &r.Status); err != nil {
			continue
		}
		list = append(list, r)
	}
	return list, nil
}

// ========== Dir Results ==========

type DirResult struct {
	ID            int64  `json:"id"`
	TaskID        int64  `json:"task_id"`
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	Title         string `json:"title"`
	ResponseTime  int64  `json:"response_time"`
}

func (db *DB) AddDirResult(r DirResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("INSERT INTO dir_results (task_id,url,status_code,content_length,title,response_time) VALUES (?,?,?,?,?,?)",
		r.TaskID, r.URL, r.StatusCode, r.ContentLength, r.Title, r.ResponseTime)
	return err
}

func (db *DB) GetDirResults(taskID int64) ([]DirResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,task_id,url,status_code,content_length,title,response_time FROM dir_results WHERE task_id=?", taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []DirResult
	for rows.Next() {
		var r DirResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.URL, &r.StatusCode, &r.ContentLength, &r.Title, &r.ResponseTime); err != nil {
			continue
		}
		list = append(list, r)
	}
	return list, nil
}

// ========== OSINT Results ==========

type OsintResult struct {
	ID     int64  `json:"id"`
	TaskID int64  `json:"task_id"`
	Module string `json:"module"`
	Target string `json:"target"`
	Data   string `json:"data"`
}

func (db *DB) AddOsintResult(r OsintResult) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("INSERT INTO osint_results (task_id,module,target,data) VALUES (?,?,?,?)",
		r.TaskID, r.Module, r.Target, r.Data)
	return err
}

func (db *DB) GetOsintResults(taskID int64) ([]OsintResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT id,task_id,module,target,data FROM osint_results WHERE task_id=?", taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []OsintResult
	for rows.Next() {
		var r OsintResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Module, &r.Target, &r.Data); err != nil {
			continue
		}
		list = append(list, r)
	}
	return list, nil
}

// ========== Settings ==========

func (db *DB) GetSetting(key string) string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var val string
	db.conn.QueryRow("SELECT value FROM settings WHERE key=?", key).Scan(&val)
	return val
}

func (db *DB) SetSetting(key, value string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.conn.Exec("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", key, value)
}

func (db *DB) GetAllSettings() map[string]string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	rows, err := db.conn.Query("SELECT key,value FROM settings")
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		m[k] = v
	}
	return m
}

// ========== Stats ==========

func (db *DB) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()
	stats := make(map[string]interface{})
	var tp, tt, rt, tv, to int
	db.conn.QueryRow("SELECT COUNT(*) FROM projects").Scan(&tp)
	db.conn.QueryRow("SELECT COUNT(*) FROM scan_tasks").Scan(&tt)
	db.conn.QueryRow("SELECT COUNT(*) FROM scan_tasks WHERE status='running'").Scan(&rt)
	db.conn.QueryRow("SELECT COUNT(*) FROM poc_results WHERE vulnerable=1").Scan(&tv)
	db.conn.QueryRow("SELECT COUNT(DISTINCT ip||':'||port) FROM port_results").Scan(&to)
	stats["total_projects"] = tp
	stats["total_tasks"] = tt
	stats["running_tasks"] = rt
	stats["total_vulns"] = tv
	stats["total_open_ports"] = to

	var c, h, m, l int
	db.conn.QueryRow("SELECT COUNT(*) FROM poc_results WHERE vulnerable=1 AND severity='critical'").Scan(&c)
	db.conn.QueryRow("SELECT COUNT(*) FROM poc_results WHERE vulnerable=1 AND severity='high'").Scan(&h)
	db.conn.QueryRow("SELECT COUNT(*) FROM poc_results WHERE vulnerable=1 AND severity='medium'").Scan(&m)
	db.conn.QueryRow("SELECT COUNT(*) FROM poc_results WHERE vulnerable=1 AND severity='low'").Scan(&l)
	stats["vuln_critical"] = c
	stats["vuln_high"] = h
	stats["vuln_medium"] = m
	stats["vuln_low"] = l
	return stats
}

// ========== Scan Templates ==========

type ScanTemplate struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Config    string `json:"config"`
	CreatedAt string `json:"created_at"`
}

func (db *DB) CreateTemplate(name, typ, config string) (ScanTemplate, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	r, err := db.conn.Exec("INSERT INTO scan_templates (name,type,config) VALUES (?,?,?)", name, typ, config)
	if err != nil {
		return ScanTemplate{}, err
	}
	id, _ := r.LastInsertId()
	var t ScanTemplate
	db.conn.QueryRow("SELECT id,name,type,config,created_at FROM scan_templates WHERE id=?", id).Scan(&t.ID, &t.Name, &t.Type, &t.Config, &t.CreatedAt)
	return t, nil
}

func (db *DB) GetTemplates(typ string) ([]ScanTemplate, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var rows *sql.Rows
	var err error
	if typ != "" {
		rows, err = db.conn.Query("SELECT id,name,type,config,created_at FROM scan_templates WHERE type=? ORDER BY updated_at DESC", typ)
	} else {
		rows, err = db.conn.Query("SELECT id,name,type,config,created_at FROM scan_templates ORDER BY updated_at DESC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []ScanTemplate
	for rows.Next() {
		var t ScanTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Config, &t.CreatedAt); err != nil {
			continue
		}
		list = append(list, t)
	}
	return list, nil
}

func (db *DB) DeleteTemplate(id int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, err := db.conn.Exec("DELETE FROM scan_templates WHERE id=?", id)
	return err
}

func (db *DB) GetRecentTasksPaginated(offset, limit int, taskType string) ([]ScanTask, int, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	var total int
	var where string
	if taskType != "" {
		where = " WHERE type='" + taskType + "'"
	}
	db.conn.QueryRow("SELECT COUNT(*) FROM scan_tasks" + where).Scan(&total)
	query := "SELECT id,type,project_id,targets,status,progress,total,found,created_at FROM scan_tasks" + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	rows, err := db.conn.Query(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var list []ScanTask
	for rows.Next() {
		var t ScanTask
		if err := rows.Scan(&t.ID, &t.Type, &t.ProjectID, &t.Targets, &t.Status, &t.Progress, &t.Total, &t.Found, &t.CreatedAt); err != nil {
			continue
		}
		list = append(list, t)
	}
	return list, total, nil
}

// ========== Backup ==========

func (db *DB) ExportBackup() (map[string]interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	backup := make(map[string]interface{})

	// Export all tables
	tables := []string{"projects", "scan_tasks", "port_results", "webfinger_results", "poc_results", "brute_results", "dir_results", "osint_results", "settings"}
	for _, table := range tables {
		rows, err := db.conn.Query("SELECT * FROM " + table)
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		var records []map[string]interface{}
		for rows.Next() {
			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			record := make(map[string]interface{})
			for i, col := range cols {
				record[col] = vals[i]
			}
			records = append(records, record)
		}
		rows.Close()
		backup[table] = records
	}
	return backup, nil
}
