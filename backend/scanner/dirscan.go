package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DirResult represents directory scan result
type DirResult struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	Title         string `json:"title"`
	ResponseTime  int64  `json:"response_time"`
}

// DirScanConfig configures directory scanning
type DirScanConfig struct {
	Targets    []string
	Wordlist   []string
	Extensions []string
	Timeout    int
	MaxConn    int
	Recursive  bool
	StatusCodes []int
	OnResult   func(DirResult)
	OnProgress func(completed, total int)
	IsStopped  func() bool
}

// WordlistLevel defines wordlist size levels
var WordlistLevel = map[string]string{
	"small":  "assets/wordlists/small.txt",
	"medium": "assets/wordlists/medium.txt",
	"large":  "assets/wordlists/large.txt",
}

// DefaultWordlist is the fallback wordlist (small level)
var DefaultWordlist = []string{
	"admin", "login", "wp-admin", "wp-login.php", "administrator", "phpmyadmin",
	"manager", "console", "api", "v1", "v2", "test", "debug", "config", "backup",
	"db", "database", "sql", "mysql", "phpinfo.php", "info.php", "test.php",
	"robots.txt", "sitemap.xml", ".git", ".svn", ".env", ".htaccess", "web.config",
	"crossdomain.xml", "favicon.ico", "index.html", "index.php", "default.asp",
	"upload", "uploads", "images", "img", "css", "js", "static", "assets",
	"app", "application", "src", "lib", "vendor", "node_modules", "bower_components",
	"temp", "tmp", "log", "logs", "cache", "session", "sessions", "data",
	"download", "downloads", "files", "file", "docs", "doc", "document",
	"panel", "dashboard", "admin.php", "admin.html", "cpanel", "webmail",
	"mail", "email", "smtp", "ftp", "ssh", "telnet", "rdp", "vnc",
	"server-status", "server-info", "status", "health", "metrics", "monitor",
	"swagger", "api-docs", "graphql", "graphiql", "playground",
	"actuator", "env", "beans", "configprops", "mappings", "trace",
	"solr", "elasticsearch", "kibana", "grafana", "prometheus", "jenkins",
	"gitlab", "harbor", "nexus", "sonar", "jira", "confluence", "redmine",
	"wordpress", "wp-content", "wp-includes", "wp-admin",
	"drupal", "joomla", "magento", "prestashop", "opencart",
	"cgi-bin", "bin", "scripts", "includes", "classes",
	"old", "bak", "backup", "archive", "copy", "temp",
	"readme.md", "readme.txt", "changelog.md", "license.txt",
	"1", "2", "3", "test1", "test2", "demo", "example",
	"www", "home", "main", "default", "index",
}

// LoadWordlistFromFile loads a wordlist from a file
func LoadWordlistFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, nil
}

// DirScan performs directory scanning
func DirScan(cfg DirScanConfig) []DirResult {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5000
	}
	if cfg.MaxConn == 0 {
		cfg.MaxConn = 100
	}
	if len(cfg.Wordlist) == 0 {
		cfg.Wordlist = DefaultWordlist
	}
	if len(cfg.StatusCodes) == 0 {
		cfg.StatusCodes = []int{200, 201, 301, 302, 403}
	}

	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    cfg.MaxConn,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type task struct {
		target string
		path   string
	}

	var tasks []task
	for _, target := range cfg.Targets {
		if !strings.HasPrefix(target, "http") {
			target = "http://" + target
		}
		target = strings.TrimRight(target, "/")
		for _, word := range cfg.Wordlist {
			tasks = append(tasks, task{target, word})
			// Add with common extensions
			for _, ext := range cfg.Extensions {
				tasks = append(tasks, task{target, word + "." + ext})
			}
		}
	}

	var results []DirResult
	var mu sync.Mutex
	var completed int32
	total := len(tasks)

	sem := make(chan struct{}, cfg.MaxConn)
	var wg sync.WaitGroup

	for _, t := range tasks {
		if cfg.IsStopped != nil && cfg.IsStopped() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t task) {
			defer wg.Done()
			defer func() { <-sem }()

			url := t.target + "/" + t.path
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			elapsed := time.Since(start).Milliseconds()

			// Check status code filter
			for _, code := range cfg.StatusCodes {
				if resp.StatusCode == code {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
					title := ""
					if m := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`).FindStringSubmatch(string(body)); len(m) > 1 {
						title = strings.TrimSpace(m[1])
					}

					result := DirResult{
						URL:           url,
						StatusCode:    resp.StatusCode,
						ContentLength: len(body),
						Title:         title,
						ResponseTime:  elapsed,
					}

					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if cfg.OnResult != nil {
						cfg.OnResult(result)
					}
					break
				}
			}

			completed++
			if cfg.OnProgress != nil && int(completed)%max(1, total/100) == 0 {
				cfg.OnProgress(int(completed), total)
			}
		}(t)
	}
	wg.Wait()
	return results
}

// FormatDirResult formats directory scan result
func FormatDirResult(r DirResult) string {
	return fmt.Sprintf("[%d] %s (%d bytes) - %s", r.StatusCode, r.URL, r.ContentLength, r.Title)
}
