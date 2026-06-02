package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PocResult represents a POC vulnerability detection result
type PocResult struct {
	URL         string `json:"url"`
	PocName     string `json:"poc_name"`
	CveID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Vulnerable  bool   `json:"vulnerable"`
	Request     string `json:"request"`
	Response    string `json:"response"`
	Description string `json:"description"`
}

// PocScanConfig configures POC scanning
type PocScanConfig struct {
	Targets    []string
	Severity   string
	Timeout    int
	MaxConn    int
	SkipSSL    bool
	Proxy      string
	OnResult   func(PocResult)
	OnProgress func(completed, total int)
	IsStopped  func() bool
}

// Built-in POC checks
var builtinPOCs = []struct {
	Name     string
	CVE      string
	Severity string
	Path     string
	Match    string
}{
	{"Spring Boot Actuator", "CVE-2022-22947", "high", "/actuator", "status"},
	{"Spring Boot Env", "CVE-2022-22947", "high", "/actuator/env", "activeProfiles"},
	{"Swagger UI", "", "info", "/swagger-ui.html", "swagger"},
	{"Swagger API", "", "info", "/v2/api-docs", "swagger"},
	{"Druid Monitor", "", "medium", "/druid/index.html", "Druid"},
	{"phpMyAdmin", "", "medium", "/phpmyadmin/", "phpMyAdmin"},
	{"WordPress Login", "", "info", "/wp-login.php", "wp-login"},
	{"WordPress Admin", "", "info", "/wp-admin/", "WordPress"},
	{"Joomla Admin", "", "info", "/administrator/", "Joomla"},
	{"Tomcat Manager", "", "high", "/manager/html", "Tomcat"},
	{"Weblogic Console", "", "critical", "/console/login/LoginForm.jsp", "WebLogic"},
	{"Jenkins", "", "high", "/login", "Jenkins"},
	{"GitLab", "", "medium", "/users/sign_in", "GitLab"},
	{"Harbor", "", "medium", "/harbor/sign-in", "Harbor"},
	{"MinIO", "", "medium", "/minio/login", "MinIO"},
	{"Prometheus", "", "medium", "/graph", "Prometheus"},
	{"Grafana", "", "medium", "/login", "Grafana"},
	{"Kibana", "", "medium", "/app/kibana", "Kibana"},
	{"Elasticsearch", "", "medium", "/_cat/health", "cluster_name"},
	{"MongoDB Express", "", "high", "/", "mongo-express"},
	{"Redis Commander", "", "high", "/", "Redis Commander"},
	{"Portainer", "", "medium", "/", "portainer"},
	{"Rancher", "", "medium", "/", "Rancher"},
	{"CouchDB", "", "medium", "/_utils/", "CouchDB"},
	{"Solr Admin", "", "medium", "/solr/#/", "Solr"},
	{"Jupyter Notebook", "", "high", "/login", "Jupyter"},
	{"Kubernetes API", "", "high", "/api/v1/namespaces", "namespaces"},
	{"Docker API", "", "critical", "/containers/json", "Id"},
	{"PHP Info", "", "info", "/phpinfo.php", "phpinfo"},
	{"Backup File", "", "high", "/backup.zip", ""},
	{"Env File", "", "critical", "/.env", "APP_KEY"},
	{"Git Config", "", "high", "/.git/config", "repositoryformatversion"},
	{"DS_Store", "", "low", "/.DS_Store", ""},
	{"Robots.txt", "", "info", "/robots.txt", ""},
	{"Sitemap.xml", "", "info", "/sitemap.xml", ""},
	{"Crossdomain.xml", "", "info", "/crossdomain.xml", ""},
}

// GetPocTemplateLoader returns a template loader with default POC directories
func GetPocTemplateLoader() *PocTemplateLoader {
	// Try common POC directories
	dirs := []string{"pocs", "assets/pocs"}
	// Also check user home directory
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".netscan", "pocs"))
	}
	return NewPocTemplateLoader(dirs...)
}

// ParseTarget parses any target format into a normalized base URL
// Supports: IP, IP:port, domain, http://..., https://..., URL with path
func ParseTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target")
	}

	// Remove any trailing slashes
	target = strings.TrimRight(target, "/")

	// If it already has a scheme, parse directly
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("invalid URL '%s': %w", target, err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("invalid URL '%s': missing host", target)
		}
		// Return scheme://host (without path, path will be added by POC)
		return u.Scheme + "://" + u.Host, nil
	}

	// Check if it's IP:port or domain:port
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		// Has port
		if port == "443" || port == "8443" {
			return "https://" + host + ":" + port, nil
		}
		return "http://" + host + ":" + port, nil
	}

	// Check if it's a bare IP
	if ip := net.ParseIP(target); ip != nil {
		return "http://" + target, nil
	}

	// Check if it contains a dot (domain name)
	if strings.Contains(target, ".") && !strings.Contains(target, " ") {
		// Check if it ends with a port number after last colon
		lastColon := strings.LastIndex(target, ":")
		if lastColon > 0 {
			potentialHost := target[:lastColon]
			potentialPort := target[lastColon+1:]
			// Verify it's host:port not part of IPv6
			if !strings.Contains(potentialHost, ":") {
				if port == "443" || port == "8443" || potentialPort == "443" || potentialPort == "8443" {
					return "https://" + potentialHost + ":" + potentialPort, nil
				}
				return "http://" + potentialHost + ":" + potentialPort, nil
			}
		}
		return "http://" + target, nil
	}

	// Last resort: treat as IP or hostname
	return "http://" + target, nil
}

// ValidateTarget checks if a target string is valid
func ValidateTarget(target string) error {
	_, err := ParseTarget(target)
	return err
}

// PocScan performs POC vulnerability detection
func PocScan(cfg PocScanConfig) []PocResult {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5000
	}
	if cfg.MaxConn == 0 {
		cfg.MaxConn = 20
	}

	// Create HTTP client with options
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipSSL || true, // Default skip SSL for security scanning
		},
		MaxIdleConns:        cfg.MaxConn,
		MaxIdleConnsPerHost: cfg.MaxConn,
		IdleConnTimeout:     30 * time.Second,
	}

	// Add proxy support
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.Timeout) * time.Millisecond,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Parse and normalize all targets
	var normalizedTargets []string
	for _, target := range cfg.Targets {
		normalized, err := ParseTarget(target)
		if err != nil {
			runtime_LogError(fmt.Sprintf("Invalid target '%s': %v", target, err))
			continue
		}
		normalizedTargets = append(normalizedTargets, normalized)
	}

	if len(normalizedTargets) == 0 {
		return nil
	}

	// Load YAML POC templates
	loader := GetPocTemplateLoader()
	templates, _ := loader.LoadAll()
	// Also load builtin templates
	templates = append(templates, LoadBuiltinTemplates()...)

	// Build check list
	type pocCheck struct {
		baseURL  string
		name     string
		cve      string
		severity string
		path     string
		match    string
		template *PocTemplate // nil for builtin checks
	}
	var checks []pocCheck

	for _, baseURL := range normalizedTargets {
		// Add YAML template checks
		for i := range templates {
			tmpl := &templates[i]
			if cfg.Severity != "" && !strings.EqualFold(tmpl.Info.Severity, cfg.Severity) {
				continue
			}
			checks = append(checks, pocCheck{
				baseURL:  baseURL,
				name:     tmpl.Info.Name,
				cve:      tmpl.Info.CVE,
				severity: tmpl.Info.Severity,
				template: tmpl,
			})
		}
		// Add builtin hardcoded checks
		for _, poc := range builtinPOCs {
			if cfg.Severity != "" && poc.Severity != cfg.Severity {
				continue
			}
			checks = append(checks, pocCheck{
				baseURL:  baseURL,
				name:     poc.Name,
				cve:      poc.CVE,
				severity: poc.Severity,
				path:     poc.Path,
				match:    poc.Match,
			})
		}
	}

	var results []PocResult
	var mu sync.Mutex
	var completed int64
	total := len(checks)

	sem := make(chan struct{}, cfg.MaxConn)
	var wg sync.WaitGroup

	for _, c := range checks {
		if cfg.IsStopped != nil && cfg.IsStopped() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c pocCheck) {
			defer wg.Done()
			defer func() { <-sem }()

			// Handle YAML template checks
			if c.template != nil {
				result := ExecutePocTemplate(client, *c.template, c.baseURL)
				if result.Vulnerable {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					if cfg.OnResult != nil {
						cfg.OnResult(result)
					}
				}
				cur := atomic.AddInt64(&completed, 1)
				if cfg.OnProgress != nil && cur%max(1, int64(total)/100) == 0 {
					cfg.OnProgress(int(cur), total)
				}
				return
			}

			// Handle builtin hardcoded checks
			fullURL := c.baseURL + c.path
			req, err := http.NewRequest("GET", fullURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "*/*")

			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			bodyStr := string(body)
			elapsed := time.Since(start).Milliseconds()

			vulnerable := false
			if c.match == "" {
				vulnerable = resp.StatusCode == 200
			} else {
				vulnerable = strings.Contains(bodyStr, c.match) || strings.Contains(strings.ToLower(bodyStr), strings.ToLower(c.match))
			}

			if vulnerable {
				result := PocResult{
					URL:         fullURL,
					PocName:     c.name,
					CveID:       c.cve,
					Severity:    c.severity,
					Vulnerable:  true,
					Request:     fmt.Sprintf("GET %s HTTP/1.1", c.path),
					Response:    fmt.Sprintf("HTTP/%d %d (%dms)", resp.ProtoMajor, resp.StatusCode, elapsed),
					Description: fmt.Sprintf("Found %s at %s", c.name, fullURL),
				}
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				if cfg.OnResult != nil {
					cfg.OnResult(result)
				}
			}

			cur := atomic.AddInt64(&completed, 1)
			if cfg.OnProgress != nil && cur%max(1, int64(total)/100) == 0 {
				cfg.OnProgress(int(cur), total)
			}
		}(c)
	}
	wg.Wait()
	return results
}

// runtime_LogError is a placeholder for logging errors
func runtime_LogError(msg string) {
	fmt.Println("[ERROR]", msg)
}
