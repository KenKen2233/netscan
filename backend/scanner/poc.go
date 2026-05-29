package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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

// PocTemplate represents a Nuclei-style POC template
type PocTemplate struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Requests    []struct {
		Method  string            `yaml:"method"`
		Path    []string          `yaml:"path"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
		Matchers []struct {
			Type     string   `yaml:"type"`
			Words    []string `yaml:"words"`
			Regex    []string `yaml:"regex"`
			Status   []int    `yaml:"status"`
		} `yaml:"matchers"`
	} `yaml:"http"`
}

// PocScanConfig configures POC scanning
type PocScanConfig struct {
	Targets    []string
	Templates  []PocTemplate
	Severity   string
	Timeout    int
	MaxConn    int
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
	{"Clientaccesspolicy.xml", "", "info", "/clientaccesspolicy.xml", ""},
}

// PocScan performs POC vulnerability detection
func PocScan(cfg PocScanConfig) []PocResult {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5000
	}
	if cfg.MaxConn == 0 {
		cfg.MaxConn = 20
	}

	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build check list
	type check struct {
		target string
		poc    interface{}
	}
	var checks []check

	for _, target := range cfg.Targets {
		if !strings.HasPrefix(target, "http") {
			target = "http://" + target
		}
		target = strings.TrimRight(target, "/")

		// Built-in POCs
		for _, poc := range builtinPOCs {
			if cfg.Severity != "" && poc.Severity != cfg.Severity {
				continue
			}
			checks = append(checks, check{target: target, poc: poc})
		}
	}

	var results []PocResult
	var mu sync.Mutex
	var completed int32
	total := len(checks)

	sem := make(chan struct{}, cfg.MaxConn)
	var wg sync.WaitGroup

	for _, c := range checks {
		if cfg.IsStopped != nil && cfg.IsStopped() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string, poc struct {
			Name     string
			CVE      string
			Severity string
			Path     string
			Match    string
		}) {
			defer wg.Done()
			defer func() { <-sem }()

			url := target + poc.Path
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

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			bodyStr := string(body)
			elapsed := time.Since(start).Milliseconds()

			vulnerable := false
			if poc.Match == "" {
				vulnerable = resp.StatusCode == 200
			} else {
				vulnerable = strings.Contains(bodyStr, poc.Match) || strings.Contains(strings.ToLower(bodyStr), strings.ToLower(poc.Match))
			}

			if vulnerable {
				result := PocResult{
					URL:         url,
					PocName:     poc.Name,
					CveID:       poc.CVE,
					Severity:    poc.Severity,
					Vulnerable:  true,
					Request:     fmt.Sprintf("GET %s HTTP/1.1", poc.Path),
					Response:    fmt.Sprintf("HTTP/%d %d (%dms)", resp.ProtoMajor, resp.StatusCode, elapsed),
					Description: fmt.Sprintf("Found %s at %s", poc.Name, url),
				}
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				if cfg.OnResult != nil {
					cfg.OnResult(result)
				}
			}

			completed++
			if cfg.OnProgress != nil {
				cfg.OnProgress(int(completed), total)
			}
		}(c.target, c.poc.(struct {
			Name     string
			CVE      string
			Severity string
			Path     string
			Match    string
		}))
	}
	wg.Wait()
	return results
}
