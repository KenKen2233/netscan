package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PocTemplate represents a YAML-based POC definition
type PocTemplate struct {
	ID          string            `yaml:"id" json:"id"`
	Info        PocInfo           `yaml:"info" json:"info"`
	Requests    []PocRequest      `yaml:"requests" json:"requests"`
	Variables   map[string]string `yaml:"variables" json:"variables"`
}

type PocInfo struct {
	Name     string   `yaml:"name" json:"name"`
	Author   string   `yaml:"author" json:"author"`
	Severity string   `yaml:"severity" json:"severity"`
	CVE      string   `yaml:"cve" json:"cve"`
	Tags     []string `yaml:"tags" json:"tags"`
	Ref      []string `yaml:"reference" json:"reference"`
}

type PocRequest struct {
	Method         string            `yaml:"method" json:"method"`
	Path           string            `yaml:"path" json:"path"`
	Headers        map[string]string `yaml:"headers" json:"headers"`
	Body           string            `yaml:"body" json:"body"`
	FollowRedirect bool              `yaml:"follow_redirect" json:"follow_redirect"`
	Matchers       []PocMatcher      `yaml:"matchers" json:"matchers"`
	Extractors     []PocExtractor    `yaml:"extractors" json:"extractors"`
}

type PocMatcher struct {
	Type      string   `yaml:"type" json:"type"` // word, regex, status, binary
	Condition string   `yaml:"condition" json:"condition"` // and, or
	Words     []string `yaml:"words" json:"words"`
	Regex     []string `yaml:"regex" json:"regex"`
	Status    []int    `yaml:"status" json:"status"`
	Negative  bool     `yaml:"negative" json:"negative"`
	Part      string   `yaml:"part" json:"part"` // body, header, all
}

type PocExtractor struct {
	Type  string `yaml:"type" json:"type"` // regex, kval, json
	Name  string `yaml:"name" json:"name"`
	Regex string `yaml:"regex" json:"regex"`
	JSON  string `yaml:"json" json:"json"`
	Part  string `yaml:"part" json:"part"`
}

// PocTemplateLoader loads and manages YAML POC templates
type PocTemplateLoader struct {
	templates []PocTemplate
	dirs      []string
}

// NewPocTemplateLoader creates a new template loader
func NewPocTemplateLoader(dirs ...string) *PocTemplateLoader {
	return &PocTemplateLoader{dirs: dirs}
}

// LoadAll loads all YAML POC templates from configured directories
func (l *PocTemplateLoader) LoadAll() ([]PocTemplate, error) {
	var all []PocTemplate
	seen := make(map[string]bool)

	for _, dir := range l.dirs {
		templates, err := l.loadDir(dir)
		if err != nil {
			continue // skip dirs that don't exist
		}
		for _, t := range templates {
			if !seen[t.ID] {
				seen[t.ID] = true
				all = append(all, t)
			}
		}
	}
	l.templates = all
	return all, nil
}

func (l *PocTemplateLoader) loadDir(dir string) ([]PocTemplate, error) {
	var templates []PocTemplate

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		tmpl, err := l.loadFile(path)
		if err != nil {
			return nil // skip invalid files
		}
		templates = append(templates, tmpl)
		return nil
	})

	return templates, err
}

func (l *PocTemplateLoader) loadFile(path string) (PocTemplate, error) {
	var tmpl PocTemplate
	data, err := os.ReadFile(path)
	if err != nil {
		return tmpl, err
	}
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return tmpl, err
	}
	if tmpl.ID == "" {
		tmpl.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return tmpl, nil
}

// FilterBySeverity filters templates by severity level
func (l *PocTemplateLoader) FilterBySeverity(severity string) []PocTemplate {
	if severity == "" {
		return l.templates
	}
	var filtered []PocTemplate
	for _, t := range l.templates {
		if strings.EqualFold(t.Info.Severity, severity) {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// FilterByTags filters templates by tags
func (l *PocTemplateLoader) FilterByTags(tags []string) []PocTemplate {
	if len(tags) == 0 {
		return l.templates
	}
	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[strings.ToLower(t)] = true
	}
	var filtered []PocTemplate
	for _, tmpl := range l.templates {
		for _, t := range tmpl.Info.Tags {
			if tagSet[strings.ToLower(t)] {
				filtered = append(filtered, tmpl)
				break
			}
		}
	}
	return filtered
}

// ExecutePocTemplate executes a YAML POC template against a target
func ExecutePocTemplate(client *http.Client, tmpl PocTemplate, baseURL string) PocResult {
	baseURL = strings.TrimRight(baseURL, "/")

	for _, req := range tmpl.Requests {
		fullURL := baseURL + req.Path

		httpReq, err := http.NewRequest(strings.ToUpper(req.Method), fullURL, strings.NewReader(req.Body))
		if err != nil {
			continue
		}

		// Set default headers
		httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}

		start := time.Now()
		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		elapsed := time.Since(start).Milliseconds()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()

		bodyStr := string(body)
		headerStr := fmt.Sprintf("%+v", resp.Header)

		// Check matchers
		matched := checkMatchers(req.Matchers, resp.StatusCode, bodyStr, headerStr)
		if matched {
			return PocResult{
				URL:         fullURL,
				PocName:     tmpl.Info.Name,
				CveID:       tmpl.Info.CVE,
				Severity:    tmpl.Info.Severity,
				Vulnerable:  true,
				Request:     fmt.Sprintf("%s %s HTTP/1.1", strings.ToUpper(req.Method), req.Path),
				Response:    fmt.Sprintf("HTTP/%d %d (%dms)", resp.ProtoMajor, resp.StatusCode, elapsed),
				Description: fmt.Sprintf("[%s] %s matched at %s", tmpl.ID, tmpl.Info.Name, fullURL),
			}
		}
	}

	return PocResult{
		URL:        baseURL,
		PocName:    tmpl.Info.Name,
		CveID:      tmpl.Info.CVE,
		Severity:   tmpl.Info.Severity,
		Vulnerable: false,
	}
}

func checkMatchers(matchers []PocMatcher, statusCode int, body, headers string) bool {
	if len(matchers) == 0 {
		return false
	}

	for _, m := range matchers {
		matched := false
		content := body
		if m.Part == "header" {
			content = headers
		}

		switch m.Type {
		case "word":
			lower := strings.ToLower(content)
			for _, w := range m.Words {
				if strings.Contains(lower, strings.ToLower(w)) {
					matched = true
					break
				}
			}
		case "regex":
			for _, r := range m.Regex {
				if re, err := regexp.Compile(r); err == nil && re.MatchString(content) {
					matched = true
					break
				}
			}
		case "status":
			for _, s := range m.Status {
				if statusCode == s {
					matched = true
					break
				}
			}
		case "binary":
			for _, w := range m.Words {
				if strings.Contains(body, w) {
					matched = true
					break
				}
			}
		}

		if m.Negative {
			matched = !matched
		}

		cond := m.Condition
		if cond == "" {
			cond = "and" // default to AND
		}

		if cond == "and" && !matched {
			return false
		}
		if cond == "or" && matched {
			return true
		}
	}

	// All AND matchers passed
	return true
}

// LoadBuiltinTemplates returns embedded example POC templates
func LoadBuiltinTemplates() []PocTemplate {
	return []PocTemplate{
		{
			ID: "spring-boot-actuator",
			Info: PocInfo{
				Name:     "Spring Boot Actuator Exposure",
				Severity: "high",
				CVE:      "CVE-2022-22947",
				Tags:     []string{"spring", "actuator", "exposure"},
			},
			Requests: []PocRequest{
				{
					Method: "GET",
					Path:   "/actuator",
					Matchers: []PocMatcher{
						{Type: "word", Words: []string{"status"}, Part: "body"},
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
		{
			ID: "swagger-ui",
			Info: PocInfo{
				Name:     "Swagger UI Exposure",
				Severity: "info",
				Tags:     []string{"swagger", "api", "exposure"},
			},
			Requests: []PocRequest{
				{
					Method: "GET",
					Path:   "/swagger-ui.html",
					Matchers: []PocMatcher{
						{Type: "word", Words: []string{"swagger"}, Part: "body"},
					},
				},
			},
		},
		{
			ID: "env-file-exposure",
			Info: PocInfo{
				Name:     ".env File Exposure",
				Severity: "critical",
				Tags:     []string{"env", "config", "exposure"},
			},
			Requests: []PocRequest{
				{
					Method: "GET",
					Path:   "/.env",
					Matchers: []PocMatcher{
						{Type: "word", Words: []string{"APP_KEY", "DB_PASSWORD", "SECRET"}, Condition: "or"},
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
		{
			ID: "git-config-exposure",
			Info: PocInfo{
				Name:     "Git Config Exposure",
				Severity: "high",
				Tags:     []string{"git", "config", "exposure"},
			},
			Requests: []PocRequest{
				{
					Method: "GET",
					Path:   "/.git/config",
					Matchers: []PocMatcher{
						{Type: "word", Words: []string{"repositoryformatversion"}},
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
		{
			ID: "docker-api-exposure",
			Info: PocInfo{
				Name:     "Docker API Exposure",
				Severity: "critical",
				Tags:     []string{"docker", "api", "exposure"},
			},
			Requests: []PocRequest{
				{
					Method: "GET",
					Path:   "/containers/json",
					Matchers: []PocMatcher{
						{Type: "word", Words: []string{"Id"}},
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
		{
			ID: "kubernetes-api-exposure",
			Info: PocInfo{
				Name:     "Kubernetes API Exposure",
				Severity: "high",
				Tags:     []string{"kubernetes", "k8s", "api", "exposure"},
			},
			Requests: []PocRequest{
				{
					Method: "GET",
					Path:   "/api/v1/namespaces",
					Matchers: []PocMatcher{
						{Type: "word", Words: []string{"namespaces"}},
						{Type: "status", Status: []int{200}},
					},
				},
			},
		},
	}
}

// TemplateToJSON serializes a template to JSON for frontend
func TemplateToJSON(tmpl PocTemplate) string {
	data, _ := json.MarshalIndent(tmpl, "", "  ")
	return string(data)
}

// PocTemplateSource represents a remote POC template source
var PocTemplateSources = []struct {
	Name string
	URL  string
}{
	{"NetScan Official", "https://raw.githubusercontent.com/KenKen2233/netscan/main/assets/pocs/"},
}

// UpdatePocTemplates downloads latest POC templates from remote sources
func UpdatePocTemplates(localDir string) (int, error) {
	os.MkdirAll(localDir, 0755)
	total := 0

	client := &http.Client{Timeout: 30 * time.Second}
	for _, src := range PocTemplateSources {
		// Try to download index file
		indexURL := src.URL + "index.txt"
		resp, err := client.Get(indexURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		for _, name := range strings.Split(string(body), "\n") {
			name = strings.TrimSpace(name)
			if name == "" || strings.HasPrefix(name, "#") {
				continue
			}
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				name += ".yaml"
			}

			fileURL := src.URL + name
			fileResp, err := client.Get(fileURL)
			if err != nil {
				continue
			}
			fileData, _ := io.ReadAll(fileResp.Body)
			fileResp.Body.Close()

			if len(fileData) > 0 {
				destPath := filepath.Join(localDir, name)
				os.WriteFile(destPath, fileData, 0644)
				total++
			}
		}
	}
	return total, nil
}
