package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WebFingerResult represents web fingerprint result
type WebFingerResult struct {
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

// WebFingerConfig configures web fingerprinting
type WebFingerConfig struct {
	Targets    []string
	Timeout    int
	MaxConn    int
	OnResult   func(WebFingerResult)
	OnProgress func(completed, total int)
	IsStopped  func() bool
}

// CMS signatures
var cmsSignatures = []struct {
	Name    string
	Pattern string
	Header  string
	Body    string
}{
	{"WordPress", "", "x-powered-by", "wp-content"},
	{"WordPress", "", "", "wp-includes"},
	{"Joomla", "", "", "joomla"},
	{"Drupal", "", "x-generator", "drupal"},
	{"Discuz", "", "", "discuz"},
	{"DedeCMS", "", "", "dedecms"},
	{"ThinkPHP", "", "x-powered-by", "thinkphp"},
	{"Laravel", "", "set-cookie", "laravel"},
	{"Django", "", "", "csrfmiddlewaretoken"},
	{"Spring", "", "", "Whitelabel Error Page"},
	{"Vue.js", "", "", "vue.js"},
	{"React", "", "", "_reactRootContainer"},
	{"Angular", "", "", "ng-version"},
	{"jQuery", "", "", "jquery"},
	{"Bootstrap", "", "", "bootstrap"},
	{"Nginx", "server", "nginx", ""},
	{"Apache", "server", "apache", ""},
	{"IIS", "server", "microsoft-iis", ""},
	{"Tomcat", "server", "tomcat", ""},
	{"Cloudflare", "server", "cloudflare", ""},
	{"AWS", "server", "amazons3", ""},
	{"PHP", "x-powered-by", "php", ""},
	{"ASP.NET", "x-powered-by", "asp.net", ""},
	{"Express", "x-powered-by", "express", ""},
}

// WebFinger performs web fingerprinting
func WebFinger(cfg WebFingerConfig) []WebFingerResult {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5000
	}
	if cfg.MaxConn == 0 {
		cfg.MaxConn = 50
	}

	var results []WebFingerResult
	var mu sync.Mutex
	var completed int32
	total := len(cfg.Targets)

	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        cfg.MaxConn,
			MaxIdleConnsPerHost: 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	sem := make(chan struct{}, cfg.MaxConn)
	var wg sync.WaitGroup

	for _, target := range cfg.Targets {
		if cfg.IsStopped != nil && cfg.IsStopped() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := fingerURL(client, url)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			if cfg.OnResult != nil {
				cfg.OnResult(result)
			}
			completed++
			if cfg.OnProgress != nil {
				cfg.OnProgress(int(completed), total)
			}
		}(target)
	}
	wg.Wait()
	return results
}

func fingerURL(client *http.Client, url string) WebFingerResult {
	result := WebFingerResult{URL: url}

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
		result.URL = url
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)

	// Extract title
	if m := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`).FindStringSubmatch(bodyStr); len(m) > 1 {
		result.Title = strings.TrimSpace(m[1])
	}

	// Detect CMS and frameworks
	lowerBody := strings.ToLower(bodyStr)
	for _, sig := range cmsSignatures {
		if sig.Header != "" {
			headerVal := strings.ToLower(resp.Header.Get(sig.Header))
			if strings.Contains(headerVal, strings.ToLower(sig.Pattern)) {
				if result.CMS == "" {
					result.CMS = sig.Name
				}
			}
		}
		if sig.Body != "" && strings.Contains(lowerBody, strings.ToLower(sig.Body)) {
			if result.CMS == "" {
				result.CMS = sig.Name
			}
		}
	}

	// Detect language
	if resp.Header.Get("X-Powered-By") != "" {
		xpb := strings.ToLower(resp.Header.Get("X-Powered-By"))
		if strings.Contains(xpb, "php") {
			result.Language = "PHP"
		} else if strings.Contains(xpb, "asp") {
			result.Language = "ASP.NET"
		}
	}
	if strings.Contains(lowerBody, ".php") {
		result.Language = "PHP"
	} else if strings.Contains(lowerBody, ".aspx") || strings.Contains(lowerBody, "asp.net") {
		result.Language = "ASP.NET"
	} else if strings.Contains(lowerBody, ".jsp") || strings.Contains(lowerBody, "servlet") {
		result.Language = "Java"
	} else if strings.Contains(lowerBody, "django") || strings.Contains(lowerBody, "csrf") {
		result.Language = "Python"
	} else if strings.Contains(lowerBody, "rails") || strings.Contains(lowerBody, "ruby") {
		result.Language = "Ruby"
	}

	// Detect CDN
	if strings.Contains(lowerBody, "cloudflare") || strings.Contains(resp.Header.Get("Server"), "cloudflare") {
		result.CDN = "Cloudflare"
	} else if resp.Header.Get("X-CDN") != "" {
		result.CDN = resp.Header.Get("X-CDN")
	} else if strings.Contains(resp.Header.Get("Server"), "cloudfront") {
		result.CDN = "AWS CloudFront"
	}

	return result
}

// ExtractTitle extracts title from HTML body
func ExtractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	if m := re.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// FormatWebFingerResult formats result for display
func FormatWebFingerResult(r WebFingerResult) string {
	return fmt.Sprintf("[%d] %s | %s | %s | %s",
		r.StatusCode, r.URL, r.Server, r.CMS, r.Title)
}
