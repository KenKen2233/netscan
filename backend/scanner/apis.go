package scanner

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ShodanResult represents Shodan API response
type ShodanResult struct {
	IP       string   `json:"ip"`
	Ports    []int    `json:"ports"`
	OS       string   `json:"os"`
	Org      string   `json:"org"`
	ISP      string   `json:"isp"`
	Hostnames []string `json:"hostnames"`
	Vulns    []string `json:"vulns"`
	Banner   string   `json:"banner"`
}

// FofaResult represents Fofa API response entry
type FofaResult struct {
	Host    string   `json:"host"`
	IP      string   `json:"ip"`
	Port    string   `json:"port"`
	Title   string   `json:"title"`
	OS      string   `json:"os"`
	Country string   `json:"country"`
}

// SSLCertInfo represents parsed SSL certificate information
type SSLCertInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SANs         []string `json:"sans"`
	SerialNumber string   `json:"serial_number"`
	Fingerprint  string   `json:"fingerprint"`
	Version      int      `json:"version"`
	KeySize      int      `json:"key_size"`
	IsValid      bool     `json:"is_valid"`
	DaysLeft     int      `json:"days_left"`
}

// ShodanLookup queries Shodan API for host information
// Requires API key: set via SHODAN_API_KEY environment variable
func ShodanLookup(ip string) (*ShodanResult, error) {
	apiKey := getEnvOrDefault("SHODAN_API_KEY", "")
	if apiKey == "" {
		return nil, fmt.Errorf("Shodan API key not configured (set SHODAN_API_KEY)")
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Shodan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Shodan returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result ShodanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse Shodan response: %w", err)
	}

	return &result, nil
}

// FofaSearch queries Fofa API for asset discovery
// Requires API key: set via FOFA_EMAIL and FOFA_KEY environment variables
func FofaSearch(query string, size int) ([]FofaResult, error) {
	email := getEnvOrDefault("FOFA_EMAIL", "")
	key := getEnvOrDefault("FOFA_KEY", "")
	if email == "" || key == "" {
		return nil, fmt.Errorf("Fofa API not configured (set FOFA_EMAIL and FOFA_KEY)")
	}

	if size <= 0 {
		size = 100
	}

	url := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d",
		email, key, toBase64(query), size)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Fofa request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results [][]string `json:"results"`
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse Fofa response: %w", err)
	}

	var fofaResults []FofaResult
	for _, r := range result.Results {
		if len(r) >= 4 {
			fofaResults = append(fofaResults, FofaResult{
				Host:  r[0],
				IP:    r[1],
				Port:  r[2],
				Title: r[3],
			})
		}
	}

	return fofaResults, nil
}

// ParseSSLCertificate parses SSL certificate from a host
func ParseSSLCertificate(host string) (*SSLCertInfo, error) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := certs[0]
	info := &SSLCertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		SerialNumber: cert.SerialNumber.String(),
		Version:      cert.Version,
		SANs:         cert.DNSNames,
	}

	// Add IP SANs
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	// Calculate fingerprint
	info.Fingerprint = fmt.Sprintf("%x", cert.SerialNumber)

	// Check validity
	now := time.Now()
	info.IsValid = now.After(cert.NotBefore) && now.Before(cert.NotAfter)
	info.DaysLeft = int(cert.NotAfter.Sub(now).Hours() / 24)

	// Estimate key size
	if cert.PublicKey != nil {
		switch key := cert.PublicKey.(type) {
		case *tls.Certificate:
			_ = key
		}
	}

	return info, nil
}

// HunterResult represents Hunter API response entry
// Hunter: https://hunter.qianxin.com/
type HunterResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Host    string `json:"host"`
	Title   string `json:"title"`
	Domain  string `json:"domain"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// QuakeResult represents Quake API response entry
type QuakeResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Host    string `json:"host"`
	Title   string `json:"title"`
	Service string `json:"service"`
	Country string `json:"country"`
	OS      string `json:"os"`
}

// ZoomEyeResult represents ZoomEye API response entry
type ZoomEyeResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Host    string `json:"host"`
	Title   string `json:"title"`
	Server  string `json:"server"`
	Country string `json:"country"`
	OS      string `json:"os"`
}

// HunterSearch queries Hunter API
func HunterSearch(query string, size int) ([]HunterResult, error) {
	apiKey := getEnvOrDefault("HUNTER_KEY", "")
	if apiKey == "" {
		return nil, fmt.Errorf("Hunter API key not configured")
	}
	if size <= 0 {
		size = 100
	}
	// Hunter API: https://hunter.qianxin.com/openAPI/search
	encoded := toBase64(query)
	url := fmt.Sprintf("https://hunter.qianxin.com/openAPI/search?api-key=%s&search=%s&page_size=%d", apiKey, encoded, size)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Hunter request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Code int `json:"code"`
		Data struct {
			Arr []struct {
				IP      string `json:"ip"`
				Port    int    `json:"port"`
				WebName string `json:"web_name"`
				Domain  string `json:"domain"`
				Country string `json:"country"`
				City    string `json:"city"`
			} `json:"arr"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse Hunter response: %w", err)
	}
	var results []HunterResult
	for _, r := range result.Data.Arr {
		results = append(results, HunterResult{IP: r.IP, Port: r.Port, Host: r.Domain, Title: r.WebName, Domain: r.Domain, Country: r.Country, City: r.City})
	}
	return results, nil
}

// QuakeSearch queries Quake API
func QuakeSearch(query string, size int) ([]QuakeResult, error) {
	apiKey := getEnvOrDefault("QUAKE_KEY", "")
	if apiKey == "" {
		return nil, fmt.Errorf("Quake API key not configured")
	}
	if size <= 0 {
		size = 100
	}
	url := "https://quake.360.net/api/v3/search/quake_service"
	payload := fmt.Sprintf(`{"query":"%s","size":%d}`, query, size)
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload))
	req.Header.Set("X-QuakeToken", apiKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Quake request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Code int `json:"code"`
		Data []struct {
			IP      string `json:"ip"`
			Port    int    `json:"port"`
			Name    string `json:"service.name"`
			Host    string `json:"hostname"`
			Title   string `json:"service.http.title"`
			Country string `json:"location.country_cn"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse Quake response: %w", err)
	}
	var results []QuakeResult
	for _, r := range result.Data {
		results = append(results, QuakeResult{IP: r.IP, Port: r.Port, Host: r.Host, Title: r.Title, Service: r.Name, Country: r.Country})
	}
	return results, nil
}

// ZoomEyeSearch queries ZoomEye API
func ZoomEyeSearch(query string, size int) ([]ZoomEyeResult, error) {
	apiKey := getEnvOrDefault("ZOOMEYE_KEY", "")
	if apiKey == "" {
		return nil, fmt.Errorf("ZoomEye API key not configured")
	}
	if size <= 0 {
		size = 100
	}
	// ZoomEye API
	encoded := toBase64(query)
	url := fmt.Sprintf("https://api.zoomeye.org/host/search?query=%s&page=1", encoded)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("API-KEY", apiKey)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ZoomEye request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Matches []struct {
			IP      string   `json:"ip"`
			PortInfo struct {
				Port   int    `json:"port"`
				Server string `json:"server"`
			} `json:"portinfo"`
			Title   string `json:"title"`
			Country struct {
				Name string `json:"name"`
			} `json:"geoinfo"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse ZoomEye response: %w", err)
	}
	var results []ZoomEyeResult
	for _, r := range result.Matches {
		results = append(results, ZoomEyeResult{IP: r.IP, Port: r.PortInfo.Port, Title: r.Title, Server: r.PortInfo.Server, Country: r.Country.Name})
	}
	return results, nil
}

// WhoisLookup performs a basic WHOIS lookup via TCP
func WhoisLookup(domain string) (string, error) {
	// Determine WHOIS server
	server := "whois.iana.org"
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		tld := parts[len(parts)-1]
		switch tld {
		case "com", "net":
			server = "whois.verisign-grs.com"
		case "org":
			server = "whois.pir.org"
		case "cn":
			server = "whois.cnnic.cn"
		case "io":
			server = "whois.nic.io"
		case "info":
			server = "whois.afilias.net"
		}
	}

	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("WHOIS connection failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "%s\r\n", domain)

	var result strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	return result.String(), nil
}

func getEnvOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func toBase64(s string) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var result []byte
	for i := 0; i < len(s); i += 3 {
		end := i + 3
		if end > len(s) {
			end = len(s)
		}
		chunk := s[i:end]
		b := uint32(chunk[0]) << 16
		if len(chunk) > 1 {
			b |= uint32(chunk[1]) << 8
		}
		if len(chunk) > 2 {
			b |= uint32(chunk[2])
		}
		result = append(result, chars[(b>>18)&0x3F])
		result = append(result, chars[(b>>12)&0x3F])
		if len(chunk) > 1 {
			result = append(result, chars[(b>>6)&0x3F])
		} else {
			result = append(result, '=')
		}
		if len(chunk) > 2 {
			result = append(result, chars[b&0x3F])
		} else {
			result = append(result, '=')
		}
	}
	return string(result)
}
