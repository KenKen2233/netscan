package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OsintResult represents OSINT collection result
type OsintResult struct {
	Module string `json:"module"`
	Target string `json:"target"`
	Data   string `json:"data"`
}

// OsintConfig configures OSINT collection
type OsintConfig struct {
	Target     string
	Modules    []string
	OnProgress func(completed, total int)
	IsStopped  func() bool
}

// OsintCollect performs OSINT collection
func OsintCollect(cfg OsintConfig) []OsintResult {
	var results []OsintResult
	total := len(cfg.Modules)

	for i, mod := range cfg.Modules {
		if cfg.IsStopped != nil && cfg.IsStopped() {
			break
		}
		switch mod {
		case "dns":
			results = append(results, collectDNS(cfg.Target))
		case "whois":
			results = append(results, collectWhois(cfg.Target))
		case "subdomain":
			results = append(results, collectSubdomains(cfg.Target))
		case "crtsh":
			results = append(results, collectCrtSh(cfg.Target))
		case "ipinfo":
			results = append(results, collectIPInfo(cfg.Target))
		case "ssl":
			results = append(results, collectSSL(cfg.Target))
		case "subdomain_brute":
			results = append(results, collectSubdomainBrute(cfg.Target))
		case "shodan":
			results = append(results, collectShodan(cfg.Target))
		}
		if cfg.OnProgress != nil {
			cfg.OnProgress(i+1, total)
		}
	}
	return results
}

func collectDNS(target string) OsintResult {
	data := map[string]interface{}{
		"domain": target,
	}

	// A records
	if ips, err := net.LookupHost(target); err == nil {
		data["a_records"] = ips
	}

	// CNAME
	if cname, err := net.LookupCNAME(target); err == nil && cname != "" {
		data["cname"] = cname
	}

	// MX records
	if mxs, err := net.LookupMX(target); err == nil {
		var mxList []string
		for _, mx := range mxs {
			mxList = append(mxList, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
		data["mx_records"] = mxList
	}

	// NS records
	if nss, err := net.LookupNS(target); err == nil {
		var nsList []string
		for _, ns := range nss {
			nsList = append(nsList, ns.Host)
		}
		data["ns_records"] = nsList
	}

	// TXT records
	if txts, err := net.LookupTXT(target); err == nil {
		data["txt_records"] = txts
	}

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "dns", Target: target, Data: string(jsonData)}
}

func collectWhois(target string) OsintResult {
	data := map[string]interface{}{
		"domain": target,
	}

	// Resolve IP
	ips, err := net.LookupHost(target)
	if err == nil && len(ips) > 0 {
		data["ip"] = ips[0]
		names, _ := net.LookupAddr(ips[0])
		if len(names) > 0 {
			data["reverse_dns"] = names[0]
		}
	}

	// Real WHOIS via TCP
	whoisResult, err := WhoisLookup(target)
	if err == nil && whoisResult != "" {
		// Parse key fields from WHOIS response
		lines := strings.Split(whoisResult, "\n")
		parsed := make(map[string]string)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
				continue
			}
			if idx := strings.Index(line, ":"); idx > 0 {
				key := strings.TrimSpace(line[:idx])
				val := strings.TrimSpace(line[idx+1:])
				if val != "" {
					keyLower := strings.ToLower(key)
					switch {
					case strings.Contains(keyLower, "registrar"):
						parsed["registrar"] = val
					case strings.Contains(keyLower, "creation"):
						parsed["creation_date"] = val
					case strings.Contains(keyLower, "expir"):
						parsed["expiry_date"] = val
					case strings.Contains(keyLower, "name server"):
						parsed["name_servers"] += val + ", "
					case strings.Contains(keyLower, "updated"):
						parsed["updated_date"] = val
					}
				}
			}
		}
		data["whois_parsed"] = parsed
		data["whois_raw"] = whoisResult[:min(len(whoisResult), 2000)] // truncate
	} else if err != nil {
		data["whois_error"] = err.Error()
	}

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "whois", Target: target, Data: string(jsonData)}
}

func collectSubdomains(target string) OsintResult {
	data := map[string]interface{}{
		"domain": target,
	}

	// Try common subdomains
	commonSubs := []string{
		"www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
		"ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "test", "dev",
		"staging", "admin", "panel", "api", "app", "beta", "demo", "blog",
		"shop", "store", "forum", "cdn", "static", "media", "img", "images",
		"vpn", "proxy", "gateway", "portal", "login", "sso", "auth",
		"oa", "crm", "erp", "hr", "finance", "git", "gitlab", "jenkins",
		"ci", "cd", "jira", "wiki", "confluence", "doc", "docs", "help",
		"support", "status", "monitor", "grafana", "prometheus", "elk",
		"kibana", "zabbix", "nagios", "cacti", "awx", "ansible", "terraform",
	}

	var found []string
	for _, sub := range commonSubs {
		domain := sub + "." + target
		ips, err := net.LookupHost(domain)
		if err == nil && len(ips) > 0 {
			found = append(found, domain+" -> "+strings.Join(ips, ", "))
		}
	}

	data["subdomains"] = found
	data["total"] = len(found)

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "subdomain", Target: target, Data: string(jsonData)}
}

func collectIPInfo(target string) OsintResult {
	data := map[string]interface{}{
		"target": target,
	}

	// Resolve IP
	ips, err := net.LookupHost(target)
	if err != nil {
		data["error"] = err.Error()
		jsonData, _ := json.Marshal(data)
		return OsintResult{Module: "ipinfo", Target: target, Data: string(jsonData)}
	}

	if len(ips) > 0 {
		ip := ips[0]
		data["ip"] = ip

		// Check if private IP
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			data["is_private"] = parsedIP.IsPrivate()
			data["is_loopback"] = parsedIP.IsLoopback()
		}

		// Reverse DNS
		names, _ := net.LookupAddr(ip)
		if len(names) > 0 {
			data["reverse_dns"] = names[0]
		}
	}

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "ipinfo", Target: target, Data: string(jsonData)}
}

func collectCrtSh(target string) OsintResult {
	data := map[string]interface{}{
		"domain": target,
	}

	subdomains, err := QueryCrtSh(target)
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["subdomains"] = subdomains
		data["total"] = len(subdomains)
	}

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "crtsh", Target: target, Data: string(jsonData)}
}

// collectSSL collects SSL certificate information
func collectSSL(target string) OsintResult {
	data := map[string]interface{}{"domain": target}

	info, err := ParseSSLCertificate(target)
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["subject"] = info.Subject
		data["issuer"] = info.Issuer
		data["not_before"] = info.NotBefore
		data["not_after"] = info.NotAfter
		data["sans"] = info.SANs
		data["is_valid"] = info.IsValid
		data["days_left"] = info.DaysLeft
		data["serial_number"] = info.SerialNumber
	}

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "ssl", Target: target, Data: string(jsonData)}
}

// collectSubdomainBrute performs subdomain dictionary brute force
func collectSubdomainBrute(target string) OsintResult {
	data := map[string]interface{}{"domain": target}

	var found []map[string]string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	for _, word := range DefaultSubdomainWordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			fqdn := w + "." + target
			ips, err := net.LookupHost(fqdn)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				found = append(found, map[string]string{"domain": fqdn, "ip": strings.Join(ips, ", ")})
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()

	data["subdomains"] = found
	data["total"] = len(found)
	data["wordlist_size"] = len(DefaultSubdomainWordlist)

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "subdomain_brute", Target: target, Data: string(jsonData)}
}

// collectShodan queries Shodan for host information
func collectShodan(target string) OsintResult {
	data := map[string]interface{}{"target": target}

	// Resolve IP first
	ips, err := net.LookupHost(target)
	if err != nil || len(ips) == 0 {
		data["error"] = "无法解析域名"
		jsonData, _ := json.Marshal(data)
		return OsintResult{Module: "shodan", Target: target, Data: string(jsonData)}
	}

	ip := ips[0]
	data["ip"] = ip

	result, err := ShodanLookup(ip)
	if err != nil {
		data["error"] = err.Error()
	} else {
		data["ports"] = result.Ports
		data["os"] = result.OS
		data["org"] = result.Org
		data["isp"] = result.ISP
		data["hostnames"] = result.Hostnames
		data["vulns"] = result.Vulns
	}

	jsonData, _ := json.Marshal(data)
	return OsintResult{Module: "shodan", Target: target, Data: string(jsonData)}
}

// QueryCrtSh queries crt.sh certificate transparency logs
func QueryCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		Name string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.Name, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				results = append(results, name)
			}
		}
	}
	return results, nil
}
