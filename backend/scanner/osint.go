package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// OsintResult represents OSINT collection result
type OsintResult struct {
	Module string `json:"module"`
	Target string `json:"target"`
	Data   string `json:"data"`
}

// OsintConfig configures OSINT collection
type OsintConfig struct {
	Target  string
	Modules []string
}

// OsintCollect performs OSINT collection
func OsintCollect(cfg OsintConfig) []OsintResult {
	var results []OsintResult

	for _, mod := range cfg.Modules {
		switch mod {
		case "dns":
			results = append(results, collectDNS(cfg.Target))
		case "whois":
			results = append(results, collectWhois(cfg.Target))
		case "subdomain":
			results = append(results, collectSubdomains(cfg.Target))
		case "ipinfo":
			results = append(results, collectIPInfo(cfg.Target))
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
	// Basic WHOIS via DNS lookup
	data := map[string]interface{}{
		"domain": target,
	}

	// Resolve IP
	ips, err := net.LookupHost(target)
	if err == nil && len(ips) > 0 {
		data["ip"] = ips[0]
		// Try reverse DNS
		names, _ := net.LookupAddr(ips[0])
		if len(names) > 0 {
			data["reverse_dns"] = names[0]
		}
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
