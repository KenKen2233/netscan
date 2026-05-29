package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Common service ports
var CommonPorts = map[int]string{
	21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP",
	110:"POP3", 111:"RPCBind", 135:"MSRPC", 139:"NetBIOS", 143:"IMAP",
	443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S", 1433:"MSSQL",
	1521:"Oracle", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 5900:"VNC",
	6379:"Redis", 8080:"HTTP-Proxy", 8443:"HTTPS-Alt", 8888:"HTTP-Alt",
	9200:"Elasticsearch", 11211:"Memcached", 27017:"MongoDB",
}

var Top100Ports = []int{
	7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6379,6646,7070,7100,7402,7938,8000,8001,8008,8009,8080,8081,8443,8888,9000,9001,9100,9200,9443,9999,10000,11211,27017,28017,50000,
}

// PortScanResult represents a single port scan result
type PortScanResult struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	State        string `json:"state"`
	Banner       string `json:"banner"`
	ResponseTime int64  `json:"response_time"`
}

// PortScanConfig configures port scanning
type PortScanConfig struct {
	Targets   []string
	Ports     []int
	Mode      string // tcp, syn, udp
	Timeout   int    // ms
	MaxConn   int
	OnResult  func(PortScanResult)
	OnProgress func(completed, total int)
	IsStopped func() bool
}

// PortScan performs port scanning
func PortScan(cfg PortScanConfig) []PortScanResult {
	var ips []string
	for _, t := range cfg.Targets {
		ips = append(ips, expandTarget(t)...)
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = Top100Ports
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 500
	}
	if cfg.MaxConn == 0 {
		cfg.MaxConn = 500
	}

	total := len(ips) * len(cfg.Ports)
	var completed int64
	var results []PortScanResult
	var mu sync.Mutex

	sem := make(chan struct{}, cfg.MaxConn)
	var wg sync.WaitGroup

	for _, ip := range ips {
		for _, port := range cfg.Ports {
			if cfg.IsStopped != nil && cfg.IsStopped() {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				addr := fmt.Sprintf("%s:%d", ip, port)
				start := time.Now()
				conn, err := net.DialTimeout("tcp", addr, time.Duration(cfg.Timeout)*time.Millisecond)
				elapsed := time.Since(start).Milliseconds()

				if err == nil {
					conn.Close()
					svc := CommonPorts[port]
					result := PortScanResult{
						IP: ip, Port: port, Protocol: cfg.Mode,
						Service: svc, State: "open", ResponseTime: elapsed,
					}
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					if cfg.OnResult != nil {
						cfg.OnResult(result)
					}
				}

				cur := int(atomic.AddInt64(&completed, 1))
				if cfg.OnProgress != nil && cur%max(1, total/100) == 0 {
					cfg.OnProgress(cur, total)
				}
			}(ip, port)
		}
	}
	wg.Wait()
	return results
}

// expandTarget expands a target string to a list of IPs
func expandTarget(target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}
	if strings.Contains(target, "-") {
		return expandRange(target)
	}
	// Try to resolve hostname
	ips, err := net.LookupHost(target)
	if err != nil {
		return []string{target}
	}
	return ips
}

func expandCIDR(cidr string) []string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	if len(ips) > 65536 {
		ips = ips[:65536]
	}
	return ips
}

func expandRange(target string) []string {
	parts := strings.Split(target, "-")
	if len(parts) != 2 {
		return []string{target}
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	endStr := strings.TrimSpace(parts[1])
	if start == nil {
		return []string{target}
	}
	// Handle short form like 192.168.1.1-254
	if !strings.Contains(endStr, ".") {
		base := start.To4()
		if base == nil {
			return []string{target}
		}
		endNum, err := strconv.Atoi(endStr)
		if err != nil || endNum < 0 || endNum > 255 {
			return []string{target}
		}
		var ips []string
		for i := int(base[3]); i <= endNum; i++ {
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i))
		}
		return ips
	}
	end := net.ParseIP(endStr)
	if end == nil {
		return []string{target}
	}
	var ips []string
	for ip := start.To4(); ip != nil && !ip.Equal(end); inc(ip) {
		ips = append(ips, ip.String())
		if len(ips) > 65536 {
			break
		}
	}
	ips = append(ips, end.String())
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParsePorts parses port specification string
func ParsePorts(portStr string) []int {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" || portStr == "top100" {
		return Top100Ports
	}
	if portStr == "top1000" {
		ports := make([]int, 0, 1024)
		for i := 1; i <= 1024; i++ {
			ports = append(ports, i)
		}
		return ports
	}
	if portStr == "all" {
		ports := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			ports[i] = i + 1
		}
		return ports
	}
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			r := strings.Split(part, "-")
			if len(r) == 2 {
				s, _ := strconv.Atoi(strings.TrimSpace(r[0]))
				e, _ := strconv.Atoi(strings.TrimSpace(r[1]))
				for i := s; i <= e && i <= 65535 && i > 0; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
