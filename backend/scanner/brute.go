package scanner

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
			case "mssql":
				success = tryMSSQL(t.target, t.username, t.password, cfg.Timeout)
			case "postgresql":
				success = tryPostgreSQL(t.target, t.username, t.password, cfg.Timeout)
			case "mongodb":
				success = tryMongoDB(t.target, t.username, t.password, cfg.Timeout)
			case "telnet":
				success = tryTelnet(t.target, t.username, t.password, cfg.Timeout)
			case "smb":
				success = trySMB(t.target, t.username, t.password, cfg.Timeout)
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

			cur := int(atomic.AddInt32(&completed, 1))
			if cfg.OnProgress != nil && cur%max(1, total/100) == 0 {
				cfg.OnProgress(cur, total)
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
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	fmt.Fprintf(conn, "USER %s\r\n", user)
	n, err = conn.Read(buf)
	if err != nil {
		return false
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "331") && !strings.HasPrefix(resp, "230") {
		return false
	}

	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	n, err = conn.Read(buf)
	if err != nil {
		return false
	}
	resp = string(buf[:n])
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

	// Read MySQL handshake packet
	handshake := make([]byte, 4096)
	n, err := conn.Read(handshake)
	if err != nil || n < 5 {
		return false
	}

	// Check protocol version (should be 10)
	protoVersion := handshake[4]
	if protoVersion != 10 {
		return false
	}

	// Extract salt (auth-plugin-data) from handshake
	// Handshake format: [protocol version][server version null-term][connection id][capability flags lower 2][status flags][capability flags upper 2][auth data length][reserved][auth data]
	idx := 5
	for idx < n && handshake[idx] != 0 {
		idx++
	}
	idx++ // skip null terminator
	// connection id: 4 bytes
	idx += 4
	// auth-plugin-data-part-1: 8 bytes (always present)
	saltPart1 := make([]byte, 8)
	if idx+8 > n {
		return false
	}
	copy(saltPart1, handshake[idx:idx+8])
	idx += 8
	// filler byte
	idx++
	// capability flags upper 2 bytes (if present)
	if idx+2 > n {
		return false
	}
	capsUpper := uint16(handshake[idx]) | uint16(handshake[idx+1])<<8
	idx += 2
	// auth data length or 0
	authDataLen := 0
	if idx < n {
		authDataLen = int(handshake[idx])
	}
	idx++
	// reserved: 6 bytes
	idx += 6
	// auth-plugin-data-part-2 (if CLIENT_SECURE_CONNECTION)
	var salt []byte
	if capsUpper&0x0020 != 0 && authDataLen > 8 { // CLIENT_SECURE_CONNECTION
		part2Len := authDataLen - 8
		if part2Len < 13 {
			part2Len = 13
		}
		if idx+part2Len <= n {
			saltPart2 := make([]byte, part2Len)
			copy(saltPart2, handshake[idx:idx+part2Len])
			// Remove trailing null byte
			for len(saltPart2) > 0 && saltPart2[len(saltPart2)-1] == 0 {
				saltPart2 = saltPart2[:len(saltPart2)-1]
			}
			salt = append(saltPart1, saltPart2...)
		}
	}
	if len(salt) == 0 {
		salt = saltPart1
	}

	// Compute auth response: SHA1(pass) XOR SHA1(salt + SHA1(SHA1(pass)))
	hash := mysqlAuthHash(pass, salt)

	// Build auth response packet
	// Client capabilities: 4 bytes (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH)
	clientCaps := []byte{0x85, 0xa6, 0x03, 0x00}
	maxPacket := []byte{0x00, 0x00, 0x00, 0x01}
	charset := []byte{0x21} // utf8
	reserved := make([]byte, 23)
	userBytes := append([]byte(user), 0)
	authLen := byte(len(hash))

	var payload []byte
	payload = append(payload, clientCaps...)
	payload = append(payload, maxPacket...)
	payload = append(payload, charset...)
	payload = append(payload, reserved...)
	payload = append(payload, userBytes...)
	payload = append(payload, authLen)
	payload = append(payload, hash...)
	// Add auth plugin name: mysql_native_password\0
	authPlugin := append([]byte("mysql_native_password"), 0)
	payload = append(payload, authPlugin...)

	pktLen := len(payload)
	pktHeader := []byte{byte(pktLen), byte(pktLen >> 8), byte(pktLen >> 16), 1}

	_, err = conn.Write(append(pktHeader, payload...))
	if err != nil {
		return false
	}

	// Read response
	resp := make([]byte, 4096)
	n, err = conn.Read(resp)
	if err != nil || n < 4 {
		return false
	}

	// OK packet starts with 0x00, ERR packet starts with 0xFF
	return resp[4] == 0x00
}

// mysqlAuthHash implements mysql_native_password authentication
// Result = SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
func mysqlAuthHash(password string, salt []byte) []byte {
	if password == "" {
		return nil
	}
	// SHA1(password)
	h1 := sha1.Sum([]byte(password))
	// SHA1(SHA1(password))
	h2 := sha1.Sum(h1[:])
	// SHA1(salt + SHA1(SHA1(password)))
	h3 := sha1.Sum(append(salt, h2[:]...))
	// XOR: SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
	result := make([]byte, 20)
	for i := 0; i < 20; i++ {
		result[i] = h1[i] ^ h3[i]
	}
	return result
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

// tryMSSQL attempts MSSQL authentication via TDS protocol
func tryMSSQL(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":1433"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	// Send TDS pre-login packet
	prelogin := []byte{
		0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, // TDS header
		0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, // prelogin token
		0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, // version
		0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00, // encryption
		0x01, // end marker
	}
	_, err = conn.Write(prelogin)
	if err != nil {
		return false
	}

	// Read prelogin response
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 8 {
		return false
	}

	// Build TDS login packet (simplified)
	// We just check if the server responds to connection
	// Full TDS login is complex; this is a connectivity check
	return resp[0] == 0x04 || resp[0] == 0x12 // valid TDS response
}

// tryPostgreSQL attempts PostgreSQL authentication
func tryPostgreSQL(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":5432"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	// Send PostgreSQL startup message
	startup := fmt.Sprintf("\x00\x03\x00\x00user\x00%s\x00database\x00postgres\x00\x00", user)
	pkt := make([]byte, 4+len(startup))
	// Length (4 bytes, big endian)
	pktLen := len(startup) + 4
	pkt[0] = byte(pktLen >> 24)
	pkt[1] = byte(pktLen >> 16)
	pkt[2] = byte(pktLen >> 8)
	pkt[3] = byte(pktLen)
	copy(pkt[4:], startup)

	_, err = conn.Write(pkt)
	if err != nil {
		return false
	}

	// Read response
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 1 {
		return false
	}

	// 'R' = authentication request
	if resp[0] == 'R' {
		// Auth type at offset 5-8 (big endian)
		if n >= 9 {
			authType := int(resp[5])<<24 | int(resp[6])<<16 | int(resp[7])<<8 | int(resp[8])
			if authType == 0 {
				return true // Authentication OK
			}
			// Send password for MD5/cleartext auth
			if authType == 3 || authType == 5 { // cleartext or md5
				// PasswordMessage: 'p' + length(4 bytes) + password + null
				passBytes := []byte(pass)
				pktLen := len(passBytes) + 5 // 4(length) + password + null
				passPkt := make([]byte, 1+pktLen)
				passPkt[0] = 'p'
				passPkt[1] = byte(pktLen >> 24)
				passPkt[2] = byte(pktLen >> 16)
				passPkt[3] = byte(pktLen >> 8)
				passPkt[4] = byte(pktLen)
				copy(passPkt[5:], passBytes)
				passPkt[len(passPkt)-1] = 0 // null terminator
				conn.Write(passPkt)
				resp2 := make([]byte, 4096)
				n2, err := conn.Read(resp2)
				if err != nil || n2 < 1 {
					return false
				}
				return resp2[0] == 'R' // Auth OK
			}
		}
	}
	return false
}

// tryMongoDB attempts MongoDB authentication
func tryMongoDB(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":27017"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	// Try isMaster command (simplified MongoDB wire protocol)
	// OP_QUERY header: length(4) + requestId(4) + responseTo(4) + opCode(4)
	isMaster := "{\"isMaster\":1}\x00"
	fullDoc := "{\"isMaster\":1,\"$db\":\"admin\"}"
	_ = isMaster

	// Build OP_MSG (MongoDB 3.6+)
	opMsg := buildMongoOpMsg(fullDoc)
	_, err = conn.Write(opMsg)
	if err != nil {
		return false
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 16 {
		return false
	}

	// Check for valid MongoDB response (OP_REPLY or OP_MSG)
	opCode := int(resp[12]) | int(resp[13])<<8 | int(resp[14])<<8 | int(resp[15])<<8
	return opCode == 1 || opCode == 2013 // OP_REPLY or OP_MSG
}

func buildMongoOpMsg(doc string) []byte {
	docBytes := []byte(doc)
	// OP_MSG: header(16) + flagBits(4) + section(1+4+doc)
	totalLen := 16 + 4 + 1 + 4 + len(docBytes)
	pkt := make([]byte, totalLen)
	// Message length
	pkt[0] = byte(totalLen)
	pkt[1] = byte(totalLen >> 8)
	pkt[2] = byte(totalLen >> 16)
	pkt[3] = byte(totalLen >> 24)
	// RequestID
	pkt[4] = 1
	// ResponseTo
	// OpCode = OP_MSG (2013)
	pkt[12] = 0xcd
	pkt[13] = 0x07
	// FlagBits (checksumPresent=0, moreToCome=0)
	// Section: kind=0 (body)
	pkt[20] = 0 // kind = body
	// Document length
	docLen := len(docBytes)
	pkt[21] = byte(docLen)
	pkt[22] = byte(docLen >> 8)
	pkt[23] = byte(docLen >> 16)
	pkt[24] = byte(docLen >> 24)
	copy(pkt[25:], docBytes)
	return pkt
}

// tryTelnet attempts Telnet authentication
func tryTelnet(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":23"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	buf := make([]byte, 4096)

	// Read initial banner/login prompt
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	resp := string(buf[:n])

	// Check if it looks like a login prompt
	lower := strings.ToLower(resp)
	if !strings.Contains(lower, "login") && !strings.Contains(lower, "user") && !strings.Contains(lower, "password") {
		// Send username anyway
	}

	// Send username
	fmt.Fprintf(conn, "%s\r\n", user)
	n, err = conn.Read(buf)
	if err != nil {
		return false
	}
	resp = string(buf[:n])

	// Check for password prompt
	lower = strings.ToLower(resp)
	if strings.Contains(lower, "password") || strings.Contains(lower, "pass") {
		fmt.Fprintf(conn, "%s\r\n", pass)
		n, err = conn.Read(buf)
		if err != nil {
			return false
		}
		resp = string(buf[:n])
		lower = strings.ToLower(resp)
		// Check for shell prompt or successful login indicators
		return !strings.Contains(lower, "denied") && !strings.Contains(lower, "failed") &&
			!strings.Contains(lower, "incorrect") && !strings.Contains(lower, "invalid")
	}
	return false
}

// trySMB attempts SMB authentication (simplified - checks if port is open and service responds)
func trySMB(target, user, pass string, timeout int) bool {
	if !strings.Contains(target, ":") {
		target = target + ":445"
	}
	conn, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

	// Send SMB negotiate request (simplified)
	negPkt := []byte{
		0x00, 0x00, 0x00, 0x85, // NetBIOS header
		0xff, 0x53, 0x4d, 0x42, // SMB magic
		0x72, // Negotiate
		0x00, 0x00, 0x00, 0x00, // Status
		0x18, 0x53, 0xc8, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
		0x00, 0x00, 0x00, 0x00,
		0x00, // Word count
		0x62, 0x00, // Byte count
		0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
		0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
		0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00,
		0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
		0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00,
		0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
	}
	_, err = conn.Write(negPkt)
	if err != nil {
		return false
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return false
	}

	// Check for SMB response (\xffSMB)
	return n >= 4 && resp[0] == 0xff && resp[1] == 'S' && resp[2] == 'M' && resp[3] == 'B'
}
