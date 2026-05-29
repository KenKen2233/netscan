package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/url"
	"strings"
)

// EncodeResult represents encoding result
type EncodeResult struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Type   string `json:"type"`
}

// Base64Encode encodes string to base64
func Base64Encode(input string) EncodeResult {
	return EncodeResult{Input: input, Output: base64.StdEncoding.EncodeToString([]byte(input)), Type: "base64_encode"}
}

// Base64Decode decodes base64 string
func Base64Decode(input string) EncodeResult {
	output, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return EncodeResult{Input: input, Output: "Error: " + err.Error(), Type: "base64_decode"}
	}
	return EncodeResult{Input: input, Output: string(output), Type: "base64_decode"}
}

// URLEncode encodes string to URL encoding
func URLEncode(input string) EncodeResult {
	return EncodeResult{Input: input, Output: url.QueryEscape(input), Type: "url_encode"}
}

// URLDecode decodes URL encoded string
func URLDecode(input string) EncodeResult {
	output, err := url.QueryUnescape(input)
	if err != nil {
		return EncodeResult{Input: input, Output: "Error: " + err.Error(), Type: "url_decode"}
	}
	return EncodeResult{Input: input, Output: output, Type: "url_decode"}
}

// HexEncode encodes string to hex
func HexEncode(input string) EncodeResult {
	return EncodeResult{Input: input, Output: hex.EncodeToString([]byte(input)), Type: "hex_encode"}
}

// HexDecode decodes hex string
func HexDecode(input string) EncodeResult {
	output, err := hex.DecodeString(input)
	if err != nil {
		return EncodeResult{Input: input, Output: "Error: " + err.Error(), Type: "hex_decode"}
	}
	return EncodeResult{Input: input, Output: string(output), Type: "hex_decode"}
}

// HTMLEncode encodes string to HTML entities
func HTMLEncode(input string) EncodeResult {
	return EncodeResult{Input: input, Output: html.EscapeString(input), Type: "html_encode"}
}

// HTMLDecode decodes HTML entities
func HTMLDecode(input string) EncodeResult {
	return EncodeResult{Input: input, Output: html.UnescapeString(input), Type: "html_decode"}
}

// UnicodeEncode encodes string to Unicode
func UnicodeEncode(input string) EncodeResult {
	var sb strings.Builder
	for _, r := range input {
		sb.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return EncodeResult{Input: input, Output: sb.String(), Type: "unicode_encode"}
}

// UnicodeDecode decodes Unicode string
func UnicodeDecode(input string) EncodeResult {
	var sb strings.Builder
	for i := 0; i < len(input); i++ {
		if i+5 < len(input) && input[i:i+2] == "\\u" {
			var r rune
			fmt.Sscanf(input[i+2:i+6], "%x", &r)
			sb.WriteRune(r)
			i += 5
		} else {
			sb.WriteByte(input[i])
		}
	}
	return EncodeResult{Input: input, Output: sb.String(), Type: "unicode_decode"}
}

// Base32Encode encodes string to base32
func Base32Encode(input string) EncodeResult {
	return EncodeResult{Input: input, Output: base32.StdEncoding.EncodeToString([]byte(input)), Type: "base32_encode"}
}

// Base32Decode decodes base32 string
func Base32Decode(input string) EncodeResult {
	output, err := base32.StdEncoding.DecodeString(strings.ToUpper(input))
	if err != nil {
		return EncodeResult{Input: input, Output: "Error: " + err.Error(), Type: "base32_decode"}
	}
	return EncodeResult{Input: input, Output: string(output), Type: "base32_decode"}
}

// HashResult represents hash result
type HashResult struct {
	Input  string `json:"input"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

// Hash calculates various hashes of input
func Hash(input string) HashResult {
	md5Hash := md5.Sum([]byte(input))
	sha1Hash := sha1.Sum([]byte(input))
	sha256Hash := sha256.Sum256([]byte(input))
	sha512Hash := sha512.Sum512([]byte(input))

	return HashResult{
		Input:  input,
		MD5:    hex.EncodeToString(md5Hash[:]),
		SHA1:   hex.EncodeToString(sha1Hash[:]),
		SHA256: hex.EncodeToString(sha256Hash[:]),
		SHA512: hex.EncodeToString(sha512Hash[:]),
	}
}

// AESEncrypt encrypts data with AES
func AESEncrypt(plaintext, key string) (string, error) {
	block, err := aes.NewCipher([]byte(padKey(key, 32)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AESDecrypt decrypts AES encrypted data
func AESDecrypt(ciphertext, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(padKey(key, 32)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DESEncrypt encrypts data with DES
func DESEncrypt(plaintext, key string) (string, error) {
	block, err := des.NewCipher([]byte(padKey(key, 8)))
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	src := pkcs5Pad([]byte(plaintext), bs)
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		block.Encrypt(dst[i:i+bs], src[i:i+bs])
	}
	return hex.EncodeToString(dst), nil
}

// DESDecrypt decrypts DES encrypted data
func DESDecrypt(ciphertext, key string) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := des.NewCipher([]byte(padKey(key, 8)))
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	dst := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(dst[i:i+bs], data[i:i+bs])
	}
	return string(pkcs5Unpad(dst)), nil
}

// padKey pads or truncates key to the required size
// Uses SHA256 hash of key for padding instead of zeros for better security
func padKey(key string, size int) string {
	if len(key) >= size {
		return key[:size]
	}
	// Use repeated key hash for padding
	hash := sha256.Sum256([]byte(key))
	padded := key
	for len(padded) < size {
		padded += hex.EncodeToString(hash[:])
	}
	return padded[:size]
}

func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func pkcs5Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

// FormatJSON formats JSON string
func FormatJSON(input string) (string, error) {
	var obj interface{}
	if err := json.Unmarshal([]byte(input), &obj); err != nil {
		return "", err
	}
	output, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// CompressJSON compresses JSON string
func CompressJSON(input string) (string, error) {
	var obj interface{}
	if err := json.Unmarshal([]byte(input), &obj); err != nil {
		return "", err
	}
	output, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// IPInfo represents IP/CIDR calculation result
type IPInfo struct {
	IP          string `json:"ip"`
	Network     string `json:"network"`
	Broadcast   string `json:"broadcast"`
	SubnetMask  string `json:"subnet_mask"`
	HostMin     string `json:"host_min"`
	HostMax     string `json:"host_max"`
	TotalHosts  int    `json:"total_hosts"`
	UsableHosts int    `json:"usable_hosts"`
	CIDR        string `json:"cidr"`
}

// CalculateCIDR calculates IP/CIDR information
func CalculateCIDR(cidr string) (IPInfo, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPInfo{}, err
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()

	totalHosts := 1 << (bits - ones)
	usableHosts := totalHosts - 2
	if usableHosts < 0 {
		usableHosts = 0
	}

	// Network address
	network := ipNet.IP.Mask(mask)

	// Broadcast address
	broadcast := make(net.IP, len(network))
	for i := range broadcast {
		broadcast[i] = network[i] | ^mask[i]
	}

	// Host min/max
	hostMin := make(net.IP, len(network))
	copy(hostMin, network)
	hostMin[len(hostMin)-1]++

	hostMax := make(net.IP, len(broadcast))
	copy(hostMax, broadcast)
	hostMax[len(hostMax)-1]--

	return IPInfo{
		IP:          ip.String(),
		Network:     network.String(),
		Broadcast:   broadcast.String(),
		SubnetMask:  net.IP(mask).String(),
		HostMin:     hostMin.String(),
		HostMax:     hostMax.String(),
		TotalHosts:  totalHosts,
		UsableHosts: usableHosts,
		CIDR:        fmt.Sprintf("%s/%d", ip.String(), ones),
	}, nil
}

// JWTClaims represents JWT claims
type JWTClaims struct {
	Header    string `json:"header"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// ParseJWT parses a JWT token
func ParseJWT(token string) (JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWTClaims{}, fmt.Errorf("invalid JWT format")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWTClaims{}, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return JWTClaims{}, err
	}

	var headerMap map[string]interface{}
	json.Unmarshal(header, &headerMap)
	alg := ""
	if a, ok := headerMap["alg"]; ok {
		alg = fmt.Sprintf("%v", a)
	}

	return JWTClaims{
		Header:    string(header),
		Payload:   string(payload),
		Signature: parts[2],
		Algorithm: alg,
	}, nil
}
