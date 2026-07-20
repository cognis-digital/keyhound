package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Config holds scanner settings
type Config struct {
	MinRSASize    int // Minimum RSA key size to flag as weak (bits)
	MinECDSACurve string // Curve name for weak ECDSA detection
}

func DefaultConfig() *Config {
	return &Config{
		MinRSASize: 1024,
		MinECDSACurve: "prime192v1",
	}
}

// Patterns defines regex patterns for credential detection
type Patterns struct {
	SSHPrivateKeys    []*regexp.Regexp
	SSLCertificates   []*regexp.Regexp
	GPGKeys           []*regexp.Regexp
	PGPKeys           []*regexp.Regexp
	APITokens         map[string]*regexp.Regexp
	DefaultCredentials map[string][]*regexp.Regexp
}

func DefaultPatterns() *Patterns {
	p := &Patterns{
		APITokens: make(map[string]*regexp.Regexp),
		DefaultCredentials: make(map[string][]*regexp.Regexp),
	}

	// SSH Private Keys (PEM format)
	p.SSHPrivateKeys = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	}

	// SSL/TLS Certificates (PEM format)
	p.SSLCertificates = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
		regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`),
	}

	// GPG Keys (PEM format)
	p.GPGKeys = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		regexp.MustCompile(`-----BEGIN PGP PUBLIC KEY BLOCK-----`),
	}

	// PGP Keys (PEM format)
	p.PGPKeys = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN PGP SIGNATURE-----`),
	}

	// API Tokens - GitHub
	p.APITokens["github"] = []*regexp.Regexp{
		regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`ghu_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),
		regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`),
	}

	// API Tokens - AWS
	p.APITokens["aws"] = []*regexp.Regexp{
		regexp.MustCompile(`AKIA[0-9A-Z]{14}`),
		regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
		regexp.MustCompile(`A3T[0-9A-Z]{14}`),
	}

	// API Tokens - Google Cloud
	p.APITokens["google"] = []*regexp.Regexp{
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		regexp.MustCompile(`gcp_[a-zA-Z0-9]{24,36}`),
	}

	// API Tokens - Slack
	p.APITokens["slack"] = []*regexp.Regexp{
		regexp.MustCompile(`xoxb-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}`),
		regexp.MustCompile(`xoxp-[0-9]{8}-[0-9]{8}-[0-9]{8}-[a-zA-Z0-9]{24}`),
	}

	// API Tokens - Stripe
	p.APITokens["stripe"] = []*regexp.Regexp{
		regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,36}`),
		regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,36}`),
	}

	// Default Credentials - Common usernames/passwords
	p.DefaultCredentials["username"] = []*regexp.Regexp{
		regexp.MustCompile(`user:password`),
		regexp.MustCompile(`admin:admin`),
		regexp.MustCompile(`root:toor`),
		regexp.MustCompile(`test:test`),
	}

	// Default Credentials - Common password patterns
	p.DefaultCredentials["password"] = []*regexp.Regexp{
		regexp.MustCompile(`password=.*?['"][a-zA-Z0-9]{8,16}['"]`),
		regexp.MustCompile(`pwd:.*?[a-zA-Z0-9]{8,16}`),
	}

	return p
}

// Result represents a single finding
type Result struct {
	File     string
	Type     string
	Pattern  string
	Value    string
	Context  string
	LineNum  int
	Offset   int
}

// Scanner holds the state of an ongoing scan
type Scanner struct {
	config      *Config
	patterns    *Patterns
	results     []Result
	currentFile string
	fileSize    int64
	lineNum     int
	offset      int64
}

func NewScanner(cfg *Config, pat *Patterns) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if pat == nil {
		pat = DefaultPatterns()
	}
	return &Scanner{
		config:  cfg,
		patterns: pat,
		results: make([]Result, 0),
	}
}

// scanFile scans a single file for credentials
func (s *Scanner) scanFile(path string) error {
	s.currentFile = path
	s.fileSize = -1
	s.lineNum = 0
	s.offset = 0

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err == nil {
		s.fileSize = info.Size()
	}

	// For large files, read in chunks
	chunkSize := int64(8192)
	buf := make([]byte, chunkSize)

	for s.offset < s.fileSize {
		n, err := file.Read(buf)
		if n > 0 {
			s.offset += int64(n)
			s.scanChunk(string(buf[:n]))
		}
		if err != nil && err != io.EOF {
			return fmt.Errorf("read chunk: %w", err)
		}
	}

	return nil
}

// scanChunk processes a text chunk for patterns
func (s *Scanner) scanChunk(chunk string) {
	lines := strings.Split(chunk, "\n")

	for _, line := range lines {
		s.lineNum++
		
		// Check SSH private keys
		if s.matchPattern(s.patterns.SSHPrivateKeys, line) {
			s.addResult("SSH Private Key", "PEM Header", line[:min(100, len(line))], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
		}

		// Check SSL certificates
		if s.matchPattern(s.patterns.SSLCertificates, line) {
			s.addResult("SSL Certificate", "PEM Header", line[:min(100, len(line))], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
		}

		// Check GPG/PGP keys
		if s.matchPattern(s.patterns.GPGKeys, line) || s.matchPattern(s.patterns.PGPKeys, line) {
			s.addResult("GPG/PGP Key", "PEM Header", line[:min(100, len(line))], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
		}

		// Check API tokens
		for service, patterns := range s.patterns.APITokens {
			for _, pattern := range patterns {
				if matches := pattern.FindStringIndex(line); matches != nil {
					s.addResult(service+" Token", "API Key", matches[0], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
				}
			}
		}

		// Check default credentials
		for category, patterns := range s.patterns.DefaultCredentials {
			for _, pattern := range patterns {
				if matches := pattern.FindStringIndex(line); matches != nil {
					s.addResult(category+" Credential", "Default Pattern", matches[0], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
				}
			}
		}

		// Check for weak RSA key sizes in PEM content
		if s.checkWeakRSA(line) {
			s.addResult("Weak RSA Key", "RSA Size", line[:min(100, len(line))], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
		}

		// Check for weak ECDSA curves in PEM content
		if s.checkWeakECDSA(line) {
			s.addResult("Weak ECDSA Key", "Curve Name", line[:min(100, len(line))], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
		}

		// Check for common password patterns
		if s.checkCommonPasswords(line) {
			s.addResult("Potential Password", "Password Pattern", matches[0], chunk, s.lineNum, s.offset-chunkSize*int64(len(lines)-s.lineNum))
		}
	}
}

// matchPattern checks if any pattern in the slice matches the line
func (s *Scanner) matchPattern(patterns []*regexp.Regexp, line string) bool {
	for _, p := range patterns {
		if p.MatchString(line) {
			return true
		}
	}
	return false
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// addResult adds a finding to results
func (s *Scanner) addResult(t, p, v, c string, l, o int64) {
	s.results = append(s.results, Result{
		File:     s.currentFile,
		Type:     t,
		Pattern:  p,
		Value:    v,
		Context:  c,
		LineNum:  int(l),
		Offset:   int(o),
	})
}

// checkWeakRSA extracts and validates RSA key size from PEM content
func (s *Scanner) checkWeakRSA(line string) bool {
	// Look for common RSA header patterns in the line
	if !strings.Contains(strings.ToLower(line), "rsa") && 
	   !strings.Contains(strings.ToLower(line), "private") {
		return false
	}

	// Try to extract key size from PEM block metadata
	matches := regexp.MustCompile(`RSA.*?(\d{3,4})`).FindStringSubmatch(line)
	if len(matches) >= 2 {
		size, err := strconv.Atoi(matches[1])
		if err == nil && size < s.config.MinRSASize {
			return true
		}
	}

	// Check for explicit size mentions
	matches = regexp.MustCompile(`(\d{3,4})\s*bit`).FindStringSubmatch(line)
	if len(matches) >= 2 {
		size, err := strconv.Atoi(matches[1])
		if err == nil && size < s.config.MinRSASize {
			return true
		}
	}

	return false
}

// checkWeakECDSA extracts and validates ECDSA curve from PEM content
func (s *Scanner) checkWeakECDSA(line string) bool {
	if !strings.Contains(strings.ToLower(line), "ec") && 
	   !strings.Contains(strings.ToLower(line), "curve") {
		return false
	}

	matches := regexp.MustCompile(`(\w+)?v1`).FindStringSubmatch(line)
	if len(matches) >= 2 {
		curve := matches[1]
		if curve == "" || strings.HasPrefix(curve, "prime") {
			// Check if it's a weak curve
			weakCurves := map[string]bool{
				"prime192v1": true,
				"secp192r1":  true,
				"prime239v1": true,
				"secp239r1":  true,
			}
			if weakCurves[curve] {
				return true
			}
		}
	}

	return false
}

// checkCommonPasswords looks for common password patterns
func (s *Scanner) checkCommonPasswords(line string) bool {
	// Common short passwords
	shortPass := regexp.MustCompile(`['"]([a-zA-Z0-9]{8,12})['"]`)
	matches := shortPass.FindStringSubmatch(line)
	if len(matches) >= 2 {
		pass := matches[1]
		commonPasswords := map[string]bool{
			"password": true, "admin": true, "root": true, "guest": true,
			"welcome": true, "hello": true, "test": true, "demo": true,
		}
		if commonPasswords[pass] {
			return true
		}
	}

	// Check for sequential patterns
	seqPattern := regexp.MustCompile(`([a-zA-Z0-9]{4})\1+`)
	matches = seqPattern.FindStringSubmatch(line)
	if len(matches) >= 2 {
		seq := matches[1]
		if strings.Contains("123456789", seq[:min(9, len(seq))] + "0") ||
		   strings.Contains("qwertyuiop", seq[:min(10, len(seq))] + "a") {
			return true
		}
	}

	return false
}

// scanDirectory recursively scans a directory
func (s *Scanner) scanDirectory(path string) error {
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", filePath, err)
		}

		// Skip directories and very large files
		if info.IsDir() || info.Size() > 10*1024*1024 { // 10MB limit per file
			return nil
		}

		// Skip binary files by checking magic bytes
		if s.isBinaryFile(filePath) {
			return nil
		}

		return s.scanFile(filePath)
	})

	return err
}

// isBinaryFile checks if a file appears to be binary
func (s *Scanner) isBinaryFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	
	// Check for null bytes in first 512 bytes
	nullCount := bytes.Count(buf[:n], []byte{0})
	if float64(nullCount)/float64(n) > 0.3 {
		return true
	}

	// Check magic bytes for common binary formats
	magicBytes := map[string]bool{
		"PK\x03\x04": true, // ZIP
		"\x1f\x8b":     true, // GZIP
		"GIF87a":       true, // GIF
		"GIF89a":       true, // GIF
	}

	for _, magic := range magicBytes {
		if bytes.HasPrefix(buf[:n], []byte(magic)) {
			return true
		}
	}

	return false
}

// scanBlob scans a memory buffer (for embedded blobs)
func (s *Scanner) scanBlob(data []byte, name string) error {
	s.currentFile = name
	s.fileSize = int64(len(data))
	s.lineNum = 0
	s.offset = 0

	chunk := string(data[:min(8192, len(data))])
	s.scanChunk(chunk)

	if s.fileSize > 8192 {
		for offset := 8192; offset < s.fileSize; offset += 8192 {
			end := min(offset+8192, s.fileSize)
			chunk = string(data[offset:end])
			s.lineNum = 0 // Reset for new chunk context
			s.scanChunk(chunk)
		}
	}

	return nil
}

// scanBlobs scans multiple memory buffers
func (s *Scanner) scanBlobs(blobs map[string][]byte) error {
	for name, data := range blobs {
		if err := s.scanBlob(data, name); err != nil {
			return fmt.Errorf("scan blob %s: %w", name, err)
		}
	}
	return nil
}

// writePEMBlock