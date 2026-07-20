//go:build !windows || go1.18
// +build !windows,go1.18

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ============================================================================
// Data Structures
// ============================================================================

type Blob struct {
	Path     string
	Data     []byte
	Size     int64
	Format   FormatType
}

type FormatType uint8

const (
	FormatUnknown FormatType = iota
	FormatPE
	FormatELF
	FormatMachO
	FormatFAT
	FormatRaw
)

type StringEntry struct {
	Offset    int64
	Length    int
	Context   string // 50 chars before/after
	Score     float64 // Context score (higher = more likely to be code/data)
}

type KeyMatch struct {
	Type       string
	Pattern    string
	Value      string
	Offset     int64
	Length     int
	Context    string
	Confidence float64
	Category   CategoryType
}

type CategoryType uint8

const (
	CatUnknown CategoryType = iota
	CatPrivateRSA
	CatPrivateKeyECDSA
	CatAPITokenAWS
	CatAPITokenGCP
	CatAPITokenAzure
	CatAPITokenGitHub
	CatAPITokenSlack
	CatAPITokenDiscord
	CatDefaultCreds
	CatWeakRSA
	CatWeakECC
)

type WeakCryptoInfo struct {
	Type       string
	Offset     int64
	Value      string
	Reason     string
}

// ============================================================================
// Constants and Patterns
// ============================================================================

const (
	StringMinLength = 4
	ContextSize     = 50
	DefaultRSAKeyLen = 2048 // Minimum expected for strong RSA
)

var patterns = map[string]*regexp.Regexp{
	"RSA_PEM_Private": regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s*KEY-----`),
	"ECDSA_PKCS8":    regexp.MustCompile(`-----BEGIN\s+EC\s+PRIVATE\s*KEY-----|-----BEGIN\s+PKCS8\s+ENCRYPTED\s*PRIVATE\s*KEY-----`),
	"AWS_ACCESS_KEY": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"GOOGLE_CLOUD":   regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"GITHUB_TOKEN":   regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}`),
	"SLACK_TOKEN":    regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
	"DISCORD_TOKEN":  regexp.MustCompile(`MT[a-zA-Z0-9_\-]{26}\.[a-zA-Z0-9_\-]{64}`),
	"DEFAULT_PASS":   regexp.MustCompile(`(admin|root|user|test):([a-zA-Z0-9@._\-]+)`),
}

// Common default credentials
var defaultCreds = []struct {
	User, Pass string
}{
	{"admin", "admin"},
	{"root", "root"},
	{"user", "password"},
	{"test", "test123"},
	{"oracle", "oracle"},
}

// ============================================================================
// Blob Parser Core Functions
// ============================================================================

func NewBlob(path string) (*Blob, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	blob := &Blob{
		Path: path,
		Data: data,
		Size: int64(len(data)),
	}

	blob.Format = DetectFormat(blob.Data[:1024]) // Check first 1KB for format detection

	return blob, nil
}

func DetectFormat(header []byte) FormatType {
	if len(header) < 4 {
		return FormatRaw
	}

	// PE header check (MZ signature)
	if bytes.Equal(header[:2], []byte("MZ")) {
		return FormatPE
	}

	// ELF header check
	if bytes.HasPrefix(header, []byte{0x7f, 'E', 'L', 'F'}) {
		return FormatELF
	}

	// Mach-O header check (64-bit)
	if len(header) >= 8 && bytes.Equal(header[0:2], []byte{\x3c, '\xf9'}) {
		return FormatMachO
	}

	// FAT binary check
	if len(header) >= 12 && bytes.Equal(header[:12], []byte("FAT\x00\x00\x00\x00")) {
		return FormatFAT
	}

	return FormatRaw
}

func (b *Blob) ExtractStrings(minLen int) ([]StringEntry, error) {
	var entries []StringEntry
	context := make([]byte, ContextSize*2)

	for offset := 0; offset < len(b.Data); offset++ {
		if b.Data[offset] >= 32 && b.Data[offset] <= 126 { // Printable ASCII
			start := offset - ContextSize
			if start < 0 {
				start = 0
			}

			end := offset + 1
			for end < len(b.Data) && b.Data[end] >= 32 && b.Data[end] <= 126 {
				end++
			}

			length := end - offset
			if length >= minLen {
				entry := StringEntry{
					Offset: int64(offset),
					Length: length,
				}

				// Calculate context score (more printable = higher score)
				contextStart := start
				contextEnd := end
				if contextStart < 0 {
					contextStart = 0
				}
				if contextEnd > len(b.Data) {
					contextEnd = len(b.Data)
				}

				entry.Context = string(b.Data[contextStart:contextEnd])
				entry.Score = float64(contextEnd-contextStart) / ContextSize

				entries = append(entries, entry)
			}
		} else if offset > 0 && b.Data[offset-1] >= 32 && b.Data[offset-1] <= 126 {
			offset-- // Extend previous string
		}
	}

	return entries, nil
}

// ============================================================================
// Pattern Matching Engine
// ============================================================================

func (b *Blob) MatchPatterns() ([]KeyMatch, error) {
	entries, err := b.ExtractStrings(StringMinLength)
	if err != nil {
		return nil, err
	}

	var matches []KeyMatch

	for _, entry := range entries {
		for name, pattern := range patterns {
			matches = append(matches, matchPattern(b, name, pattern, entry)...)
		}

		// Check for default credentials in context
		if strings.Contains(entry.Context, ":") && len(entry.Context) > 10 {
			matches = append(matches, checkDefaultCreds(b, entry)...)
		}
	}

	return matches, nil
}

func matchPattern(blob *Blob, name string, pattern *regexp.Regexp, entry StringEntry) []KeyMatch {
	var results []KeyMatch

	for i := 0; i < len(entry.Context); i++ {
		matches := pattern.FindStringIndex(entry.Context[i:])
		if matches == nil {
			continue
		}

		start := entry.Offset + int64(i) + int64(matches[0])
		value := string(pattern.FindAllString(entry.Context, -1)[0])

		match := KeyMatch{
			Type:       name,
			Pattern:    pattern.String(),
			Value:      value,
			Offset:     start,
			Length:     len(value),
			Context:    entry.Context[i:i+matches[1]-i],
			Confidence: 0.85, // High confidence for exact matches
			Category:   CatUnknown,
		}

		match.Category = categorizeMatch(name)
		results = append(results, match)
	}

	return results
}

func categorizeMatch(patternName string) CategoryType {
	switch patternName {
	case "RSA_PEM_Private":
		return CatPrivateRSA
	case "ECDSA_PKCS8":
		return CatPrivateKeyECDSA
	case "AWS_ACCESS_KEY":
		return CatAPITokenAWS
	case "GOOGLE_CLOUD":
		return CatAPITokenGCP
	case "GITHUB_TOKEN":
		return CatAPITokenGitHub
	case "SLACK_TOKEN":
		return CatAPITokenSlack
	case "DISCORD_TOKEN":
		return CatAPITokenDiscord
	case "DEFAULT_PASS":
		return CatDefaultCreds
	default:
		return CatUnknown
	}
}

func checkDefaultCreds(blob *Blob, entry StringEntry) []KeyMatch {
	var results []KeyMatch

	for _, creds := range defaultCreds {
		if strings.Contains(entry.Context, creds.User+"") && 
		   strings.Contains(entry.Context, creds.Pass+"") {
			start := entry.Offset + int64(strings.Index(entry.Context, creds.User))
			
			match := KeyMatch{
				Type:       "DefaultCredentials",
				Pattern:    fmt.Sprintf("%s:%s", creds.User, creds.Pass),
				Value:      creds.User + ":" + creds.Pass,
				Offset:     start,
				Length:     len(creds.User) + 1 + len(creds.Pass),
				Context:    entry.Context,
				Confidence: 0.95,
				Category:   CatDefaultCreds,
			}

			results = append(results, match)
		}
	}

	return results
}

// ============================================================================
// Binary Key Detection (PEM/DER embedded in blob)
// ============================================================================

func (b *Blob) FindEmbeddedKeys() ([]KeyMatch, error) {
	var matches []KeyMatch

	// Search for PEM headers anywhere in the blob
	pemHeaders := map[string]string{
		"RSA PRIVATE KEY": "CatPrivateRSA",
		"EC PRIVATE KEY":  "CatPrivateKeyECDSA",
	}

	for header, cat := range pemHeaders {
		headerBytes := []byte(header)
		
		for i := 0; i <= len(b.Data)-len(headerBytes); i++ {
			if bytes.Equal(b.Data[i:i+len(headerBytes)], headerBytes) {
				start := int64(i - 100) // Include some context before header
				if start < 0 {
					start = 0
				}

				end := int64(i + len(headerBytes))
				if end > int64(len(b.Data)) {
					end = int64(len(b.Data))
				}

				match := KeyMatch{
					Type:       header,
					Pattern:    fmt.Sprintf("PEM Header: %s", header),
					Value:      string(b.Data[start:end]),
					Offset:     start,
					Length:     int(end - start),
					Context:    string(b.Data[start:end+100]),
					Confidence: 0.95,
					Category:   CatUnknown, // Will be set by caller
				}

				match.Category = categorizeMatch(header)
				matches = append(matches, match)
			}
		}
	}

	return matches, nil
}

// ============================================================================
// Weak Crypto Detection
// ============================================================================

func (b *Blob) CheckWeakCrypto() ([]WeakCryptoInfo, error) {
	var weak []WeakCryptoInfo

	// Extract all printable strings for analysis
	entries, err := b.ExtractStrings(StringMinLength)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		// Check for small RSA primes (weak 512-bit or less)
		if checkWeakRSA(entry.Context) {
			weak = append(weak, WeakCryptoInfo{
				Type:   "WeakRSA",
				Offset: entry.Offset,
				Value:  entry.Context[:min(100, len(entry.Context))],
				Reason: "Potential small RSA modulus detected in string data",
			})
		}

		// Check for default ECC curves with small keys (secp160r1, secp192r1)
		if checkWeakECC(entry.Context) {
			weak = append(weak, WeakCryptoInfo{
				Type:   "WeakECC",
				Offset: entry.Offset,
				Value:  entry.Context[:min(100, len(entry.Context))],
				Reason: "Default ECC curve with small key size detected",
			})
		}

		// Check for weak Diffie-Hellman parameters (512-bit or less)
		if checkWeakDH(entry.Context) {
			weak = append(weak, WeakCryptoInfo{
				Type:   "WeakDH",
				Offset: entry.Offset,
				Value:  entry.Context[:min(100, len(entry.Context))],
				Reason: "Potential weak Diffie-Hellman parameters detected",
			})
		}
	}

	return weak, nil
}

func checkWeakRSA(context string) bool {
	// Look for hex strings that might be small RSA moduli (512 bits = 64 bytes = ~128 hex chars)
	hexPattern := regexp.MustCompile(`0x([0-9a-fA-F]{32,128})`)

	matches := hexPattern.FindAllString(context, -1)
	for _, m := range matches {
		if len(m) >= 64 && len(m) <= 256 { // 32 to 128 bytes
			val, err := fmt.Sprintf("%x", []byte(m[2:])), 0
			if err == nil {
				// Check if it looks like a small RSA modulus (common weak values)
				if len(val) >= 64 && len(val) <= 192 {
					return true
				}
			}
		}
	}

	return false
}

func checkWeakECC(context string) bool {
	// Check for common small ECC curve names or parameters
	eccPatterns := []string{
		"secp160r1", "secp192r1", "secp224r1", // Small curves
		"x9_62_prime192v1", "x9_62_prime239v1",
	}

	for _, curve := range eccPatterns {
		if strings.Contains(context, curve) {
			return true
		}
	}

	return false
}

func checkWeakDH(context string) bool {
	// Check for 512-bit DH primes (common weak values)
	dhPattern := regexp.MustCompile(`0x([0-9a-fA-F]{64,128})`)

	matches := dhPattern.FindAllString(context, -1)
	for _, m := range matches {
		if len(m) >= 128 && len(m) <= 256 { // 64 to 128 bytes = ~128-256 hex chars
			return true
		}
	}

	return false
}

// ============================================================================
// Report Generation
// ============================================================================

type Report struct {
	Blob        *Blob
	Strings     []StringEntry
	Matches     []KeyMatch
	WeakCrypto  []WeakCryptoInfo
	TotalStrings int
}

func (r *Report) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== BLOB PARSER REPORT ===\n"))
	sb.WriteString(fmt.Sprintf("File: %s\n", r.Blob.Path))
	sb.WriteString(fmt.Sprintf("Format: %s\n", formatName(r.Blob.Format)))
	sb.WriteString(fmt.Sprintf("Size: %d bytes\n\n", r.Blob.Size))

	// Summary counts
	sb.WriteString(fmt.Sprintf("Summary:\n"))
	sb.WriteString(fmt.Sprintf("  Total strings extracted: %d\n", len(r.Strings)))
	sb.WriteString(fmt.Sprintf("  Key matches found: %d\n", len(r.Matches)))
	sb.WriteString(fmt.Sprintf("  Weak crypto