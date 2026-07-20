use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, BufReader, Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use regex::{Regex, RegexBuilder};
use rayon::prelude::*;

/// Configuration for the credential scanner.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Maximum file size to scan in bytes (default: 100MB)
    pub max_file_size: u64,
    /// Minimum key length to consider valid (default: 256 bits for RSA)
    pub min_rsa_bits: u32,
    /// Minimum ECC key size (default: 256 bits)
    pub min_ecc_bits: u32,
    /// Threshold for weak RSA modulus (default: 1024 bits)
    pub weak_rsa_threshold: u32,
    /// Threshold for weak ECC curve (default: P-256 is ok, below that warn)
    pub weak_ecc_threshold: u32,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            min_rsa_bits: 256,
            min_ecc_bits: 256,
            weak_rsa_threshold: 1024,
            weak_ecc_threshold: 256,
        }
    }
}

/// A single finding from the scan.
#[derive(Debug, Clone)]
pub struct Finding {
    pub file_path: PathBuf,
    pub category: Category,
    pub severity: Severity,
    pub description: String,
    pub offset: u64,
    pub length: usize,
    pub raw_value: Option<String>,
}

/// Categories of findings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Category {
    HardcodedPassword,
    HardcodedToken,
    HardcodedApiKey,
    HardcodedCertificate,
    WeakRSAKey,
    WeakECCKey,
    DefaultCredentials,
    OtherSecret,
}

/// Severity levels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Category {
    pub fn severity(&self) -> Severity {
        match self {
            Self::HardcodedPassword | Self::WeakRSAKey => Severity::High,
            Self::HardcodedToken | Self::HardcodedApiKey | Self::DefaultCredentials => Severity::Medium,
            Self::HardcodedCertificate | Self::OtherSecret => Severity::Low,
            Self::WeakECCKey => Severity::Medium,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HardcodedPassword => "Potential hardcoded password",
            Self::HardcodedToken => "Potential API token or auth token",
            Self::HardcodedApiKey => "Potential API key",
            Self::HardcodedCertificate => "Embedded certificate/SSL material",
            Self::WeakRSAKey => "Potentially weak RSA key detected",
            Self::WeakECCKey => "Potentially weak ECC curve/key detected",
            Self::DefaultCredentials => "Default or sample credentials found",
            Self::OtherSecret => "Other potential secret material",
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Low => "\x1b[36m", // cyan
            Self::Medium => "\x1b[33m", // yellow
            Self::High => "\x1b[31m", // red
            Self::Critical => "\x1b[35m", // magenta
        }
    }

    pub fn reset(&self) -> &'static str {
        "\x1b[0m"
    }
}

/// Result of scanning a single file.
#[derive(Debug, Default)]
pub struct FileResult {
    pub path: PathBuf,
    pub format: Option<String>,
    pub findings: Vec<Finding>,
    pub scan_duration: Duration,
    pub size_bytes: u64,
}

/// Main scanner state.
#[derive(Default)]
pub struct ScannerState {
    config: ScannerConfig,
    results: Vec<FileResult>,
    total_files: usize,
    bytes_scanned: u64,
    findings_by_category: HashMap<Category, usize>,
    start_time: Instant,
}

impl ScannerState {
    pub fn new(config: impl Into<ScannerConfig>) -> Self {
        let config = config.into();
        Self {
            config,
            results: Vec::new(),
            total_files: 0,
            bytes_scanned: 0,
            findings_by_category: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    pub fn add_file_result(&mut self, result: FileResult) {
        self.results.push(result);
        self.total_files += 1;
        self.bytes_scanned += result.size_bytes;

        for finding in &result.findings {
            let cat = finding.category;
            *self.findings_by_category.entry(cat).or_insert(0) += 1;
        }
    }

    pub fn get_summary(&self) -> Summary {
        Summary::new(self, self.start_time.elapsed())
    }
}

/// Summary of the entire scan.
#[derive(Debug)]
pub struct Summary {
    pub total_files: usize,
    pub bytes_scanned: u64,
    pub total_findings: usize,
    pub duration: Duration,
    pub findings_by_category: HashMap<Category, usize>,
}

impl Summary {
    pub fn new(state: &ScannerState, elapsed: Duration) -> Self {
        let mut totals = HashMap::new();
        for cat in Category::iter() {
            *totals.entry(cat).or_insert(0) += state.findings_by_category.get(&cat).copied().unwrap_or(0);
        }

        Self {
            total_files: state.total_files,
            bytes_scanned: state.bytes_scanned,
            total_findings: totals.values().sum(),
            duration: elapsed,
            findings_by_category: totals,
        }
    }
}

impl Category {
    pub fn iter() -> impl Iterator<Item = Self> {
        [
            Self::HardcodedPassword,
            Self::HardcodedToken,
            Self::HardcodedApiKey,
            Self::HardcodedCertificate,
            Self::WeakRSAKey,
            Self::WeakECCKey,
            Self::DefaultCredentials,
            Self::OtherSecret,
        ].iter().copied()
    }
}

/// Compile-time regex patterns for common secret formats.
pub mod patterns {
    use std::str::FromStr;
    use regex::RegexBuilder;

    /// Common password patterns (weak or default)
    pub static PASSWORD_PATTERNS: &[&'static str] = &[
        // Default/obvious passwords
        r"(?i)(password|passwd|pwd)\s*[:=]\s*(admin|root|123456|qwerty|letmein|passw0rd)",
        // Common weak patterns
        r"(?i)^(123456|12345678|password|admin|welcome|master|dragon|monkey|shadow|princess|football|iloveyou)$",
        // Pattern with common suffixes
        r"(?i)(user|guest)\s*[:=]\s*(pass|word|1234)",
    ];

    /// API token patterns (Stripe, Twilio, GitHub, etc.)
    pub static TOKEN_PATTERNS: &[&'static str] = &[
        // Stripe keys
        r"(?i)(sk_live_|rk_live_|sk_test_|rk_test_)[a-zA-Z0-9]{24}",
        // GitHub PAT
        r"(?i)ghp_[a-zA-Z0-9]{36}",
        // Generic JWT patterns (careful with false positives)
        r"(?i)(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
        // Generic API key
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}",
    ];

    /// RSA public modulus (n) - 64 to 128 hex chars for typical sizes
    pub static RSA_MODULUS_PATTERN: &str = r"(?i)(?:0x)?([0-9a-fA-F]{64,128})";

    /// ECC private key format (hex encoded)
    pub static ECC_KEY_PATTERN: &str = r"(?i)(?:-----BEGIN EC PRIVATE KEY-----|-----BEGIN PRIVATE KEY-----)[\s\S]*?(?:-----END EC PRIVATE KEY----|-----END PRIVATE KEY-----)"
        .to_string();

    /// PEM certificate pattern (often contains embedded keys)
    pub static CERT_PATTERN: &str = r"(?i)(?:-----BEGIN CERTIFICATE-----|-----BEGIN RSA PUBLIC KEY-----)[\s\S]*?(?:-----END CERTIFICATE----|-----END RSA PUBLIC KEY-----)"
        .to_string();

    /// Default credential pairs
    pub static DEFAULT_CREDS_PATTERNS: &[&'static str] = &[
        r"(?i)(root|admin)\s*[:=]\s*(password|pass)",
        r"(?i)user\s*:\s*guest",
        r"(?i)default_user\s*=\s*default_pass",
    ];

    /// Build compiled regexes at runtime for performance.
    pub fn build_compiled() -> CompiledPatterns {
        let mut compiled = CompiledPatterns::default();

        // Password patterns
        for pattern in PASSWORD_PATTERNS {
            if let Ok(r) = RegexBuilder::new(*pattern).case_insensitive(true).build() {
                compiled.passwords.push(r);
            }
        }

        // Token patterns
        for pattern in TOKEN_PATTERNS {
            if let Ok(r) = RegexBuilder::new(*pattern).case_insensitive(true).build() {
                compiled.tokens.push(r);
            }
        }

        // Default credentials
        for pattern in DEFAULT_CREDS_PATTERNS {
            if let Ok(r) = RegexBuilder::new(*pattern).case_insensitive(true).build() {
                compiled.defaults.push(r);
            }
        }

        // RSA modulus (compile once, reused)
        if let Ok(r) = RegexBuilder::new(RSA_MODULUS_PATTERN).case_insensitive(true).multi_line(true).build() {
            compiled.rsa_modulus = Some(r);
        }

        compiled
    }
}

/// Runtime-compiled regex patterns.
#[derive(Default)]
pub struct CompiledPatterns {
    passwords: Vec<Regex>,
    tokens: Vec<Regex>,
    defaults: Vec<Regex>,
    rsa_modulus: Option<Regex>,
}

impl CompiledPatterns {
    pub fn search_text(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Search passwords
        for regex in &self.passwords {
            if let Some(m) = regex.find(text) {
                findings.push(Finding {
                    file_path: PathBuf::from("text"),
                    category: Category::HardcodedPassword,
                    severity: Severity::High,
                    description: format!("Weak password pattern: {}", m.as_str()),
                    offset: m.start() as u64,
                    length: m.len(),
                    raw_value: Some(m.as_str().to_string()),
                });
            }
        }

        // Search tokens
        for regex in &self.tokens {
            if let Some(m) = regex.find(text) {
                findings.push(Finding {
                    file_path: PathBuf::from("text"),
                    category: Category::HardcodedToken,
                    severity: Severity::Medium,
                    description: format!("Potential token pattern: {}", m.as_str()),
                    offset: m.start() as u64,
                    length: m.len(),
                    raw_value: Some(m.as_str().to_string()),
                });
            }
        }

        // Search default credentials
        for regex in &self.defaults {
            if let Some(m) = regex.find(text) {
                findings.push(Finding {
                    file_path: PathBuf::from("text"),
                    category: Category::DefaultCredentials,
                    severity: Severity::Medium,
                    description: format!("Potential default credential pattern: {}", m.as_str()),
                    offset: m.start() as u64,
                    length: m.len(),
                    raw_value: Some(m.as_str().to_string()),
                });
            }
        }

        findings
    }

    pub fn extract_rsa_moduli(&self, data: &[u8]) -> Vec<Finding> {
        if let Some(re) = &self.rsa_modulus {
            // Convert to string for regex matching
            let text = String::from_utf8_lossy(data);
            
            if let Some(m) = re.find(&text) {
                let hex_val = m.as_str();
                
                // Check if it's a reasonable RSA modulus size
                let bits = (hex_val.len() / 2) * 4;
                
                if bits >= self.config.min_rsa_bits as usize && bits <= 1024 {
                    return vec![Finding {
                        file_path: PathBuf::from("binary"),
                        category: Category::WeakRSAKey,
                        severity: Severity::High,
                        description: format!("Potential RSA modulus ({} bits): {}", bits, hex_val),
                        offset: m.start() as u64,
                        length: m.len(),
                        raw_value: Some(hex_val.to_string()),
                    }];
                }
            }
        }
        
        Vec::new()
    }

    pub fn extract_ecc_keys(&self, data: &[u8]) -> Vec<Finding> {
        let text = String::from_utf8_lossy(data);
        
        // Look for PEM blocks
        if let Some(start) = text.find("-----BEGIN EC PRIVATE KEY-----") 
            || text.find("-----BEGIN PRIVATE KEY-----") {
            
            let end_marker = if start.contains("EC") {
                "-----END EC PRIVATE KEY----"
            } else {
                "-----END PRIVATE KEY-----"
            };
            
            if let Some(end) = text[start..].find(end_marker) {
                let pem_block = &text[start..start + end + end_marker.len()];
                
                // Extract the actual key content (remove headers/footers and whitespace)
                let clean: String = pem_block.lines().filter(|l| !l.starts_with("-----")).collect();
                
                if !clean.is_empty() {
                    return vec![Finding {
                        file_path: PathBuf::from("binary"),
                        category: Category::HardcodedCertificate,
                        severity: Severity::Low,
                        description: format!("Potential ECC private key found ({} bytes)", clean.len()),
                        offset: start as u64,
                        length: pem_block.len(),
                        raw_value: Some(clean),
                    }];
                }
            }
        }

        Vec::new()
    }
}

/// File format detection.
pub mod formats {
    use std::io::{Read, Seek};

    /// Detect file format from magic bytes.
    pub fn detect_format(data: &[u8]) -> Option<String> {
        if data.len() < 16 {
            return None;
        }

        // PE (Windows executable)
        if &data[0..2] == b"MZ" || &data[0..4] == b"\x7f\x45\x4c\x46" {
            return Some("PE/ELF".to_string());
        }

        // ELF
        if data.len() >= 16 && &data[0..16][..2] == b"\x7f\x45\x4c" {
            let elf_class = u8::from(data[4]);
            let elf_endian = u8::from(data[5]);
            
            if elf_class == 1 || elf_class == 2 { // 32-bit or 64-bit
                return Some(format!("ELF ({}-bit, {})", 
                    match elf_class { 1 => "32", 2 => "64", _ => "unknown" },
                    if elf_endian == 1 { "little-endian" } else { "big-endian" }
                );
            }
        }

        // Mach-O (macOS)
        if data.len() >= 8 && (&data[0..2] == b"\xfe\xef" || &data[0..4] == b"\xca\xfe\xba\xbe") {
            return Some("Mach-O".to_string());
        }

        // FAT binary (universal)
        if data.len() >= 16 && (&data[0..2] == b"FAT" || &data[0..4] == b"\xca\xfe\xba\xbe") {
            return Some("FAT".to_string());