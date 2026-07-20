use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Magic numbers for common firmware and filesystem formats.
const MAGIC: &[(&[u8], &str)] = &[
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
    (b"PE\x00\x00", "PE32+"),
    (b"\x00\x00\x00\x00\x01\x00\x00\x00", "FAT32"),
    (b"PK\x03\x04", "ZIP/PE archive"),
    (b"GZ", "Gzip"),
    (b"\x1f\x8b", "Gzip compressed"),
    (b"BZ", "Bzip2"),
    (b"XZ", "XZ compression"),
];

/// Configuration for the blob parser.
#[derive(Debug, Clone)]
pub struct BlobParserConfig {
    /// Minimum string length to consider as a potential secret.
    pub min_string_length: usize,
    /// Maximum strings to extract per blob (for performance).
    pub max_strings_per_blob: usize,
    /// Whether to perform magic number detection.
    pub detect_magic: bool,
    /// Custom regex patterns for secrets (default includes common ones).
    pub secret_patterns: Vec<regex::Regex>,
}

impl Default for BlobParserConfig {
    fn default() -> Self {
        let mut patterns = vec![
            // RSA private keys
            regex::Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            regex::Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),
            regex::Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
            regex::Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            
            // API tokens and keys
            regex::Regex::new(r"(?i)api[_-]?key[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?").unwrap(),
            regex::Regex::new(r"bearer\s+['\"]?[a-zA-Z0-9_\-\.]+['\"]?").unwrap(),
            
            // Common password patterns
            regex::Regex::new(r"(?i)(password|passwd|pwd)[:=]\s*['\"]?[^\s'\"]{4,}['\"]?").unwrap(),
            regex::Regex::new(r"admin[:=]\s*['\"]?[a-zA-Z0-9_\-]{4,}['\"]?").unwrap(),
            
            // Default credentials
            regex::Regex::new(r"(default|factory|reset)[:=]\s*['\"]?[^\s'\"]{3,}['\"]?").unwrap(),
        ];
        
        Self {
            min_string_length: 8,
            max_strings_per_blob: 10_000,
            detect_magic: true,
            secret_patterns: patterns,
        }
    }
}

/// Result of parsing a single blob.
#[derive(Debug)]
pub struct BlobParseResult {
    /// Detected file format (if magic detection was enabled).
    pub format: Option<String>,
    /// Extracted strings that might contain secrets.
    pub potential_secrets: Vec<PotentialSecret>,
    /// Metadata about the blob.
    pub metadata: BlobMetadata,
}

/// A single potential secret found in a blob.
#[derive(Debug)]
pub struct PotentialSecret {
    /// The extracted string content.
    pub content: String,
    /// Offset within the original blob where it was found.
    pub offset: u64,
    /// Detected pattern type (if any).
    pub pattern_type: Option<PatternType>,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f32,
}

/// Type of detected secret pattern.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatternType {
    RsaKey,
    EcdhKey,
    OpensshKey,
    PgpKey,
    ApiToken,
    BearerToken,
    Password,
    DefaultCreds,
    Unknown,
}

/// Metadata extracted from a blob.
#[derive(Debug)]
pub struct BlobMetadata {
    /// Size of the blob in bytes.
    pub size: u64,
    /// Detected format (if applicable).
    pub format: Option<String>,
    /// Number of strings extracted.
    pub string_count: usize,
}

/// Main blob parser implementation.
pub struct BlobParser {
    config: BlobParserConfig,
}

impl BlobParser {
    /// Create a new parser with default configuration.
    pub fn new() -> Self {
        Self::with_config(BlobParserConfig::default())
    }
    
    /// Create a new parser with custom configuration.
    pub fn with_config(config: BlobParserConfig) -> Self {
        Self { config }
    }
    
    /// Parse a blob from a file path.
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> io::Result<BlobParseResult> {
        let mut metadata = BlobMetadata {
            size: 0,
            format: None,
            string_count: 0,
        };
        
        // Detect file format using magic numbers
        if self.config.detect_magic {
            if let Some(format) = Self::detect_format(&path.as_ref()) {
                metadata.format = Some(format.to_string());
            }
        }
        
        // Read the blob content
        let mut buffer = Vec::new();
        fs::read(path)?;
        metadata.size = buffer.len() as u64;
        
        if buffer.is_empty() {
            return Ok(BlobParseResult {
                format: metadata.format,
                potential_secrets: vec![],
                metadata,
            });
        }
        
        // Extract strings from the blob
        let strings = Self::extract_strings(&buffer);
        metadata.string_count = strings.len();
        
        // Filter and categorize potential secrets
        let mut potential_secrets = Vec::new();
        for (offset, content) in strings.iter().enumerate() {
            if content.len() < self.config.min_string_length {
                continue;
            }
            
            if offset >= self.config.max_strings_per_blob {
                break;
            }
            
            // Check against known patterns
            let pattern_type = Self::detect_pattern(content);
            let confidence = Self::calculate_confidence(content, &pattern_type);
            
            potential_secrets.push(PotentialSecret {
                content: content.clone(),
                offset: metadata.size - buffer.len() as u64 + offset as u64, // Approximate offset
                pattern_type: if pattern_type != PatternType::Unknown { Some(pattern_type) } else { None },
                confidence,
            });
        }
        
        Ok(BlobParseResult {
            format: metadata.format,
            potential_secrets,
            metadata,
        })
    }
    
    /// Parse a blob from raw bytes.
    pub fn parse_bytes(&self, data: &[u8]) -> BlobParseResult {
        let mut metadata = BlobMetadata {
            size: data.len() as u64,
            format: None,
            string_count: 0,
        };
        
        if self.config.detect_magic {
            if let Some(format) = Self::detect_format_from_bytes(data) {
                metadata.format = Some(format.to_string());
            }
        }
        
        let strings = Self::extract_strings(data);
        metadata.string_count = strings.len();
        
        let mut potential_secrets = Vec::new();
        for (offset, content) in strings.iter().enumerate() {
            if content.len() < self.config.min_string_length {
                continue;
            }
            
            if offset >= self.config.max_strings_per_blob {
                break;
            }
            
            let pattern_type = Self::detect_pattern(content);
            let confidence = Self::calculate_confidence(content, &pattern_type);
            
            potential_secrets.push(PotentialSecret {
                content: content.clone(),
                offset: metadata.size - data.len() as u64 + offset as u64,
                pattern_type: if pattern_type != PatternType::Unknown { Some(pattern_type) } else { None },
                confidence,
            });
        }
        
        BlobParseResult {
            format: metadata.format,
            potential_secrets,
            metadata,
        }
    }
    
    /// Detect file format from path (using magic numbers).
    fn detect_format(path: &Path) -> Option<String> {
        let mut buffer = [0u8; 16];
        
        if !path.exists() || path.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return None;
        }
        
        // Try to read magic bytes from file
        match fs::File::open(path).and_then(|f| f.read_exact(&mut buffer)) {
            Ok(_) => Self::detect_format_from_bytes(&buffer),
            Err(_) => None,
        }
    }
    
    /// Detect format directly from bytes.
    fn detect_format_from_bytes(data: &[u8]) -> Option<String> {
        for (magic, format) in MAGIC.iter() {
            if data.len() >= magic.len() && &data[..magic.len()] == *magic {
                return Some(format.to_string());
            }
        }
        
        // Fallback: treat as raw binary
        None
    }
    
    /// Extract printable strings from blob.
    fn extract_strings(data: &[u8]) -> Vec<String> {
        let mut result = Vec::new();
        let min_length = Self::min_string_length;
        
        // Use a sliding window approach for memory efficiency
        let mut current_start = 0;
        let mut current_len = 0;
        
        for (i, &byte) in data.iter().enumerate() {
            if byte.is_ascii_printable() || byte == b' ' || byte == b'\t' || byte == b'\n' || byte == b'\r' {
                current_len += 1;
                
                // Check if we've reached minimum length and next byte is non-printable
                if current_len >= min_length && i + 1 < data.len() && !data[i + 1].is_ascii_printable() 
                   && !(data[i + 1] == b' ' || data[i + 1] == b'\t') {
                    result.push(String::from_utf8_lossy(&data[current_start..i]).to_string());
                    
                    if result.len() >= Self::max_strings_per_blob {
                        break;
                    }
                }
            } else {
                // End of a string sequence
                if current_len >= min_length && i < data.len() - 1 {
                    result.push(String::from_utf8_lossy(&data[current_start..i]).to_string());
                    
                    if result.len() >= Self::max_strings_per_blob {
                        break;
                    }
                }
                
                // Start new sequence after non-printable byte
                current_start = i + 1;
                current_len = 0;
            }
        }
        
        // Handle trailing string
        if current_len >= min_length && !data.is_empty() {
            result.push(String::from_utf8_lossy(&data[current_start..]).to_string());
        }
        
        result
    }
    
    /// Detect pattern type in a potential secret.
    fn detect_pattern(content: &str) -> PatternType {
        let lower = content.to_lowercase();
        
        // Check for key types first (highest priority)
        if regex::Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").is_some() {
            return PatternType::RsaKey;
        }
        if regex::Regex::new(r"-----BEGIN EC PRIVATE KEY-----").is_some() {
            return PatternType::EcdhKey;
        }
        if regex::Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").is_some() {
            return PatternType::OpensshKey;
        }
        if regex::Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").is_some() {
            return PatternType::PgpKey;
        }
        
        // Check for API tokens
        if lower.contains("api_key") || lower.contains("apikey") {
            return PatternType::ApiToken;
        }
        if regex::Regex::new(r"bearer\s+['\"]?[a-zA-Z0-9_\-\.]+['\"]?").is_some() {
            return PatternType::BearerToken;
        }
        
        // Check for passwords
        if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
            return PatternType::Password;
        }
        
        // Check for default credentials
        if lower.contains("default") || lower.contains("factory") || lower.contains("reset") {
            return PatternType::DefaultCreds;
        }
        
        PatternType::Unknown
    }
    
    /// Calculate confidence score for a potential secret.
    fn calculate_confidence(content: &str, pattern_type: &PatternType) -> f32 {
        let mut confidence = 0.5f32; // Base confidence
        
        match pattern_type {
            PatternType::RsaKey | PatternType::EcdhKey | PatternType::OpensshKey | 
            PatternType::PgpKey => {
                confidence += 0.3; // Very high for key formats
            }
            PatternType::ApiToken | PatternType::BearerToken => {
                confidence += 0.25;
            }
            PatternType::Password => {
                if content.len() >= 8 {
                    confidence = 0.7;
                } else {
                    confidence = 0.4;
                }
            }
            PatternType::DefaultCreds => {
                confidence += 0.25;
            }
            PatternType::Unknown => {
                // Check for common secret-like patterns
                if content.len() >= 16 && 
                   (content.chars().filter(|c| c.is_alphanumeric()).count() as f32 / content.len() as f32) > 0.8 {
                    confidence = 0.4;
                }
            }
        }
        
        // Bonus for longer strings
        let length_bonus = (content.len() - 16).clamp(0, 50) as f32 / 50.0 * 0.2;
        confidence += length_bonus;
        
        confidence.min(1.0)
    }
    
    /// Get the minimum string length threshold.
    fn min_string_length() -> usize {
        Self::config.min_string_length
    }
}

impl Default for BlobParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_magic_detection() {
        let parser = BlobParser::new();
        
        // Test ELF detection
        let elf_magic = b"\x7fELF";
        assert_eq!(parser.detect_format_from_bytes(elf_magic), Some("ELF".to_string()));
        
        // Test PE detection
        let pe_magic = b"MZ";
        assert_eq!(parser.detect_format_from_bytes(pe_magic), Some("PE/EXE".to_string()));
    }
    
    #[test]
    fn test_string_extraction() {
        let parser = BlobParser::new();
        
        // Test with a simple blob containing strings
        let data = b"Hello World\x00Test String\x00Another123";
        let result = parser.parse_bytes(data);
        
        assert!(result.metadata.string_count > 0);
    }
    
    #[test]
    fn test_rsa_key_detection() {
        let parser = BlobParser::new();
        
        let key_data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let result = parser.parse_bytes(key_data);
        
        assert!(result.potential_secrets.len() > 0);
    }
}

fn main() {
    println!("keyhunt: Blob Parser Demo");
    println!("=========================");
    
    // Example usage with a sample blob
    let parser = BlobParser::new();
    
    // Create a test blob with embedded secrets
    let test_blob = vec![
        b"Hello\x00",
        b"API_KEY=sk_test_1234567890abcdef",
        b"\x00\x00",
        b"password: admin123",
        b"\x00-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\x00",
    ].concat();
    
    let result = parser.parse_bytes(&test_blob);
    
    println!("Blob size: {} bytes", result.metadata.size);
    println!("Format detected: {:?}", result.metadata.format);
    println!("Strings extracted: {}", result.metadata.string_count);