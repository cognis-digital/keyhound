import { Readable } from 'node:stream';

// ============================================================================
// CONFIGURATION & TYPES
// ============================================================================

export type ScanResult = {
  file: string;
  offset: number;
  length: number;
  category: 'SSH_KEY' | 'API_TOKEN' | 'PASSWORD' | 'RSA_MODULUS' | 'ECC_POINT' | 'DEFAULT_CRED';
  match: string;
  confidence: number; // 0.0 - 1.0
};

export interface ScannerConfig {
  minConfidence: number;
  maxResultsPerFile: number;
  caseSensitive: boolean;
  includeBinary: boolean;
}

const DEFAULT_CONFIG: Required<ScannerConfig> = {
  minConfidence: 0.7,
  maxResultsPerFile: 100,
  caseSensitive: false,
  includeBinary: true,
};

// ============================================================================
// PATTERN DEFINITIONS
// ============================================================================

const PATTERNS: Record<string, { regex: RegExp; category: ScanResult['category']; confidence: number }> = [
  // SSH Keys
  {
    regex: /-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g,
    category: 'SSH_KEY',
    confidence: 0.95,
  },
  {
    regex: /ssh-rsa\s+AAA[A-Za-z0-9+/=]{100,}/g,
    category: 'SSH_KEY',
    confidence: 0.85,
  },
  {
    regex: /ssh-ed25519\s+AAA[A-Za-z0-9+/=]{40,}/g,
    category: 'SSH_KEY',
    confidence: 0.85,
  },

  // API Tokens & Keys
  {
    regex: /(?<prefix>AKIA|ABIA|ACCA)[A-Z0-9]{16,20}/g,
    category: 'API_TOKEN',
    confidence: 0.9,
  },
  {
    regex: /pat_[a-zA-Z0-9_-]{36}/g,
    category: 'API_TOKEN',
    confidence: 0.85,
  },
  {
    regex: /ghp_[A-Za-z0-9]{36}/g,
    category: 'API_TOKEN',
    confidence: 0.85,
  },
  {
    regex: /pk_(live|test)_[a-zA-Z0-9_-]{24,}/g,
    category: 'API_TOKEN',
    confidence: 0.8,
  },

  // Passwords & Default Creds
  {
    regex: /(?<prefix>admin|root|user|default):(?<pass>[A-Za-z0-9@#$%^&*]{6,})/g,
    category: 'PASSWORD',
    confidence: 0.75,
  },
  {
    regex: /password\s*=\s*['"]?(?<pass>[A-Za-z0-9@#$%^&*]{8,})['"]?/g,
    category: 'PASSWORD',
    confidence: 0.7,
  },

  // RSA/ECC Material
  {
    regex: /n\s*=\s*([0-9a-fA-F]{128,256})/g,
    category: 'RSA_MODULUS',
    confidence: 0.8,
  },
  {
    regex: /e\s*=\s*(3|65537)/g,
    category: 'RSA_MODULUS',
    confidence: 0.75,
  },
  {
    regex: /y1\s*=\s*([0-9a-fA-F]{128,256})/g,
    category: 'ECC_POINT',
    confidence: 0.85,
  },

  // Common Default Credentials
  {
    regex: /(?<user>[A-Za-z0-9_]+):(?<pass>password|admin|1234|root|toor)/g,
    category: 'DEFAULT_CRED',
    confidence: 0.65,
  },
];

// ============================================================================
// BINARY UTILITIES
// ============================================================================

class BinaryReader {
  private buffer: Uint8Array;
  private offset: number = 0;

  constructor(buffer: Uint8Array) {
    this.buffer = buffer;
  }

  reset() {
    this.offset = 0;
  }

  peekBytes(n: number): string | null {
    if (this.offset + n > this.buffer.length) return null;
    const slice = this.buffer.slice(this.offset, this.offset + n);
    this.offset += n;
    return this.decodeString(slice);
  }

  readBytes(n: number): string | null {
    if (this.offset + n > this.buffer.length) return null;
    const slice = this.buffer.slice(this.offset, this.offset + n);
    this.offset += n;
    return this.decodeString(slice);
  }

  private decodeString(bytes: Uint8Array): string {
    // Try UTF-8 first, fall back to latin1 for binary safety
    try {
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(bytes);
    } catch {
      return String.fromCharCode(...bytes);
    }
  }

  peekLine(): string | null {
    if (this.offset >= this.buffer.length) return null;
    
    // Find next newline
    const slice = new Uint8Array(this.buffer.slice(this.offset));
    const nlIndex = slice.indexOf(0x0A); // \n
    
    if (nlIndex === -1) {
      // No newline found, read to end
      this.reset();
      return this.decodeString(slice);
    }

    const lineSlice = new Uint8Array(this.buffer.slice(this.offset, this.offset + nlIndex));
    this.offset += nlIndex;
    
    try {
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(lineSlice);
    } catch {
      return String.fromCharCode(...lineSlice);
    }
  }

  peekLines(n: number): string[] {
    const lines: string[] = [];
    while (lines.length < n && this.peekLine() !== null) {
      lines.push(this.readBytes(0)!); // Already consumed by peekLine
    }
    return lines;
  }

  getRemaining(): Uint8Array {
    return new Uint8Array(this.buffer.slice(this.offset));
  }
}

// ============================================================================
// SCANNER ENGINE
// ============================================================================

class CredentialScanner {
  private config: Required<ScannerConfig>;
  private results: ScanResult[] = [];

  constructor(config?: Partial<ScannerConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  reset() {
    this.results = [];
  }

  scanFile(filePath: string): void {
    let buffer: Uint8Array;
    
    try {
      // Try to read as file first
      const fs = require('fs');
      buffer = fs.readFileSync(filePath);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
        console.warn(`File not found: ${filePath}`);
        return;
      }
      // Fall back to stdin or stream
      const readable = Readable.from(e as any);
      buffer = Buffer.concat(readable.read());
    }

    this.scanBuffer(filePath, buffer);
  }

  scanBuffer(fileName: string, data: Uint8Array): void {
    if (data.length === 0) return;

    const reader = new BinaryReader(data);
    let resultsInFile: ScanResult[] = [];

    // Strategy 1: Line-by-line text scanning
    while (reader.peekLine() !== null) {
      const line = reader.readBytes(0)!;
      
      for (const pattern of PATTERNS) {
        if (!this.config.caseSensitive && pattern.regex.global) {
          pattern.regex.lastIndex = 0;
        }

        let match: RegExpExecArray | null;
        
        // For global patterns, find all matches in this line
        const regex = pattern.regex.global ? 
          new RegExp(pattern.regex.source, pattern.regex.flags + (this.config.caseSensitive ? '' : 'i')) :
          new RegExp(pattern.regex.source, pattern.regex.flags + (this.config.caseSensitive ? '' : 'i'));

        match = regex.exec(line);
        
        if (match) {
          const matchedText = this.extractMatch(match, line);
          
          // Check confidence threshold
          if (pattern.confidence >= this.config.minConfidence) {
            resultsInFile.push({
              file: fileName,
              offset: reader.offset - line.length,
              length: matchedText.length,
              category: pattern.category,
              match: matchedText,
              confidence: pattern.confidence,
            });

            // Limit results per file
            if (resultsInFile.length >= this.config.maxResultsPerFile) {
              break;
            }
          }
        }
      }
    }

    // Strategy 2: Binary blob scanning for RSA/ECC patterns
    if (this.config.includeBinary && data.length > 100) {
      const binaryMatches = this.scanBinaryBlob(data, fileName);
      resultsInFile.push(...binaryMatches);
    }

    this.results.push(...resultsInFile);
  }

  private extractMatch(match: RegExpExecArray | null, line: string): string {
    if (!match) return '';
    
    // Find the matched text in the original line
    const index = match.index!;
    return line.substring(index, index + match[0].length);
  }

  private scanBinaryBlob(data: Uint8Array, fileName: string): ScanResult[] {
    const results: ScanResult[] = [];
    
    // Look for RSA modulus patterns in binary data
    const hexString = Buffer.from(data).toString('hex');
    
    // Check for common RSA key markers
    if (hexString.includes('302d') || hexString.includes('3081')) {
      // ASN.1 SEQUENCE markers - likely PKCS#1/5
      const asn1Matches = this.extractAsn1Field(hexString, 'n', 16);
      results.push(...asn1Matches);
    }

    return results;
  }

  private extractAsn1Field(hexData: string, fieldName: string, minLen: number): ScanResult[] {
    const results: ScanResult[] = [];
    
    // Look for field name followed by hex data
    const regex = new RegExp(`\\b${fieldName}\\s*:\\s*([0-9a-fA-F]{${minLen * 2},})`, 'g');
    let match;
    
    while ((match = regex.exec(hexData)) !== null) {
      results.push({
        file: 'binary_blob',
        offset: 0, // Approximate in binary blob
        length: match[1].length / 2,
        category: fieldName === 'n' ? 'RSA_MODULUS' : 'UNKNOWN',
        match: `0x${match[1]}`,
        confidence: 0.8,
      });
    }

    return results;
  }

  getResults(): ScanResult[] {
    // Sort by confidence (highest first)
    return [...this.results].sort((a, b) => b.confidence - a.confidence);
  }

  filterByCategory(category: ScanResult['category']): ScanResult[] {
    return this.getResults().filter(r => r.category === category);
  }

  summary(): string {
    const grouped: Record<string, number> = {};
    
    for (const result of this.results) {
      const key = `${result.category}(${Math.round(result.confidence * 100)}%)`;
      grouped[key] = (grouped[key] || 0) + 1;
    }

    return Object.entries(grouped)
      .map(([cat, count]) => `  ${cat}: ${count}`)
      .join('\n');
  }
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

function parseArgs(args: string[]): ScannerConfig {
  const config: Partial<ScannerConfig> = {};
  
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--min-confidence':
        config.minConfidence = parseFloat(args[++i] || '0.7');
        break;
      case '--case-sensitive':
        config.caseSensitive = true;
        break;
      case '--no-binary':
        config.includeBinary = false;
        break;
      default:
        // Treat as file path
        if (!config.minConfidence && !config.caseSensitive) {
          config._files = (config._files || []).concat(args[i]);
        }
    }
  }

  return { ...DEFAULT_CONFIG, ...config };
}

function printHelp(): void {
  console.log(`
Usage: node credential_scanner.ts [options] <file>...

Options:
  --min-confidence <n>   Minimum confidence threshold (default: 0.7)
  --case-sensitive       Enable case-sensitive matching
  --no-binary            Disable binary blob scanning
  
Examples:
  node credential_scanner.ts firmware.bin
  node credential_scanner.ts --min-confidence 0.8 dump.img
`);
}

// ============================================================================
// MAIN ENTRY POINT & DEMO
// ============================================================================

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  // Demo mode if no arguments provided
  if (args.length === 0) {
    console.log('Running demo with sample data...\n');
    
    // Create a mock firmware blob with embedded credentials
    const sampleData: Uint8Array = Buffer.from([
      // Header
      ...Buffer.from('FIRMWARE_IMAGE_V1.2\n'),
      
      // Embedded SSH key
      ...Buffer.from(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcdsxiq...
wJ7bV6H4xL9vN8mP3qR2sT1uY0oI=
-----END RSA PRIVATE KEY-----`),
      
      // Embedded API token
      ...Buffer.from(`# Configuration
api_key = "AKIAIOSFODNN7EXAMPLE123"
github_pat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890abcd"

[database]
password = "admin123"`),
      
      // Embedded RSA modulus (ASN.1 format)
      ...Buffer.from(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
n = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
e = 65537
-----END PUBLIC KEY-----`),
      
      // Default credentials
      ...Buffer.from(`# User accounts
admin:password
root:toor
default_user:1234`),
    ]);

    const scanner = new CredentialScanner({ minConfidence: 0.6 });
    
    console.log('Scanning sample firmware blob...\n');
    
    // Scan the binary data
    scanner.scanBuffer('sample_firmware.bin', sampleData);
    
    // Output results
    const results = scanner.getResults();
    
    if (results.length === 0) {
      console.log('No matches found.');
    } else {
      console.log(`Found ${results.length} potential credential(s):\n\n` + 
                  scanner.summary());
      
      console.log('\n--- Detailed Results ---\n');
      for (const result of results.slice(0, 15)) { // Limit output
        const prefix = '>>>';
        console.log(`${prefix} ${result.category.padEnd(20)} [${Math.round(result.confidence * 100)}%]`);
        console.log(`    Offset: ${result.offset}, Length: ${result.length}`);
        console.log(`    Match: ${result.match.substring(0, 80)}...`);
      }
      
      if (results.length > 15) {
        console.log(`\n... and ${results.length - 15} more matches.`);
      }
    }

    // Exit with non-zero code if high-confidence findings found
    const critical = results.filter(r => r.confidence >= 0.9).length;
    process.exit(critical > 0 ? 1 : 0);
  } else {
    // CLI mode - scan provided files
    const config = parseArgs(args);
    const scanner = new CredentialScanner(config);

    for (const file of config._files || []) {
      console.log(`Scanning: ${file}`);
      scanner.scanFile(file);
    }

    if (scanner.results.length > 0) {
      console.log('\n--- Scan Summary ---');
      console.log(scanner.summary());
      
      // Output as JSON for piping
      const jsonOutput = JSON.stringify(scanner.getResults(), null, 2);
      process.stdout.write(jsonOutput + '\n');
    } else {
      console.log('No matches found.');
    }

    process.exit(0);
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch((err