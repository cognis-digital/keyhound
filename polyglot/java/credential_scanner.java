package polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.security.*;
import java.security.spec.*;

/**
 * Credential Scanner for firmware blobs and filesystem dumps.
 * Detects hardcoded private keys, API tokens, default creds, and weak RSA/ECC material.
 */
public class credential_scanner {

    // Configuration constants
    private static final int DEFAULT_BUFFER_SIZE = 64 * 1024;
    private static final int MIN_RSA_MODULUS_BITS = 512;
    private static final int MAX_RSA_MODULUS_BITS = 4096;
    private static final int MIN_ECC_CURVE_ORDER = 160;

    // Regex patterns for common credential types
    private static final Map<String, Pattern> TOKEN_PATTERNS = new HashMap<>();
    private static final List<Pattern> CREDENTIAL_LINE_PATTERNS = new ArrayList<>();

    static {
        // API Tokens and Keys (generic)
        TOKEN_PATTERNS.put("Generic API Token", 
            Pattern.compile("(?:api[_-]?key|apikey)[\\s:]*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?", 
                Pattern.CASE_INSENSITIVE));

        TOKEN_PATTERNS.put("AWS Access Key ID",
            Pattern.compile("AKIA[0-9A-Z]{16}", Pattern.CASE_INSENSITIVE));

        TOKEN_PATTERNS.put("Google API Key",
            Pattern.compile("(?:AIza|GIPQ)[a-zA-Z0-9_\-]{35}", Pattern.CASE_INSENSITIVE));

        TOKEN_PATTERNS.put("Stripe Secret Key",
            Pattern.compile("sk_live_[0-9A-Za-z]{24,}", Pattern.CASE_INSENSITIVE));

        TOKEN_PATTERNS.put("Twilio Auth Token",
            Pattern.compile("SK[a-zA-Z0-9]{32}", Pattern.CASE_INSENSITIVE));

        // JWT Tokens (potential secrets)
        TOKEN_PATTERNS.put("JWT Secret Key",
            Pattern.compile("(?:jwt[_-]?secret|jwt[_-]?key)[\\s:]*['\"]?([a-zA-Z0-9_\-\.]{16,64})['\"]?", 
                Pattern.CASE_INSENSITIVE));

        // OAuth Client Secrets
        TOKEN_PATTERNS.put("OAuth Client Secret",
            Pattern.compile("(?:client[_-]?secret|oauth[_-]?secret)[\\s:]*['\"]?([a-zA-Z0-9_\-\.]{16,32})['\"]?", 
                Pattern.CASE_INSENSITIVE));

        // Generic long base64 strings (potential encrypted keys)
        TOKEN_PATTERNS.put("Potential Encrypted Key",
            Pattern.compile("[A-Za-z0-9+/=]{128,}", Pattern.CASE_INSENSITIVE));

        // Default credentials
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("(?:default|admin)[\\s:]*password[\\s:]*['\"]?([a-zA-Z0-9_\-\.]{4,})['\"]?", 
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));

        // Common default passwords
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("(?:default|admin)[\\s:]*password[\\s:]*['\"]?(password|123456|admin|qwerty|letmein)['\"]?", 
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));

        // Private key headers
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("-----BEGIN (?:RSA )?PRIVATE KEY-----", Pattern.CASE_INSENSITIVE));
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("-----BEGIN EC PRIVATE KEY-----", Pattern.CASE_INSENSITIVE));
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("-----BEGIN DSA PRIVATE KEY-----", Pattern.CASE_INSENSITIVE));

        // RSA modulus for weak key detection
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("(?:n|modulus)[\\s:]*=\\s*([0-9a-fA-F]{128,})", 
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));

        // ECC curve order (weak if small)
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("(?:d|order)[\\s:]*=\\s*([0-9a-fA-F]+)", 
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));

        // SSH private keys
        CREDENTIAL_LINE_PATTERNS.add(Pattern.compile("-----BEGIN OPENSSH PRIVATE KEY-----", Pattern.CASE_INSENSITIVE));
    }

    /**
     * Main entry point with demo functionality.
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            // Demo: scan the current directory for all files
            File[] files = new File(".").listFiles();
            if (files != null && files.length > 0) {
                System.out.println("Scanning " + files.length + " files in current directory...");
                CredentialScanner scanner = new CredentialScanner();
                
                for (File file : files) {
                    if (!file.isFile()) continue;
                    
                    String filename = file.getName();
                    long startTime = System.nanoTime();
                    
                    var results = scanner.scan(file);
                    double durationMs = (System.nanoTime() - startTime) / 1_000_000.0;
                    
                    System.out.println("\n=== " + filename + " ===");
                    System.out.println("Size: " + file.length() + " bytes, Found issues: " + results.totalIssues);
                    System.out.println("Scan time: " + String.format("%.2f", durationMs) + " ms");
                    
                    if (results.issues.isEmpty()) {
                        System.out.println("  Status: Clean");
                    } else {
                        for (var issue : results.issues) {
                            System.out.println("  [WARN] " + issue.type + ": " + issue.message);
                            if (issue.location != null) {
                                System.out.println("    Location: " + issue.location);
                            }
                            if (issue.suggestion != null) {
                                System.out.println("    Suggestion: " + issue.suggestion);
                            }
                        }
                    }
                }
            } else {
                System.out.println("No files found to scan.");
            }
        } else {
            // Command-line mode: scan specified file(s)
            CredentialScanner scanner = new CredentialScanner();
            
            for (String path : args) {
                File file = new File(path);
                
                if (!file.exists()) {
                    System.out.println("File not found: " + path);
                    continue;
                }

                var results = scanner.scan(file);
                System.out.printf("%-60s | %-15d issues | %8.2f ms\n", 
                    file.getName(), results.totalIssues, (System.nanoTime() - startTime) / 1_000_000.0);
            }
        }
    }

    /**
     * Main scanner class that orchestrates the scanning process.
     */
    public static class CredentialScanner {
        
        private final Map<String, Pattern> tokenPatterns = TOKEN_PATTERNS;
        private final List<Pattern> credentialLinePatterns = CREDENTIAL_LINE_PATTERNS;
        
        /**
         * Scans a file for credentials and returns results.
         */
        public ScanResults scan(File file) {
            long fileSize = file.length();
            if (fileSize == 0) {
                return new ScanResults(file.getName(), 0, Collections.emptyList());
            }

            // For large files, read in chunks to reduce memory pressure
            int chunkSize = Math.min((int)fileSize, DEFAULT_BUFFER_SIZE);
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(file), "UTF-8"))) {
                
                List<Issue> issues = new ArrayList<>();
                long lastMatchOffset = 0;
                boolean inKeyBlock = false;

                // Read line by line for pattern matching, but track byte offsets
                String line;
                int lineNumber = 1;
                long charPosition = 0;

                while ((line = reader.readLine()) != null) {
                    if (line.length() > 2048) {
                        // Long lines might indicate binary data or large strings
                        inKeyBlock = true;
                    } else {
                        // Check for key block boundaries
                        if (!inKeyBlock && line.contains("BEGIN") || 
                            !inKeyBlock && line.contains("END")) {
                            inKeyBlock = line.contains("BEGIN");
                        }
                        
                        // Reset flag on closing boundary
                        if (line.contains("END") && !line.contains("BEGIN")) {
                            inKeyBlock = false;
                        }

                        // Check against token patterns
                        for (Map.Entry<String, Pattern> entry : tokenPatterns.entrySet()) {
                            Matcher matcher = entry.getValue().matcher(line);
                            while (matcher.find()) {
                                String matchText = matcher.group(1) != null ? matcher.group(1) : 
                                    (matcher.group() == null ? "" : matcher.group());
                                
                                if (!matchText.isEmpty()) {
                                    issues.add(new Issue(
                                        entry.getKey(),
                                        "Found potential " + entry.getKey() + ": " + matchText,
                                        lineNumber,
                                        charPosition,
                                        "Consider rotating this credential or using a secret management system."
                                    ));
                                    lastMatchOffset = matcher.end();
                                }
                            }
                        }

                        // Check against line-based patterns (credentials, keys)
                        for (Pattern pattern : credentialLinePatterns) {
                            Matcher matcher = pattern.matcher(line);
                            while (matcher.find()) {
                                String matchText = matcher.group() != null ? 
                                    matcher.group().trim() : "";
                                
                                if (!matchText.isEmpty()) {
                                    // Avoid duplicate reports from overlapping patterns
                                    boolean isDuplicate = false;
                                    
                                    for (Issue existing : issues) {
                                        if (existing.type.equals("Private Key") ||
                                            existing.type.equals("RSA Private Key")) {
                                            continue; // Skip, will report once per block
                                        }
                                        
                                        if (existing.lineNumber == lineNumber && 
                                            Math.abs(existing.charPosition - charPosition) < 50) {
                                            isDuplicate = true;
                                            break;
                                        }
                                    }

                                    if (!isDuplicate) {
                                        issues.add(new Issue(
                                            "Credential Line",
                                            "Found credential pattern: " + matchText,
                                            lineNumber,
                                            charPosition,
                                            null
                                        ));
                                        lastMatchOffset = matcher.end();
                                    }
                                }
                            }
                        }
                    }

                    // Update character position for next line
                    charPosition += line.length() + 1; // +1 for newline
                    lineNumber++;
                }

                // Check if file ended with an open key block (binary data)
                if (inKeyBlock && fileSize > 0) {
                    issues.add(new Issue(
                        "Private Key",
                        "File appears to contain private key material (truncated or binary)",
                        lineNumber,
                        charPosition - 1,
                        "Verify if this is expected. If not, check for embedded certificates."
                    ));
                }

                return new ScanResults(file.getName(), issues.size(), issues);
            } catch (IOException e) {
                throw new RuntimeException("Error reading file: " + file.getAbsolutePath(), e);
            }
        }

        /**
         * Scans multiple files and aggregates results.
         */
        public Map<String, ScanResults> scanMultiple(File... files) {
            Map<String, ScanResults> results = new HashMap<>();
            
            for (File file : files) {
                if (!file.exists()) continue;
                
                try {
                    var result = scan(file);
                    results.put(file.getName(), result);
                } catch (Exception e) {
                    System.err.println("Error scanning " + file.getAbsolutePath() + ": " + e.getMessage());
                    results.put(file.getName(), new ScanResults(
                        file.getName(), 1, 
                        Collections.singletonList(new Issue(
                            "IO Error",
                            "Failed to read file: " + e.getMessage(),
                            -1, -1, null
                        ))
                    ));
                }
            }
            
            return results;
        }

        /**
         * Scans from a byte array (useful for memory-mapped files).
         */
        public ScanResults scan(byte[] data) {
            if (data == null || data.length == 0) {
                return new ScanResults("Memory", 0, Collections.emptyList());
            }

            try (ByteArrayInputStream bais = new ByteArrayInputStream(data)) {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(bais, "UTF-8"));
                
                List<Issue> issues = new ArrayList<>();
                int lineNumber = 1;
                long charPosition = 0;
                boolean inKeyBlock = false;

                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.length() > 2048) {
                        inKeyBlock = true;
                    } else {
                        if (!inKeyBlock && (line.contains("BEGIN") || line.contains("END"))) {
                            inKeyBlock = line.contains("BEGIN");
                        }
                        
                        if (line.contains("END") && !line.contains("BEGIN")) {
                            inKeyBlock = false;
                        }

                        for (Map.Entry<String, Pattern> entry : tokenPatterns.entrySet()) {
                            Matcher matcher = entry.getValue().matcher(line);
                            while (matcher.find()) {
                                String matchText = matcher.group(1) != null ? matcher.group(1) : 
                                    (matcher.group() == null ? "" : matcher.group());
                                
                                if (!matchText.isEmpty()) {
                                    issues.add(new Issue(
                                        entry.getKey(),
                                        "Found potential " + entry.getKey() + ": " + matchText,
                                        lineNumber,
                                        charPosition,
                                        "Consider rotating this credential or using a secret management system."
                                    ));
                                }
                            }
                        }

                        for (Pattern pattern : credentialLinePatterns) {
                            Matcher matcher = pattern.matcher(line);
                            while (matcher.find()) {
                                String matchText = matcher.group() != null ? 
                                    matcher.group().trim() : "";
                                
                                if (!matchText.isEmpty()) {
                                    boolean isDuplicate = false;
                                    
                                    for (Issue existing : issues) {
                                        if (existing.type.equals("Private Key") ||
                                            existing.type.equals("RSA Private Key")) {
                                            continue;
                                        }
                                        
                                        if (existing.lineNumber == lineNumber && 
                                            Math.abs(existing.charPosition - charPosition) < 50) {
                                            isDuplicate = true;
                                            break;
                                        }
                                    }

                                    if (!isDuplicate) {
                                        issues.add(new Issue(
                                            "Credential Line",
                                            "Found credential pattern: " + matchText,
                                            lineNumber,
                                            charPosition,
                                            null
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    charPosition += line.length() + 1;
                    lineNumber++;
                }

                if (inKeyBlock && data.length > 0) {
                    issues.add(new Issue(
                        "Private Key",
                        "Memory buffer appears to contain private key material",
                        lineNumber,
                        charPosition - 1,
                        "Verify if this is expected. If not, check for embedded certificates."
                    ));
                }

                return new ScanResults("Memory", issues.size(), issues);
            } catch (IOException e) {
                throw new RuntimeException("Error reading from byte array", e);
            }
        }
    }

    /**
     * Represents a single issue found during scanning.
     */
    public static class Issue {
        public final String type;
        public final String message;
        public final int lineNumber;
        public final long charPosition;
        public final String suggestion;

        public Issue(String type, String message, int lineNumber, long charPosition, String suggestion) {
            this.type = type;
            this.message = message;
            this.lineNumber = lineNumber;
            this.charPosition = charPosition;
            this.suggestion = suggestion;
        }

        @Override
        public String toString() {
            return String.format("[%s] Line %d: %s", type, lineNumber, message);
        }
    }

    /**
     * Aggregated results from scanning a single file.
     */
    public static class ScanResults {
        public final String filename;
        public final int totalIssues;
        public final List<Issue> issues;

        public ScanResults(String filename, int totalIssues, List<Issue> issues) {
            this.filename = filename;
            this.totalIssues = totalIssues;
            this.issues = issues != null ? issues : Collections.emptyList();
        }
    }
}