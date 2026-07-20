package polyglot.java;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.util.regex.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;

/**
 * Blob Parser for KeyHunt - Scans firmware and filesystem dumps for secrets.
 */
public class BlobParser {

    // --- Configuration Constants ---
    private static final int DEFAULT_BUFFER_SIZE = 65536;
    private static final int MIN_RSA_MODULUS_BITS = 1024;
    private static final int MAX_RSA_MODULUS_BITS = 8192;
    
    // --- Regex Patterns for Common Secrets ---
    private static final Pattern API_KEY_PATTERN = 
        Pattern.compile("(?i)(api[_-]?key|apikey)[\\s:=]*['\"]?([A-Za-z0-9_\\-\\.]{16,})['\"]?", 
                       Pattern.CASE_INSENSITIVE);
    
    private static final Pattern JWT_TOKEN_PATTERN = 
        Pattern.compile("(?i)(access[_-]?token|auth[_-]?token)[\\s:=]*['\"]?([A-Za-z0-9_\\-\\.]{20,})['\"]?", 
                       Pattern.CASE_INSENSITIVE);
    
    private static final Pattern AWS_SECRET_PATTERN = 
        Pattern.compile("(?i)(aws[_-]?secret|access[_-]?key)[\\s:=]*['\"]?(A[0-9]{16}|AKIA[A-Z0-9]{14})['\"]?", 
                       Pattern.CASE_INSENSITIVE);
    
    private static final Pattern DEFAULT_CRED_PATTERN = 
        Pattern.compile("(?i)(default[_-]?password|admin[_-]?pass)[\\s:=]*['\"]?(password|secret|admin123|qwerty)");

    // --- RSA/ECC Weakness Patterns ---
    private static final int[] COMMON_RSA_EXPONENTS = {65537, 3, 17};
    
    public static class BlobResult {
        public String source;
        public long offset;
        public String category;
        public String matchType;
        public Object value;
        
        @Override
        public String toString() {
            return String.format("BlobResult@%d: %s | %s | '%s'", 
                hashCode(), category, matchType, value);
        }
    }

    private static class RSAWeakness {
        public int modulusBits;
        public BigInteger e;
        public BigInteger d;
        
        @Override
        public String toString() {
            return String.format("RSA@%d: e=%s, d=%s", 
                modulusBits, e, d);
        }
    }

    private static class ECCWeakness {
        public int curveName; // 1=secp256r1, 2=secp384r1, 3=secp521r1
        public BigInteger p;
        public BigInteger a, b;
        
        @Override
        public String toString() {
            return "ECC@" + curveName + ": P=" + p.toString(16);
        }
    }

    private static class ParserConfig {
        public int bufferSize = DEFAULT_BUFFER_SIZE;
        public boolean detectRSA = true;
        public boolean detectECC = true;
        public boolean detectPatterns = true;
        public long minFileSizeBytes = 0; // 0 = no limit
        
        @Override
        public String toString() {
            return "ParserConfig{bufferSize=" + bufferSize + 
                   ", detectRSA=" + detectRSA + 
                   ", detectECC=" + detectECC + "}";
        }
    }

    private ParserConfig config;
    
    public BlobParser(ParserConfig cfg) {
        this.config = (cfg != null) ? cfg : new ParserConfig();
    }

    public BlobParser() {
        this(new ParserConfig());
    }

    /**
     * Parse a file path for embedded secrets.
     */
    public List<BlobResult> parseFile(String filePath) throws IOException {
        if (filePath == null || filePath.isEmpty()) {
            return new ArrayList<>();
        }
        
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("File not found: " + filePath);
        }

        long fileSize = file.length();
        if (fileSize < config.minFileSizeBytes) {
            return new ArrayList<>();
        }

        List<BlobResult> results = new ArrayList<>();
        
        // Read entire file into memory for pattern scanning
        byte[] data = readAllBytes(file);
        String content = new String(data, StandardCharsets.UTF_8);
        
        if (config.detectPatterns) {
            scanForSecrets(content, filePath, 0, results);
        }

        if (config.detectRSA) {
            scanForRSAData(data, fileSize, results);
        }

        if (config.detectECC) {
            scanForECDData(data, fileSize, results);
        }

        return results;
    }

    /**
     * Parse a byte array directly.
     */
    public List<BlobResult> parseBytes(byte[] data, String sourceName) {
        if (data == null || data.length == 0) {
            return new ArrayList<>();
        }

        List<BlobResult> results = new ArrayList<>();
        
        // Convert to string for pattern matching
        try {
            String content = new String(data, StandardCharsets.UTF_8);
            if (config.detectPatterns) {
                scanForSecrets(content, sourceName, 0, results);
            }

            if (config.detectRSA) {
                scanForRSAData(data, data.length, results);
            }

            if (config.detectECC) {
                scanForECDData(data, data.length, results);
            }
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is always supported in Java 7+
            String content = new String(data);
            if (config.detectPatterns) {
                scanForSecrets(content, sourceName, 0, results);
            }

            if (config.detectRSA) {
                scanForRSAData(data, data.length, results);
            }

            if (config.detectECC) {
                scanForECDData(data, data.length, results);
            }
        }

        return results;
    }

    /**
     * Parse a Stream.
     */
    public List<BlobResult> parseStream(InputStream inputStream, String sourceName) throws IOException {
        if (inputStream == null) {
            return new ArrayList<>();
        }

        // Wrap in BufferedInputStream for efficient reading
        try (BufferedInputStream bis = new BufferedInputStream(inputStream, config.bufferSize)) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            
            byte[] chunk = new byte[config.bufferSize];
            int bytesRead;
            while ((bytesRead = bis.read(chunk)) != -1) {
                buffer.write(chunk, 0, bytesRead);
                
                // Periodically scan chunks for patterns (memory efficient)
                if (buffer.size() >= config.bufferSize * 2 && 
                    config.detectPatterns) {
                    String partialContent = new String(buffer.toByteArray(), StandardCharsets.UTF_8);
                    scanForSecrets(partialContent, sourceName, buffer.size() - config.bufferSize, results -> {
                        // Add with offset adjustment
                        for (BlobResult r : results) {
                            if (!r.source.equals(sourceName)) continue;
                            r.offset += buffer.size() - config.bufferSize * 2;
                        }
                    });
                }
            }

            String fullContent = new String(buffer.toByteArray(), StandardCharsets.UTF_8);
            
            // Final scan of complete content
            if (config.detectPatterns) {
                scanForSecrets(fullContent, sourceName, 0, results);
            }

            if (config.detectRSA) {
                byte[] finalData = buffer.toByteArray();
                scanForRSAData(finalData, finalData.length, results);
            }

            if (config.detectECC) {
                scanForECDData(finalData, finalData.length, results);
            }
        }

        return results;
    }

    // --- Pattern Scanning Methods ---

    private void scanForSecrets(String content, String sourceName, long offset, 
                                Consumer<List<BlobResult>> onChunkResults) {
        if (content == null || content.isEmpty()) {
            return;
        }

        List<BlobResult> chunkResults = new ArrayList<>();

        // API Keys
        Matcher apiMatcher = API_KEY_PATTERN.matcher(content);
        while (apiMatcher.find()) {
            String value = apiMatcher.group(2);
            long startOffset = content.indexOf(value, 0);
            
            if (startOffset >= 0) {
                chunkResults.add(new BlobResult() {{
                    source = sourceName;
                    offset = startOffset;
                    category = "API_KEY";
                    matchType = "Generic API Key";
                    value = value;
                }});
            }
        }

        // JWT/Access Tokens
        Matcher jwtMatcher = JWT_TOKEN_PATTERN.matcher(content);
        while (jwtMatcher.find()) {
            String value = jwtMatcher.group(2);
            long startOffset = content.indexOf(value, 0);
            
            if (startOffset >= 0) {
                chunkResults.add(new BlobResult() {{
                    source = sourceName;
                    offset = startOffset;
                    category = "TOKEN";
                    matchType = "JWT/Access Token";
                    value = value;
                }});
            }
        }

        // AWS Credentials
        Matcher awsMatcher = AWS_SECRET_PATTERN.matcher(content);
        while (awsMatcher.find()) {
            String value = awsMatcher.group(2);
            long startOffset = content.indexOf(value, 0);
            
            if (startOffset >= 0) {
                chunkResults.add(new BlobResult() {{
                    source = sourceName;
                    offset = startOffset;
                    category = "CLOUD_CRED";
                    matchType = "AWS Credential";
                    value = value;
                }});
            }
        }

        // Default Credentials
        Matcher credMatcher = DEFAULT_CRED_PATTERN.matcher(content);
        while (credMatcher.find()) {
            String value = credMatcher.group(2);
            long startOffset = content.indexOf(value, 0);
            
            if (startOffset >= 0) {
                chunkResults.add(new BlobResult() {{
                    source = sourceName;
                    offset = startOffset;
                    category = "DEFAULT_CRED";
                    matchType = "Default Password";
                    value = value;
                }});
            }
        }

        // Base64 encoded strings (potential secrets)
        if (content.length() > 100) {
            scanForBase64Secrets(content, sourceName, offset, chunkResults);
        }

        onChunkResults.accept(chunkResults);
    }

    private void scanForBase64Secrets(String content, String sourceName, long baseOffset, 
                                      Consumer<List<BlobResult>> onChunkResults) {
        List<String> potentialBases = new ArrayList<>();
        
        // Look for strings that look like Base64 (alphanumeric + /+= with reasonable length)
        Pattern b64Pattern = Pattern.compile("[A-Za-z0-9+/]{20,}={0,2}");
        Matcher m = b64Pattern.matcher(content);
        
        while (m.find()) {
            String candidate = m.group();
            
            // Filter out common non-secret Base64 patterns
            if (candidate.contains("-----BEGIN") || 
                candidate.contains("-----END") ||
                candidate.startsWith("iVBORw0KGgo=") || // PNG header
                candidate.startsWith("UklGR")) { // GIF header
                
                continue;
            }

            try {
                byte[] decoded = decodeBase64(candidate);
                
                // Check if decoded content looks like a secret
                String decodedStr = new String(decoded, StandardCharsets.UTF_8).trim();
                
                // Look for common secret prefixes in decoded data
                boolean isSecretLike = false;
                
                if (decodedStr.toLowerCase().contains("password") ||
                    decodedStr.toLowerCase().contains("secret") ||
                    decodedStr.toLowerCase().contains("token") ||
                    decodedStr.toLowerCase().startsWith("{")) { // JSON object
                
                    isSecretLike = true;
                } else if (decodedStr.length() > 30 && 
                           !decodedStr.contains(" ") &&
                           decodedStr.matches("[A-Za-z0-9_\\-\\.]{20,}")) {
                    
                    // Could be a long key - check entropy
                    double entropy = calculateEntropy(decodedStr);
                    if (entropy > 4.5) { // High entropy suggests cryptographic material
                        isSecretLike = true;
                    }
                }

                if (isSecretLike) {
                    potentialBases.add(candidate);
                }
            } catch (Exception e) {
                // Invalid Base64, skip
            }
        }

        for (String b64 : potentialBases) {
            long startOffset = content.indexOf(b64, 0);
            
            if (startOffset >= 0) {
                try {
                    byte[] decoded = decodeBase64(b64);
                    String decodedStr = new String(decoded, StandardCharsets.UTF_8).trim();
                    
                    BlobResult result = new BlobResult() {{
                        source = sourceName;
                        offset = startOffset + baseOffset;
                        category = "ENCODED_SECRET";
                        matchType = "Base64 Encoded Secret";
                        value = decodedStr.length() > 100 ? decodedStr.substring(0, 100) + "..." : decodedStr;
                    }};
                    
                    onChunkResults.accept(Collections.singletonList(result));
                } catch (Exception e) {
                    // Skip if decoding fails
                }
            }
        }
    }

    private double calculateEntropy(String str) {
        int[] freq = new int[256];
        
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c >= 32 && c <= 126) { // Printable ASCII only
                freq[c]++;
            }
        }

        double entropy = 0.0;
        int total = 0;
        
        for (int f : freq) {
            if (f > 0) {
                total += f;
                double p = f / (double) total;
                entropy -= p * Math.log(p);
            }
        }

        return entropy;
    }

    private byte[] decodeBase64(String b64) throws Exception {
        // Add padding if necessary
        int mod4 = b64.length() % 4;
        if (mod4 != 0) {
            for (int i = 0; i < 4 - mod4; i++) {
                b64 += "=";
            }
        }

        return java.util.Base64.getDecoder().decode(b64);
    }

    // --- RSA Scanning Methods ---

    private void scanForRSAData(byte[] data, long dataSize, List<BlobResult> results) {
        if (data == null || data.length < 512) {
            return;
        }

        try {
            String content = new String(data, StandardCharsets.UTF_8);
            
            // Look for PEM headers
            Pattern pemHeaderPattern = Pattern.compile(
                "-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", 
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
            
            Matcher headerMatcher = pemHeaderPattern.matcher(content);
            while (headerMatcher.find()) {
                String body = headerMatcher.group(1);
                
                // Extract modulus and exponent from PEM body
                try {
                    byte[] pemBodyBytes = decodeBase64(body.trim());
                    
                    if (pemBodyBytes.length >= 256) {
                        // Parse RSA public key structure
                        int offset = 0;
                        
                        // Skip version byte
                        offset += 1;
                        
                        // Read modulus length
                        int modLen = pemBodyBytes[offset] & 0xFF;
                        offset++;
                        
                        if (modLen > 0) {
                            int modOffset = offset;
                            offset += modLen + 1;
                            
                            // Read exponent length
                            int expLen = pemBodyBytes[offset] & 0xFF;
                            offset++;
                            
                            if (expLen > 0) {
                                int expOffset = offset;
                                offset += expLen + 1;
                                
                                // Extract modulus and exponent as BigIntegers
                                BigInteger mod = new BigInteger(1, 
                                    Arrays.copyOfRange(pemBodyBytes, modOffset, modOffset + modLen));
                                BigInteger exp = new BigInteger(1, 
                                    Arrays.copyOfRange(pemBodyBytes, expOffset, expOffset + expLen));
                                
                                // Check if modulus is in expected range (weak RSA)
                                int bitLength = mod.bitLength();
                                
                                if (bitLength >= MIN_RSA_MODULUS_BITS && 
                                    bitLength <= MAX_RSA_MODULUS_BITS) {
                                    
                                    // Check for weak exponent
                                    boolean weakExp = false;
                                    String expStr = exp.toString(16);
                                    
                                    for (int common : COMMON_RSA_EXPONENTS) {
                                        if (exp.equals(BigInteger.valueOf(common))) {
                                            weakExp = true;
                                            break;
                                        }
                                    }
                                    
                                    // Check for small modulus (weak key)
                                    boolean smallMod = bitLength < 2048;
                                    
                                    results.add(new BlobResult() {{
                                        source = "RSA_KEY";
                                        offset = modOffset - 1; // Approximate position
                                        category = "WEAK_RSA";
                                        matchType = weakExp ? "Small Modulus + Common Exponent" : 
                                                       smallMod ? "Small Modulus" : "Standard RSA";