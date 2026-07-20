#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <regex>
#include <sstream>
#include <cstring>

namespace keyhunt {

struct ScanResult {
    std::string filename;
    size_t offset;
    std::string category;
    std::string value;
    uint64_t confidence; // 0-100, higher = more likely real
};

class CredentialScanner {
public:
    static constexpr size_t MIN_KEY_LENGTH = 32;
    static constexpr size_t MAX_KEY_LENGTH = 512;
    
private:
    std::vector<std::string> base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> hex_chars;
    
public:
    CredentialScanner() {
        for (char c : "0123456789ABCDEFabcdef") {
            hex_chars.push_back(static_cast<uint8_t>(c));
        }
    }

    bool is_base64_char(char c) const {
        return base64_chars.find(c) != std::string::npos;
    }

    bool is_hex_char(uint8_t b) const {
        auto it = std::find(hex_chars.begin(), hex_chars.end(), b);
        return it != hex_chars.end();
    }

    // Check if string looks like base64 (high entropy, valid chars only)
    double estimate_base64_entropy(const std::string& s) const {
        if (s.empty() || s.length() < 8) return 0.0;
        
        size_t valid = 0, invalid = 0;
        for (char c : s) {
            if (is_base64_char(c)) valid++;
            else invalid++;
        }
        
        double ratio = static_cast<double>(valid) / s.length();
        return -ratio * std::log2(ratio + 1e-9) - 
               (1.0 - ratio) * std::log2((1.0 - ratio) + 1e-9);
    }

    // Check if string looks like hex-encoded data
    bool is_hex_string(const std::string& s, size_t min_len = 32) {
        return s.length() >= min_len && 
               s.length() % 2 == 0 &&
               std::all_of(s.begin(), s.end(), [this](char c){
                   return is_hex_char(static_cast<uint8_t>(c));
               });
    }

    // Check if string looks like a private key (PEM-like or raw)
    bool looks_like_private_key(const std::string& s, size_t offset = 0) {
        // PEM headers
        static const std::vector<std::string> pem_headers = {
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        };

        for (const auto& header : pem_headers) {
            if (s.find(header, offset) != std::string::npos) return true;
        }

        // Raw key indicators: high entropy + reasonable length
        if (s.length() >= MIN_KEY_LENGTH && s.length() <= MAX_KEY_LENGTH) {
            double ent = estimate_base64_entropy(s);
            if (ent > 4.5 && is_hex_string(s, 32)) return true;
        }

        // Common RSA modulus patterns (large hex numbers)
        static const std::vector<std::string> rsa_patterns = {
            "010001", "010003", "C4A146F", "B7E1516"
        };

        for (const auto& pat : rsa_patterns) {
            if (s.find(pat, offset) != std::string::npos) return true;
        }

        return false;
    }

    // Check if string looks like an API token/secret
    bool looks_like_api_token(const std::string& s, size_t offset = 0) {
        static const std::vector<std::string> prefixes = {
            "AKIA", "ABIA", "ACCA", "ADAA", // AWS IAM
            "ghp_", "gho_", "ghu_", "ghw_", "ghx_", // GitHub personal tokens
            "glpat-", // GitHub classic PAT
            "pk_live_", "pk_test_", // Stripe
            "sk_live_", "sk_test_", // Stripe secret keys
            "os_1a2b3c4d", // OpenAI
            "Bearer ", "Basic ", "API-Key: ", "X-API-Key: "
        };

        for (const auto& prefix : prefixes) {
            if (s.find(prefix, offset) != std::string::npos) return true;
        }

        // JWT-like tokens
        static const std::regex jwt_pattern(R"(^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$)");
        if (std::regex_match(s, jwt_pattern)) return true;

        return false;
    }

    // Check for default/weak credentials
    bool looks_like_default_creds(const std::string& s) {
        static const std::vector<std::pair<std::string, std::string>> defaults = {
            {"admin", "admin"},
            {"root", "toor"},
            {"user", "pass"},
            {"test", "test123"},
            {"guest", "guest"},
            {"oracle", "oracle"},
            {"postgres", "postgres"},
            {"mysql", "mysql"},
            {"sa", "sa"},
            {"sql", "sql"},
            {"ftpuser", "ftpuser"}
        };

        for (const auto& [u, p] : defaults) {
            if ((s == u || s == p)) return true;
        }

        // Common weak passwords
        static const std::vector<std::string> weak = {
            "password", "123456", "qwerty", "abc123", "letmein",
            "welcome", "monkey", "dragon", "master", "shadow"
        };

        for (const auto& w : weak) {
            if (s == w || s.find(w) != std::string::npos) return true;
        }

        return false;
    }

    // Check for RSA/ECC material weakness
    bool looks_like_weak_crypto(const std::string& s, size_t offset = 0) {
        static const std::vector<uint32_t> weak_primes = {
            547, 619, 787, 821, 823, 827, 829, 839, 853, 857,
            859, 863, 877, 881, 883, 887, 907, 911, 919, 929
        };

        // Check if number is product of small primes (weak RSA)
        for (auto p : weak_primes) {
            if (s.find(std::to_string(p), offset) != std::string::npos) return true;
        }

        // Common weak ECC points
        static const std::vector<std::string> weak_ecc = {
            "04", "06", "08", "10", "12"  // Curve identifiers
        };

        for (const auto& w : weak_ecc) {
            if (s.find(w, offset) != std::string::npos) return true;
        }

        return false;
    }

    // Calculate confidence score
    uint64_t calculate_confidence(const std::string& s, 
                                  const std::string& category,
                                  size_t offset) {
        double base = 50.0;
        
        if (looks_like_private_key(s)) base += 30;
        else if (looks_like_api_token(s)) base += 25;
        else if (looks_like_default_creds(s)) base += 40;
        else if (looks_like_weak_crypto(s)) base += 20;

        // Bonus for length and entropy
        double ent = estimate_base64_entropy(s);
        base += std::min(15.0, ent * 3.0);

        // Penalty for very short strings
        if (s.length() < MIN_KEY_LENGTH) base -= 20;

        return static_cast<uint64_t>(std::clamp(base, 0.0, 100.0));
    }

    // Scan a single file
    std::vector<ScanResult> scan_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) return {};

        std::vector<uint8_t> buffer((std::max<size_t>(1024, file.tellg() + 1));
        file.seekg(0, std::ios::end);
        size_t filesize = file.tellg();
        file.seekg(0, std::ios::beg);

        if (filesize <= buffer.size()) {
            file.read(reinterpret_cast<char*>(buffer.data()), filesize);
            buffer.resize(filesize);
        } else {
            // Stream large files in chunks
            size_t chunk_size = 65536;
            std::vector<ScanResult> results;

            while (file.tellg() < filesize) {
                size_t to_read = std::min(chunk_size, filesize - file.tellg());
                file.read(reinterpret_cast<char*>(buffer.data()), to_read);
                
                // Scan this chunk for patterns
                std::string chunk_str(buffer.begin(), buffer.end());

                // Look for base64-like strings (32-128 chars)
                size_t pos = 0;
                while ((pos = chunk_str.find_first_of(base64_chars, pos)) != std::string::npos) {
                    if (pos + 48 <= chunk_str.length()) {
                        std::string candidate = chunk_str.substr(pos, 48);
                        
                        // Check for newlines/whitespace boundaries
                    }

                    pos++;
                }

                file.seekg(chunk_size, std::ios::cur);
            }
        }

        return results;
    }

    // Main scanning interface
    std::vector<ScanResult> scan(const std::string& filepath) {
        if (filepath.empty()) return {};

        // Check if it's a file or directory
        std::ifstream test(filepath);
        bool is_file = !!(test.peek());
        test.close();

        if (!is_file) {
            // Directory scan - TODO: recursive
            std::cerr << "Scanning directory: " << filepath << "\n";
            return {};
        }

        std::vector<ScanResult> results;

        try {
            auto file_results = scan_file(filepath);
            for (auto& r : file_results) {
                if (!r.filename.empty()) r.filename = filepath + ":" + r.filename;
                results.push_back(r);
            }
        } catch (...) {
            std::cerr << "Error reading: " << filepath << "\n";
        }

        return results;
    }
};

// Global scanner instance
CredentialScanner g_scanner;

} // namespace keyhunt

// Demo/entry point
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file_or_directory>\n";
        return 1;
    }

    auto results = keyhunt::g_scanner.scan(argv[1]);

    if (results.empty()) {
        std::cout << "No credentials found in: " << argv[1] << "\n";
        return 0;
    }

    // Sort by confidence descending
    std::sort(results.begin(), results.end(), 
              [](const auto& a, const auto& b){
                  return a.confidence > b.confidence;
              });

    std::cout << "Found " << results.size() << " potential credentials:\n\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        
        // Truncate long values
        std::string display_value = r.value;
        if (display_value.length() > 64) {
            display_value = display_value.substr(0, 60) + "...";
        }

        std::cout << "[" << i + 1 << "] " 
                  << r.category << "\n"
                  << "  Offset: 0x" << std::hex << r.offset << std::dec << "\n"
                  << "  Value:   " << display_value << "\n"
                  << "  Confidence: " << r.confidence << "%\n\n";
    }

    return 0;
}