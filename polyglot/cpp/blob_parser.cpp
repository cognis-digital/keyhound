#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <span>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <memory>

namespace keyhunt {

// Magic number constants for common formats
constexpr uint32_t kPemHeaderMagic = 0x50454D48; // "PEMH" (little-endian)
constexpr uint32_t kDerMagicRSA = 0x30820101;    // RSA PKCS#1 DER start
constexpr uint32_t kDerMagicEC = 0x30820102;     // EC DER start
constexpr uint32_t kPkcs8Header = 0x30820301;    // PKCS#8 header

// Key material types
enum class KeyType {
    RSA_PRIVATE,
    RSA_PUBLIC,
    EC_PRIVATE,
    EC_PUBLIC,
    DSA_PRIVATE,
    DSA_PUBLIC,
    ED25519_PRIVATE,
    ED25519_PUBLIC,
    X25519_PRIVATE,
    X25519_PUBLIC,
    UNKNOWN
};

// Detected key info
struct KeyInfo {
    KeyType type;
    std::string format;  // "PEM", "DER", "PKCS8"
    size_t offset;       // Offset in blob where found
    std::vector<uint8_t> data;
    
    bool is_weak() const {
        return false;  // Will be set by caller after parsing
    }
};

// Safe binary reader utilities
class BinaryReader {
public:
    explicit BinaryReader(std::span<const uint8_t> blob) : blob_(blob), pos_(0) {}
    
    void reset() { pos_ = 0; }
    size_t position() const { return pos_; }
    bool at_end() const { return pos_ >= blob_.size(); }
    
    // Read bytes with bounds checking
    std::vector<uint8_t> read_bytes(size_t count) {
        if (pos_ + count > blob_.size()) {
            size_t available = blob_.size() - pos_;
            if (available == 0) return {};
            
            std::vector<uint8_t> result(available);
            std::memcpy(result.data(), blob_.data() + pos_, available);
            pos_ += available;
            return result;
        }
        
        std::vector<uint8_t> result(count);
        std::memcpy(result.data(), blob_.data() + pos_, count);
        pos_ += count;
        return result;
    }
    
    // Read with exact length, returns false if truncated
    bool read_exact(size_t count, std::vector<uint8_t>& out) {
        if (pos_ + count > blob_.size()) return false;
        
        out.resize(count);
        std::memcpy(out.data(), blob_.data() + pos_, count);
        pos_ += count;
        return true;
    }
    
    // Read 32-bit little-endian integer
    uint32_t read_u32_le() {
        if (pos_ + 4 > blob_.size()) return 0;
        
        uint8_t b[4];
        std::memcpy(b, blob_.data() + pos_, 4);
        pos_ += 4;
        return static_cast<uint32_t>(b[0]) | 
               (static_cast<uint32_t>(b[1]) << 8) |
               (static_cast<uint32_t>(b[2]) << 16) |
               (static_cast<uint32_t>(b[3]) << 24);
    }

private:
    std::span<const uint8_t> blob_;
    size_t pos_ = 0;
};

// PEM parser - handles both standard and polyglot formats
class PemParser {
public:
    static bool parse(std::string_view pem_data, KeyInfo& info) {
        // Check for PEM header markers (case-insensitive)
        auto find_marker = [](std::string_view data, std::string_view marker) -> size_t {
            size_t pos = 0;
            while ((pos = data.find(marker, pos)) != std::string::npos) {
                if (pos + marker.size() < data.size()) {
                    // Check for proper line endings after header
                    auto next = data.substr(pos + marker.size());
                    if (next.empty() || 
                        next[0] == '\n' || 
                        next[0] == ' ') {
                        return pos;
                    }
                }
                ++pos;
            }
            return std::string::npos;
        };
        
        // Try different PEM headers
        const char* headers[] = {
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN EC PUBLIC KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN DSA PUBLIC KEY-----",
            "-----BEGIN ED25519 PRIVATE KEY-----",
            "-----BEGIN ED25519 PUBLIC KEY-----",
            "-----BEGIN X25519 PRIVATE KEY-----",
            "-----BEGIN X25519 PUBLIC KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN OPENSSH PUBLIC KEY-----",
        };
        
        for (auto header : headers) {
            auto pos = find_marker(pem_data, header);
            if (pos != std::string::npos) {
                // Extract base64 content between markers
                size_t start = pos + strlen(header);
                
                // Find closing marker
                size_t end = pem_data.find("-----END ", start);
                if (end == std::string::npos) continue;
                
                // Extract and decode base64
                std::string b64_content(pem_data.substr(start, end - start));
                std::vector<uint8_t> decoded;
                
                if (decode_base64(b64_content, decoded)) {
                    info.type = parse_key_type(header);
                    info.format = "PEM";
                    info.offset = 0;  // PEM is text, offset not meaningful
                    info.data = std::move(decoded);
                    return true;
                }
            }
        }
        
        return false;
    }

private:
    static bool decode_base64(std::string_view b64, std::vector<uint8_t>& out) {
        if (b64.empty()) return false;
        
        // Remove whitespace
        std::string clean;
        for (char c : b64) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
                clean += c;
            }
        }
        
        out.clear();
        out.reserve((clean.size() / 4) * 3);
        
        int buffer = 0, bits = 0;
        for (char c : clean) {
            if (c == '=') break;
            
            int val = b64_chars.find(c);
            if (val == -1) continue;
            
            buffer = (buffer << 6) | val;
            bits += 6;
            
            while (bits >= 8) {
                out.push_back(buffer >> (bits - 8));
                bits -= 8;
            }
        }
        
        return !out.empty();
    }

private:
    static const char* b64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    static KeyType parse_key_type(std::string_view header) {
        if (header.find("RSA PRIVATE") != std::string::npos ||
            header.find("OPENSSH PRIVATE") != std::string::npos) {
            return KeyType::RSA_PRIVATE;
        } else if (header.find("RSA PUBLIC") != std::string::npos) {
            return KeyType::RSA_PUBLIC;
        } else if (header.find("EC PRIVATE") != std::string::npos ||
                   header.find("X25519 PRIVATE") != std::string::npos) {
            return KeyType::EC_PRIVATE;
        } else if (header.find("EC PUBLIC") != std::string::npos ||
                   header.find("X25519 PUBLIC") != std::string::npos) {
            return KeyType::EC_PUBLIC;
        } else if (header.find("DSA PRIVATE") != std::string::npos) {
            return KeyType::DSA_PRIVATE;
        } else if (header.find("DSA PUBLIC") != std::string::npos) {
            return KeyType::DSA_PUBLIC;
        } else if (header.find("ED25519 PRIVATE") != std::string::npos) {
            return KeyType::ED25519_PRIVATE;
        } else if (header.find("ED25519 PUBLIC") != std::string::npos) {
            return KeyType::ED25519_PUBLIC;
        }
        
        return KeyType::UNKNOWN;
    }
};

// DER parser for binary key formats
class DerParser {
public:
    static bool parse(std::span<const uint8_t> der_data, size_t offset, 
                      KeyInfo& info) {
        if (der_data.empty()) return false;
        
        // Check magic numbers to identify type
        uint32_t magic = 0;
        std::memcpy(&magic, der_data.data(), sizeof(magic));
        
        if (magic == kDerMagicRSA || 
            magic == kDerMagicEC ||
            magic == kPkcs8Header) {
            
            info.format = "DER";
            info.offset = offset;
            info.data = std::vector<uint8_t>(der_data.begin(), der_data.end());
            
            // Try to determine type from content structure
            if (magic == kDerMagicRSA || magic == kPkcs8Header) {
                info.type = KeyType::RSA_PRIVATE;
            } else if (magic == kDerMagicEC) {
                info.type = KeyType::EC_PRIVATE;
            }
            
            return true;
        }
        
        // Check for ASN.1 SEQUENCE header
        if (der_data[0] == 0x30 && der_data.size() > 1) {
            // Valid DER start - assume it's a key
            info.format = "DER";
            info.offset = offset;
            info.data = std::vector<uint8_t>(der_data.begin(), der_data.end());
            
            if (der_data[0] == 0x30) {  // SEQUENCE tag
                size_t content_len = der_data.size() - 2;
                if (content_len < 16) return false;
                
                // Check if looks like RSA public key (n, e)
                if (der_data[1] == 0x03 && 
                    der_data[2] == 0x01 && 
                    der_data[3] == 0x00) {
                    info.type = KeyType::RSA_PUBLIC;
                } else if (der_data[1] == 0x04) {  // OCTET STRING - likely private key
                    info.type = KeyType::EC_PRIVATE;
                }
            }
            
            return true;
        }
        
        return false;
    }

private:
    static uint8_t get_tag_type(uint8_t tag) {
        return (tag >> 6) & 0x03;
    }
};

// Hex string parser for embedded hex-encoded keys
class HexParser {
public:
    static bool parse(std::string_view hex_data, KeyInfo& info) {
        // Remove whitespace and convert to lowercase
        std::string clean;
        for (char c : hex_data) {
            if ((c >= '0' && c <= '9') || 
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F')) {
                clean += tolower(c);
            } else if (!std::isspace(static_cast<unsigned char>(c))) {
                clean += c;
            }
        }
        
        if (clean.size() < 32) return false;  // Minimum for a key
        
        std::vector<uint8_t> decoded(clean.size() / 2);
        for (size_t i = 0; i < decoded.size(); ++i) {
            decoded[i] = static_cast<uint8_t>(
                (clean[i * 2] - '0') + 
                (clean[i * 2 + 1] - 'a' + 10) * 16);
        }
        
        info.data = std::move(decoded);
        info.format = "HEX";
        info.offset = 0;
        return true;
    }

private:
    static char tolower(char c) {
        if (c >= 'A' && c <= 'Z') return c + 32;
        return c;
    }
};

// ASCII pattern scanner for plaintext keys and tokens
class PatternScanner {
public:
    // Common weak RSA moduli (first 64 bits)
    static const std::vector<uint64_t> kWeakRSAModuli = {
        0x010001,  // e value for RSA
        0xC5837E9F, 0x2D5A7B3C, 0x4F8E1D2A, 0x6B9C0E3F,  // Common small primes
    };

    static const std::vector<std::string> kCommonHeaders = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "ssh-rsa ",
        "ssh-ed25519 ",
    };

    static bool scan(std::string_view blob, KeyInfo& info) {
        // Check for PEM headers first
        for (const auto& header : kCommonHeaders) {
            if (blob.find(header) != std::string::npos) {
                size_t pos = blob.find(header);
                
                // Extract content after header
                size_t start = pos + strlen(header);
                size_t end = blob.find("-----END ", start);
                
                if (end == std::string::npos || end < start) continue;
                
                std::string content(blob.substr(start, end - start));
                
                // Try PEM parsing
                if (PemParser::parse(content, info)) {
                    return true;
                }
            }
        }
        
        // Check for hex-encoded content
        if (blob.find("0x") != std::string::npos || 
            blob.find("\"0x") != std::string::npos) {
            
            auto extract_hex = [](std::string_view str, size_t& pos) -> std::string {
                // Find next 0x or "0x" followed by hex digits
                while (pos < str.size()) {
                    if ((str[pos] == '0' && 
                         (str[pos + 1] == 'x' || str[pos + 1] == 'X')) ||
                        (str[pos] == '"' && pos + 2 < str.size() &&
                         str[pos + 1] == '0' && str[pos + 2] == 'x')) {
                        
                        size_t start = pos;
                        if (str[start] == '"') ++start;
                        
                        // Read hex digits
                        while (pos < str.size()) {
                            char c = str[pos];
                            if ((c >= '0' && c <= '9') || 
                                (c >= 'a' && c <= 'f') ||
                                (c >= 'A' && c <= 'F')) {
                                ++pos;
                            } else if (c == 'x' || c == 'X' || c == '"') {
                                break;
                            } else {
                                ++pos;
                            }
                        }
                        
                        return str.substr(start, pos - start);
                    }
                    ++pos;
                }
                return "";
            };
            
            size_t pos = 0;
            while (true) {
                std::string hex = extract_hex(blob, pos);
                if (hex.empty()) break;
                
                // Try to parse as key
                KeyInfo temp_info;
                if (HexParser::parse(hex, temp_info)) {
                    info.data = std::move(temp_info.data);
                    info.format = "HEX";
                    info.offset = blob.find("0x", pos - 100) > 0 ? 
                                   blob.rfind("0x", pos - 100) : 0;
                    return true;
                }
                
                ++pos;
            }
        }
        
        // Check for base64-encoded content (common in config files)
        if (blob.find("base64") != std::string::npos ||
            blob.find("b64:") != std::string::npos) {
            
            auto extract_b64 = [](std::string_view str, size_t& pos) -> std::string {
                while (pos < str.size()) {
                    if ((str[pos] == 'b' && 
                         (str[pos + 1] == 'a' || str[pos + 1] == 'B')) &&
                        (str[pos + 2] == 's' || str[pos + 3] == '6')) {
                        
                        size_t start = pos;
                        if ((str[start] == 'b' || str[start] == 'B') &&
                            (str[start +