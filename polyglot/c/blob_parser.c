#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

/* Configuration */
#define MAX_PATTERNS 256
#define MAX_RESULTS 1024
#define DEFAULT_BUFFER_SIZE (1 << 20) /* 1MB */
#define MIN_RSA_MODULUS_BITS 768
#define WEAK_RSA_THRESHOLD 512

/* Pattern types */
typedef enum {
    PTYPE_PEM,
    PTYPE_API_KEY,
    PTYPE_CREDENTIALS,
    PTYPE_ECC,
    PTYPE_WEAK_CRYPTO,
    PTYPE_UNKNOWN
} pattern_type_t;

/* Result structure for found items */
typedef struct {
    uint64_t offset;
    size_t length;
    pattern_type_t type;
    char *data;
    bool verified;
    time_t timestamp;
} find_result_t;

/* Pattern database entry */
typedef struct {
    const char *name;
    const char *pattern;
    size_t pattern_len;
    pattern_type_t type;
    uint32_t flags; /* 0x1=case_sensitive, 0x2=multiline, etc. */
} pattern_entry_t;

/* Global state for parser instance */
typedef struct {
    char *buffer;
    size_t buffer_size;
    size_t offset;
    find_result_t results[MAX_RESULTS];
    int result_count;
    bool eof_reached;
    uint64_t total_bytes_scanned;
} blob_parser_ctx_t;

/* Forward declarations */
static void parser_init(blob_parser_ctx_t *ctx, const char *filename);
static void parser_cleanup(blob_parser_ctx_t *ctx);
static int parser_scan(blob_parser_ctx_t *ctx);
static bool pattern_match(const char *haystack, size_t len, 
                         const char *needle, size_t needle_len,
                         uint32_t flags);
static void extract_pem_data(const blob_parser_ctx_t *ctx,
                            find_result_t *result,
                            const char **start, const char **end);
static bool is_weak_rsa(uint64_t modulus_bits);

/* Pattern database initialization */
static pattern_entry_t patterns[] = {
    /* PEM Private Keys */
    {"RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----\n", 35, PTYPE_PEM, 0},
    {"EC Private Key", "-----BEGIN EC PRIVATE KEY-----\n", 31, PTYPE_ECC, 0},
    {"DSS Private Key", "-----BEGIN DSA PRIVATE KEY-----\n", 32, PTYPE_PEM, 0},
    {"OpenSSH RSA", "-----BEGIN OPENSSH PRIVATE KEY-----\n", 40, PTYPE_PEM, 0},
    
    /* API Keys - Common prefixes */
    {"AWS Access Key", "AKIA[0-9A-Z]{16}", 18, PTYPE_API_KEY, 0x2},
    {"Google OAuth", "ya29\\.[0-9A-Za-z_.-]+", 14, PTYPE_API_KEY, 0x2},
    {"GitHub Token", "ghp_[0-9a-zA-Z]{36}", 18, PTYPE_API_KEY, 0x2},
    {"Stripe Secret", "sk_live_[0-9a-zA-Z]{24}", 25, PTYPE_API_KEY, 0x2},
    {"Twilio Auth", "SK[0-9a-fA-F]{32}", 18, PTYPE_API_KEY, 0x2},
    
    /* Default/Weak Credentials */
    {"Default Passwords", "(admin|root|user):([0-9a-zA-Z_@.]+)", 45, PTYPE_CREDENTIALS, 0x2},
    {"Common SSH Keys", "ssh-rsa [A-Za-z0-9+/]{100,}==", 38, PTYPE_PEM, 0x2},
    
    /* ECC Weakness */
    {"Small Curve NISTP256", "NISTP256[^0-9a-fA-F]{4}", 30, PTYPE_WEAK_CRYPTO, 0x2},
    {"Small Curve NISTP384", "NISTP384[^0-9a-fA-F]{4}", 30, PTYPE_WEAK_CRYPTO, 0x2},
};

#define NUM_PATTERNS (sizeof(patterns) / sizeof(pattern_entry_t))

/* Initialize parser context */
void parser_init(blob_parser_ctx_t *ctx, const char *filename) {
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->buffer_size = DEFAULT_BUFFER_SIZE;
    ctx->buffer = malloc(ctx->buffer_size);
    if (!ctx->buffer) {
        perror("malloc");
        exit(1);
    }
    
    /* Open and map the file */
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        free(ctx->buffer);
        exit(1);
    }
    
    /* Get file size */
    off_t fsize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    
    if (fsize < 0) {
        fprintf(stderr, "Failed to get file size: %s\n", strerror(errno));
        close(fd);
        free(ctx->buffer);
        exit(1);
    }
    
    /* Map file into memory */
    void *addr = mmap(NULL, fsize + 4096, PROT_READ | PROT_WRITE, 
                      MAP_PRIVATE | MAP_ANONYMOUS, fd, 0);
    close(fd);
    
    if (addr == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        free(ctx->buffer);
        exit(1);
    }
    
    /* Copy to our buffer for easier access */
    memcpy(ctx->buffer, addr, fsize);
    ctx->buffer_size = fsize;
    ctx->total_bytes_scanned = fsize;
    
    munmap(addr, fsize + 4096);
}

/* Cleanup parser resources */
void parser_cleanup(blob_parser_ctx_t *ctx) {
    if (ctx->buffer) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }
    ctx->result_count = 0;
    ctx->offset = 0;
    ctx->eof_reached = true;
}

/* Pattern matching with configurable flags */
static bool pattern_match(const char *haystack, size_t len, 
                         const char *needle, size_t needle_len,
                         uint32_t flags) {
    if (!haystack || !needle || needle_len == 0) return false;
    
    /* Case-insensitive by default */
    bool case_sensitive = (flags & 0x1);
    
    for (size_t i = 0; i <= len - needle_len; i++) {
        if (!case_sensitive) {
            if (memcmp(haystack + i, needle, needle_len) == 0) {
                return true;
            }
        } else {
            if (strncmp(haystack + i, needle, needle_len) == 0) {
                return true;
            }
        }
    }
    
    return false;
}

/* Extract PEM block boundaries */
static void extract_pem_data(const blob_parser_ctx_t *ctx,
                            find_result_t *result,
                            const char **start, const char **end) {
    /* Find matching end marker */
    const char *pem_enders[] = {
        "-----END RSA PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----", 
        "-----END DSA PRIVATE KEY-----",
        "-----END OPENSSH PRIVATE KEY-----",
        NULL
    };
    
    for (int i = 0; pem_enders[i]; i++) {
        const char *end_ptr = memmem(*start, (*end) - *start, 
                                    pem_enders[i], strlen(pem_enders[i]));
        if (end_ptr) {
            result->length = end_ptr + strlen(pem_enders[i]) - *start;
            result->data = malloc(result->length);
            memcpy(result->data, *start, result->length);
            return;
        }
    }
    
    /* Fallback: take until next PEM start or EOF */
    const char *next_start = memmem(*start, (*end) - *start, 
                                   "-----BEGIN", 9);
    if (next_start && next_start < *end) {
        result->length = next_start - *start;
    } else {
        result->length = (*end) - *start;
    }
    
    result->data = malloc(result->length);
    memcpy(result->data, *start, result->length);
}

/* Check if RSA modulus is weak */
static bool is_weak_rsa(uint64_t modulus_bits) {
    return modulus_bits < WEAK_RSA_THRESHOLD;
}

/* Scan the blob for patterns */
int parser_scan(blob_parser_ctx_t *ctx) {
    const char *start = ctx->buffer;
    const char *end = start + ctx->buffer_size;
    
    while (start < end && !ctx->eof_reached) {
        /* Check each pattern type */
        
        /* PEM headers */
        for (int i = 0; patterns[i].type == PTYPE_PEM || 
                 patterns[i].type == PTYPE_ECC; i++) {
            const char *match = memmem(start, end - start,
                                      patterns[i].pattern, 
                                      patterns[i].pattern_len);
            
            if (match) {
                find_result_t *result = &ctx->results[ctx->result_count];
                
                result->offset = match - ctx->buffer;
                result->type = patterns[i].type;
                result->verified = true;
                result->timestamp = time(NULL);
                
                /* Extract the full PEM block */
                extract_pem_data(ctx, result, &match, end);
                
                if (ctx->result_count < MAX_RESULTS) {
                    ctx->results[ctx->result_count++] = *result;
                } else {
                    fprintf(stderr, "Result limit reached\n");
                    break;
                }
            }
            
            /* Move past this match */
            start = match + patterns[i].pattern_len;
        }
        
        /* API keys - use regex-like matching for prefixes */
        const char *api_prefixes[] = {
            "AKIA",      /* AWS */
            "ya29\\.",   /* Google OAuth */
            "ghp_",      /* GitHub */
            "sk_live_",  /* Stripe */
            "SK[0-9a-fA-F]{32}", /* Twilio */
            NULL
        };
        
        for (int i = 0; api_prefixes[i]; i++) {
            const char *match = memmem(start, end - start,
                                      api_prefixes[i], strlen(api_prefixes[i]));
            
            if (match) {
                /* Extract reasonable length around match */
                size_t prefix_len = strlen(api_prefixes[i]);
                size_t max_len = 100;
                
                const char *end_match = memmem(match + prefix_len, 
                                              end - (match + prefix_len),
                                              " ", 1); /* Space after key */
                if (!end_match) {
                    end_match = end;
                } else {
                    end_match += strlen(" ");
                }
                
                size_t extracted_len = end_match - match;
                if (extracted_len > max_len) extracted_len = max_len;
                
                find_result_t *result = &ctx->results[ctx->result_count];
                result->offset = match - ctx->buffer;
                result->length = extracted_len;
                result->type = PTYPE_API_KEY;
                result->verified = true;
                result->timestamp = time(NULL);
                
                if (extracted_len > 0) {
                    result->data = malloc(extracted_len);
                    memcpy(result->data, match, extracted_len);
                    
                    if (ctx->result_count < MAX_RESULTS) {
                        ctx->results[ctx->result_count++] = *result;
                    } else {
                        break;
                    }
                }
                
                start = end_match;
            } else {
                /* Move forward */
                size_t prefix_len = strlen(api_prefixes[i]);
                if (prefix_len < 10) prefix_len = 10;
                start += prefix_len;
            }
        }
        
        /* Credentials - look for common patterns */
        const char *cred_patterns[] = {
            "admin:",
            "root:",
            "user:",
            NULL
        };
        
        for (int i = 0; cred_patterns[i]; i++) {
            const char *match = memmem(start, end - start,
                                      cred_patterns[i], strlen(cred_patterns[i]));
            
            if (match) {
                /* Extract credential block */
                size_t prefix_len = strlen(cred_patterns[i]);
                size_t max_len = 50;
                
                const char *end_match = memmem(match + prefix_len, 
                                              end - (match + prefix_len),
                                              "\n", 1);
                if (!end_match) {
                    end_match = end;
                } else {
                    end_match += strlen("\n");
                }
                
                size_t extracted_len = end_match - match;
                if (extracted_len > max_len) extracted_len = max_len;
                
                find_result_t *result = &ctx->results[ctx->result_count];
                result->offset = match - ctx->buffer;
                result->length = extracted_len;
                result->type = PTYPE_CREDENTIALS;
                result->verified = true;
                result->timestamp = time(NULL);
                
                if (extracted_len > 0) {
                    result->data = malloc(extracted_len);
                    memcpy(result->data, match, extracted_len);
                    
                    if (ctx->result_count < MAX_RESULTS) {
                        ctx->results[ctx->result_count++] = *result;
                    } else {
                        break;
                    }
                }
                
                start = end_match;
            } else {
                start += 16; /* Skip past potential match */
            }
        }
        
        /* Weak crypto - check for small RSA moduli */
        const char *weak_crypto_patterns[] = {
            "rsa02",    /* Small RSA exponent */
            "rsa03",
            "rsa05",
            NULL
        };
        
        for (int i = 0; weak_crypto_patterns[i]; i++) {
            const char *match = memmem(start, end - start,
                                      weak_crypto_patterns[i], 
                                      strlen(weak_crypto_patterns[i]));
            
            if (match) {
                find_result_t *result = &ctx->results[ctx->result_count];
                result->offset = match - ctx->buffer;
                result->length = 64; /* Approximate */
                result->type = PTYPE_WEAK_CRYPTO;
                result->verified = true;
                result->timestamp = time(NULL);
                
                if (result->length > 0) {
                    result->data = malloc(result->length);
                    memcpy(result->data, match, result->length);
                    
                    if (ctx->result_count < MAX_RESULTS) {
                        ctx->results[ctx->result_count++] = *result;
                    } else {
                        break;
                    }
                }
                
                start = match + 16;
            } else {
                start += 8;
            }
        }
        
        /* Check if we've scanned enough */
        if (start - ctx->buffer > ctx->buffer_size / 2) {
            break;
        }
    }
    
    ctx->eof_reached = true;
    return ctx->result_count;
}

/* Print results in a human-readable format */
static void print_results(const blob_parser_ctx_t *ctx, int verbose) {
    if (ctx->result_count == 0) {
        printf("No matches found.\n");
        return;
    }
    
    for (int i = 0; i