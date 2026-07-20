#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_LINE 65536
#define MAX_RESULTS 1024
#define DEFAULT_BUFFER_SIZE 8192

/* Result structure */
typedef struct {
    char *file_path;
    char *match_type;
    char *context;      /* Surrounding bytes for context */
    uint64_t offset;
} ScanResult;

static int result_count = 0;
static ScanResult results[MAX_RESULTS];

/* Forward declarations */
static void add_result(const char *file, const char *type, 
                       const char *context, uint64_t off);
static bool is_base64_char(int c);
static bool is_hex_string(const unsigned char *buf, size_t len);
static int find_jwt_token(const unsigned char *data, size_t len, 
                          uint64_t *pos, size_t *match_len);
static int find_aws_access_key(const unsigned char *data, size_t len,
                               uint64_t *pos, size_t *match_len);
static int find_gcp_service_account(const unsigned char *data, size_t len,
                                   uint64_t *pos, size_t *match_len);
static int find_azure_spn(const unsigned char *data, size_t len,
                         uint64_t *pos, size_t *match_len);

/* Check if character is valid base64 */
static inline bool is_base64_char(int c) {
    return (c >= 'A' && c <= 'Z') || 
           (c >= 'a' && c <= 'z') || 
           (c >= '0' && c <= '9') || 
           c == '+' || c == '/' || c == '=';
}

/* Check if string looks like hex-encoded data */
static inline bool is_hex_string(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int c = buf[i];
        if (!isalnum(c) && c != ':' && c != '-' && c != '_' && c != '.') {
            return false;
        }
    }
    /* Must be even length and at least 128 bits */
    return (len % 2 == 0) && len >= 32;
}

/* Check if string is valid base64 */
static inline bool is_valid_base64(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        int c = buf[i];
        if (!is_base64_char(c)) return false;
    }
    /* Allow padding */
    while (len > 0 && buf[len - 1] == '=') len--;
    /* Must be multiple of 4 after removing padding */
    return (len % 4) == 0 && len >= 88; /* At least 704 bits */
}

/* Extract JWT components from string */
static int find_jwt_token(const unsigned char *data, size_t len, 
                          uint64_t *pos, size_t *match_len) {
    const char *jwt_pattern = "eyJ";
    
    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i] == 'e' && data[i+1] == 'y' && data[i+2] == 'J') {
            /* Found JWT header start, check reasonable length */
            size_t remaining = len - i;
            if (remaining >= 50) {
                *pos = i;
                *match_len = remaining;
                return 1;
            }
        }
    }
    return 0;
}

/* Check for AWS access key pattern */
static int find_aws_access_key(const unsigned char *data, size_t len,
                               uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "AKIA",           /* Standard IAM user */
        "ASIA",           /* Temporary session */
        "AIDA",           /* Service role */
        "ABIA",           /* Custom service */
        "ACCA",           /* Another custom */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                /* Check followed by alphanumeric chars */
                size_t remaining = len - i - plen;
                if (remaining >= 16 && isalnum((int)data[i+plen])) {
                    *pos = i;
                    *match_len = plen + 16;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Check for GCP service account key */
static int find_gcp_service_account(const unsigned char *data, size_t len,
                                   uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 512; /* Read a bit more */
                return 1;
            }
        }
    }
    
    /* Also check for "-----BEGIN PRIVATE KEY-----" (PKCS#8 format) */
    if (len >= 30 && 
        data[0] == '-' && data[1] == '-' && data[2] == '-' && 
        data[3] == 'B' && data[4] == 'E' && data[5] == 'G' && 
        data[6] == 'I' && data[7] == 'N' && data[8] == ' ' &&
        data[9] == 'P' && data[10] == 'R' && data[11] == 'I' && 
        data[12] == 'V' && data[13] == 'A' && data[14] == 'T' && 
        data[15] == 'E' && data[16] == ' ' && data[17] == 'K' && 
        data[18] == 'E' && data[19] == 'Y') {
        *pos = 0;
        *match_len = 30 + 512;
        return 1;
    }
    
    return 0;
}

/* Check for Azure service principal */
static int find_azure_spn(const unsigned char *data, size_t len,
                         uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "ClientSecret",
        "SpnKey",
        "AzureAd",
        "ms_app_id",
        "tenant_id",
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 64;
                return 1;
            }
        }
    }
    
    /* Check for common Azure app registration format */
    if (len >= 25 && 
        data[0] == 'C' && data[1] == 'l' && data[2] == 'i' && 
        data[3] == 'e' && data[4] == 'n' && data[5] == 't' &&
        data[6] == 'S' && data[7] == 'e' && data[8] == 'c' && 
        data[9] == 'r' && data[10] == 'e' && data[11] == 'T') {
        *pos = 0;
        *match_len = 25 + 64;
        return 1;
    }
    
    return 0;
}

/* Check for GitHub personal access token */
static int find_github_token(const unsigned char *data, size_t len,
                            uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "ghp_",            /* Personal access token v1 */
        "github_pat_",     /* Personal access token v2 */
        "xoxb-",           /* Slack bot (often used with GitHub) */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 32;
                return 1;
            }
        }
    }
    
    /* Check for classic GitHub token format */
    if (len >= 48 && 
        data[0] == 'g' && data[1] == 'h' && data[2] == 'p' && 
        data[3] == '_' && isalnum((int)data[4]) && 
        isalnum((int)data[5])) {
        *pos = 0;
        *match_len = 48;
        return 1;
    }
    
    return 0;
}

/* Check for Slack token */
static int find_slack_token(const unsigned char *data, size_t len,
                           uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "xoxb-",           /* Bot token */
        "xoxp-",           /* Personal access token */
        "xoxa-",           /* Admin token */
        "xoxr-",           /* Robot token */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 32;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for Google OAuth client */
static int find_google_oauth(const unsigned char *data, size_t len,
                            uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "GoogleOAuthClient",
        "google-oauth-client",
        "GOOGLE_CLIENT_ID",
        "CLIENT_ID",
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 64;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for Stripe secret key */
static int find_stripe_key(const unsigned char *data, size_t len,
                          uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "sk_live_",         /* Live secret key */
        "sk_test_",         /* Test secret key */
        "rk_live_",         /* Live publishable key */
        "pk_live_",         /* Live public key */
        "pk_test_",         /* Test public key */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 32;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for Twilio API key */
static int find_twilio_key(const unsigned char *data, size_t len,
                          uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "SK",               /* Account SID prefix */
        "AC",               /* Another account format */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 32;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for SendGrid API key */
static int find_sendgrid_key(const unsigned char *data, size_t len,
                            uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "SG.",              /* SendGrid API key prefix */
        "SendGrid",         /* Service name */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 32;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for Heroku API key */
static int find_heroku_key(const unsigned char *data, size_t len,
                          uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "heroku_api_",      /* Heroku API token */
        "HEROKU_API_KEY",   /* Environment variable style */
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 32;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for Twilio webhook */
static int find_twilio_webhook(const unsigned char *data, size_t len,
                              uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "twilio.webhook",
        "TWILIO_WEBHOOK",
        "webhook_url:",
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 64;
                return 1;
            }
        }
    }
    
    return 0;
}

/* Check for SendGrid webhook */
static int find_sendgrid_webhook(const unsigned char *data, size_t len,
                                uint64_t *pos, size_t *match_len) {
    const char *patterns[] = {
        "sendgrid.webhook",
        "SENDGRID_WEBHOOK",
        "webhook_url:",
    };
    
    for (size_t p = 0; p < sizeof(patterns)/sizeof(patterns[0]); p++) {
        size_t plen = strlen(patterns[p]);
        
        for (size_t i = 0; i + plen <= len; i++) {
            if (memcmp(data + i, patterns[p], plen) == 0) {
                *pos = i;
                *match_len = plen + 64;
                return 1;
            }