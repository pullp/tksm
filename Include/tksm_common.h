#ifndef _TKMS_COMMON_H_
#define _TKMS_COMMON_H_

#define UNUSED(x) (void)(x)

#define TKSM_RSA_KEY_SIZE                   (3072 / 8)
#define TKSM_RSA_DEFAULT_EXP                  65537
#define TKSM_RSA_EXP_SIZE             4
#define TKSM_AES_KEY_SIZE                   (128 / 8)
#define TKSM_SEALED_SYM_KEY_SIZE            0x280
#define TKSM_SEALED_RSA_KEY_SIZE            0x580
#define TKSM_QUOTE_SIZE                     0x1200
#define TKSM_ENC_SYM_KEY_SIZE               TKSM_RSA_KEY_SIZE

#define QVE_ISVSVN_THRESHOLD_DEFAULT        5

typedef struct _tksm_rsa_priv_key_t {
    uint8_t n[TKSM_RSA_KEY_SIZE];
    uint8_t d[TKSM_RSA_KEY_SIZE];
} tksm_rsa_priv_key_t;

typedef struct _tksm_rsa_pub_key_t {
    uint8_t n[TKSM_RSA_KEY_SIZE];
} tksm_rsa_pub_key_t;

typedef struct _buf_t {
    uint64_t size;
    uint8_t data[];
} buf_t;

#endif // _TKMS_COMMON_H_