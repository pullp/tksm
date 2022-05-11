#ifndef _FLAS_COMMON_H_
#define _FLAS_COMMON_H_
#include <inttypes.h>

#include "tksm_common.h"

#define UNUSED(x) (void)(x)

typedef struct _enc_bufs_t {
    uint64_t cnt;
    tksm_aes_gcm_enc_t *ptrs[];
} enc_bufs_t;


typedef struct _weight_t {
    uint64_t weight_cnt;
    uint64_t sample_cnt;
    float weights[];
}

#endif // _FLAS_COMMON_H_