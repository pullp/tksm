#ifndef _FLAS_COMMON_H_
#define _FLAS_COMMON_H_
#include <inttypes.h>

#include "tksm_common.h"

#define UNUSED(x) (void)(x)

typedef struct _enc_states_t {
    uint64_t cnt;
    uint64_t weight_cnt;
    tksm_aes_gcm_enc_t *ptrs[];
} enc_states_t;

typedef struct _ratios_t {
    uint64_t cnt;
    float ratios[];
} ratios_t;


// remember to change python pack/unpack code if you change this
typedef struct _state_t {
    uint64_t weight_cnt;
    // uint64_t sample_cnt;
    float weights[];
} state_t;



#endif // _FLAS_COMMON_H_