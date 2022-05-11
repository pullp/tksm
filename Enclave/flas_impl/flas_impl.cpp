#include "flas_common.h"
#include "flas_error.h"

#include "Enclave_t.h"

// typedef float *agg_ctx;

// flas_status_t agg_init(
//     uint64_t weight_cnt,
//     agg_ctx **p_ctx;
// ) {
//     if (!weight_cnt || !p_ctx) {
//         return FLAS_ERROR_INVALID_PARAMETER;
//     }
//     float *p = static_cast<float *>(calloc(sizeof(float), weight_cnt));
//     if (p == nullptr) {
//         return FLAS_ERROR_OUT_OF_MEMORY;
//     }
//     *p_ctx = p;
//     return FLAS_SUCCESS;
// }

// flas_status_t agg_add_weight(
//     agg_ctx *ctx,
//     uint64_t weight_cnt,
//     uint64_t sample_cnt,
//     float *weights
// ) { 
//     if (!ctx || !weight_cnt || !sample_cnt || !weights) {
//         return FLAS_ERROR_INVALID_PARAMETER;
//     }

//     for (uint64_t i = 0; i < weight_cnt; i++) {
//         ctx[i] += weights[i] * sample_cnt;
//     }
//     return FLAS_SUCCESS;
// }

// void agg_finalize(
//     agg_ctx *ctx
// ) {
//     free(ctx);
// }

// const float* get_weights(
//     agg_ctx *ctx,
// ) {
//     return ctx;
// }

uint64_t ecall_flas_agg(
    const uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len, 
    const uint8_t* p_plaintext, uint64_t plaintext_len, tksm_aes_gcm_enc_t* p_ciphertext, uint64_t ciphertext_len) {

    }
