
#include <string.h>
#include <math.h>

#include <sgx_error.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>

#include "tksm_common.h"
#include "tksm_error.h"
#include "flas_common.h"
#include "flas_error.h"
#include "Enclave.h"

#include "Enclave_t.h"

#define CLIENT_CNT_MAX 0x100

// typedef float *agg_ctx;
typedef struct _agg_ctx_t {
    // uint64_t weight_cnt;
    // float weights[];
    state_t state;
} agg_ctx_t;

bool float_eq(const float a, const float b) {
    #define FLOAT_EQ_EPSILON 0.00001 
    return fabs(a - b) < FLOAT_EQ_EPSILON;
}

flas_status_t agg_init(
    uint64_t weight_cnt,
    agg_ctx_t **p_ctx
) {
    if (!weight_cnt || !p_ctx) {
        return FLAS_ERROR_INVALID_PARAMETER;
    }
    agg_ctx_t *p = static_cast<agg_ctx_t *>(calloc(1, sizeof(float) * weight_cnt + sizeof(agg_ctx_t)));
    if (p == nullptr) {
        return FLAS_ERROR_OUT_OF_MEMORY;
    }
    p->state.weight_cnt = weight_cnt;
    *p_ctx = p;
    return FLAS_SUCCESS;
}

flas_status_t agg_add_weight(
    agg_ctx_t *ctx,
    uint64_t weight_cnt,
    float ratio,
    float *weights
) { 
    if (!ctx || !weight_cnt || float_eq(ratio, 0.0f) || !weights) {
        return FLAS_ERROR_INVALID_PARAMETER;
    }

    if (ctx->state.weight_cnt != weight_cnt) {
        return FLAS_ERROR_UNEXPECTED;
    }

    for (uint64_t i = 0; i < weight_cnt; i++) {
        ctx->state.weights[i] += weights[i] * ratio;
    }
    return FLAS_SUCCESS;
}

void agg_finalize(agg_ctx_t *ctx) {
    free(ctx);
}

const float* get_weights(const agg_ctx_t *ctx) {
    return ctx->state.weights;
}

void log_weights(const agg_ctx_t *ctx) {
    const float* g_weights = get_weights(ctx);
    eprintf("[");
    for (uint64_t i = 0; i < ctx->state.weight_cnt; i++) {
        eprintf("%f, ", i, g_weights[i]);
    }
    eprintf("]\n");
}

tksm_status_t unseal_aes_key(
    const sgx_sealed_data_t *p_sealed_key,
    uint8_t key_out[TKSM_AES_KEY_SIZE]
) {
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint8_t aes_key_buffer[TKSM_AES_KEY_SIZE] = {0};
    uint32_t unsealed_aes_key_len = sizeof(aes_key_buffer);

    rc = sgx_unseal_data(
        p_sealed_key,
        nullptr, 0,
        aes_key_buffer, &unsealed_aes_key_len);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_unseal_data failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    if (unsealed_aes_key_len != TKSM_AES_KEY_SIZE) {
        LOG("unsealed_aes_key_len is not correct: %#lx\n", unsealed_aes_key_len);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    memcpy(key_out, aes_key_buffer, TKSM_AES_KEY_SIZE);

err_out:
    return ret;
}

uint64_t ecall_flas_agg(
    const uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len, 
    const enc_states_t* p_enc_bufs,
    tksm_aes_gcm_enc_t *p_out)
{
    flas_status_t ret = FLAS_SUCCESS;
    tksm_status_t tksm_rc = TKSM_SUCCESS;
    sgx_status_t sgx_rc = SGX_SUCCESS;
    agg_ctx_t *ctx = nullptr;
    uint8_t aes_key[TKSM_AES_KEY_SIZE] = {0};
    uint8_t *dec_buf = nullptr;
    tksm_aes_gcm_enc_t *p_ciphertext = nullptr;
    tksm_aes_gcm_enc_t *p_enc_state = nullptr;
    state_t *p_state = nullptr;
    float ratios[CLIENT_CNT_MAX];

    LOG("args: %p, %p, %d\n", p_sealed_sym_key, p_enc_bufs, sealed_sym_key_len);

    if (!p_sealed_sym_key || !p_enc_bufs || !p_enc_bufs->cnt) {
        return FLAS_ERROR_INVALID_PARAMETER;
    }

    const float DEFAULT_RATIO = 1.0f / static_cast<float>(p_enc_bufs->cnt);
    for(int i = 0; i < CLIENT_CNT_MAX; i ++) {
        ratios[i] = DEFAULT_RATIO;
    }

    tksm_rc = unseal_aes_key(
        reinterpret_cast<const sgx_sealed_data_t *>(p_sealed_sym_key),
        aes_key);
    if (tksm_rc != TKSM_SUCCESS) {
        LOG("unseal_aes_key failed: %#x\n", ret);
        ret = FLAS_ERROR_UNEXPECTED;
        goto err_out;
    }

    LOG("aes key:\n");
    hexdump(aes_key, TKSM_AES_KEY_SIZE);

    ret = agg_init(p_enc_bufs->weight_cnt, &ctx);
    if (ret != FLAS_SUCCESS) {
        LOG("agg_init failed: %#x\n", ret);
        ret = FLAS_ERROR_UNEXPECTED;
        goto err_out;
    }

    dec_buf = static_cast<uint8_t *>(malloc(sizeof(float) * p_enc_bufs->weight_cnt));
    if (dec_buf == nullptr) {
        LOG("malloc failed\n");
        ret = FLAS_ERROR_OUT_OF_MEMORY;
        goto err_free_agg_ctx;
    }

    for (uint64_t i = 0; i < p_enc_bufs->cnt; i++) {
        LOG("decrypt state: %lu\n", i);
        p_ciphertext = p_enc_bufs->ptrs[i];
        LOG("ciphertext:\n");
        hexdump(p_ciphertext, sizeof(tksm_aes_gcm_enc_t));
        LOG("ciphertext len: %#lx\n", p_ciphertext->data_size);

        sgx_rc = sgx_rijndael128GCM_decrypt(
            reinterpret_cast<sgx_aes_gcm_128bit_key_t *>(aes_key),
            p_ciphertext->data,
            static_cast<uint32_t>(p_ciphertext->data_size),
            dec_buf,
            p_ciphertext->iv,
            TKSM_AES_GCM_IV_SIZE,
            nullptr,
            0,
            reinterpret_cast<const sgx_aes_gcm_128bit_tag_t *>(p_ciphertext->mac));
        
        if (sgx_rc != SGX_SUCCESS) {
            LOG("sgx_rijndael128GCM_decrypt failed: %#x\n", sgx_rc);
            ret = FLAS_ERROR_UNEXPECTED;
            goto err_free_dec_buf;
        }

        p_state = reinterpret_cast<state_t *>(dec_buf);
        if (p_state->weight_cnt != p_enc_bufs->weight_cnt) {
            LOG("weight_cnt is not correct: %#lx, %#lx\n", p_state->weight_cnt, p_enc_bufs->weight_cnt);
            ret = FLAS_ERROR_UNEXPECTED;
            goto err_free_dec_buf;
        }

        ret = agg_add_weight(
            ctx,
            p_enc_bufs->weight_cnt,
            ratios[i],
            p_state->weights);
        if (ret != FLAS_SUCCESS) {
            LOG("agg_add_weight failed: %#x\n", ret);
            ret = FLAS_ERROR_UNEXPECTED;
            goto err_free_dec_buf;
        }
    }

    // LOG("print weights\n");
    // log_weights(ctx);

    // Encrypt the aggregated weights
    p_enc_state = reinterpret_cast<tksm_aes_gcm_enc_t *>(p_out);
    memcpy(p_enc_state->iv, "greedisgood.", TKSM_AES_GCM_IV_SIZE);

    sgx_rc = sgx_rijndael128GCM_encrypt(
        reinterpret_cast<sgx_aes_gcm_128bit_key_t *>(aes_key),
        reinterpret_cast<const uint8_t *>(&ctx->state),
        static_cast<uint32_t>(sizeof(ctx->state) + sizeof(float) * ctx->state.weight_cnt),
        p_enc_state->data,
        p_enc_state->iv,
        TKSM_AES_GCM_IV_SIZE,
        nullptr,
        0,
        reinterpret_cast<sgx_aes_gcm_128bit_tag_t *>(p_enc_state->mac));
    
    if (sgx_rc != SGX_SUCCESS) {
        LOG("sgx_rijndael128GCM_encrypt failed: %#x\n", sgx_rc);
        ret = FLAS_ERROR_UNEXPECTED;
        goto err_free_dec_buf;
    }
    p_enc_state->data_size = static_cast<uint32_t>(sizeof(ctx->state) + sizeof(float) * ctx->state.weight_cnt);



err_free_dec_buf:
    free(dec_buf);
err_free_agg_ctx:
    agg_finalize(ctx);
err_out:
    return ret;
}
