
#include <stdio.h>
#include <string.h>
#include <math.h>

#include <chrono>
#include <iostream>

#include "tksm_common.h"
#include "tksm_error.h"
#include "flas_common.h"
#include "flas_error.h"

#define LOG printf

// using std::chrono;
// 
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


const uint64_t weight_cnt = 20000;
float weights[weight_cnt];

int test_agg(uint64_t num_users) {
    uint64_t ret = 0;
    // float weights[weight_cnt];

    auto start = std::chrono::high_resolution_clock::now();

    agg_ctx_t *ctx = nullptr;

    ret = agg_init(weight_cnt, &ctx);
    if (ret != FLAS_SUCCESS) {
        LOG("agg_init failed: %#x\n", ret);
        exit(-1);
    }

    for (uint64_t i = 0; i < num_users; i ++) {
        ret = agg_add_weight(ctx, weight_cnt, 1.0f, weights);
        if (ret != FLAS_SUCCESS) {
            LOG("agg_add_weight failed %d: %#x\n", i, ret);
            exit(-1);
        }
    }
    agg_finalize(ctx);

    auto stop = std::chrono::high_resolution_clock::now();
    std::cout 
        // << "[!!!] do_agg duration: microseconds: " 
        << num_users
        << " : "
        << std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count() 
        << std::endl;
    return 0;
}

int main() {
    // test_agg(1);
    for (int i = 10; i <= 100; i += 10) {
        test_agg(i);
    }
}