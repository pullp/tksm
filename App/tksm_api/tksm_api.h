#ifndef _TKSM_API_H_
#define _TKSM_API_H_

#include <inttypes.h>
#include <stdio.h>

#include <sgx_error.h>      /* sgx_status_t */
#include <sgx_eid.h>    /* sgx_enclave_id_t */

#include "tksm_common.h"
#include "tksm_error.h"

#define LOG(...) do { printf("[u][%s:%d:%s] ", __FILE__, __LINE__, __FUNCTION__);  printf(__VA_ARGS__); } while (0)

tksm_status_t tksm_gen_asym_key(
    const sgx_enclave_id_t eid,
    uint8_t **pp_pub_key, uint64_t *p_pub_key_len,
    uint8_t **pp_sealed_priv_key, uint64_t *p_sealed_priv_key_len,
    uint8_t **pp_quote_pub_key, uint64_t *p_quote_pub_key_len
);


tksm_status_t tksm_gen_sym_key(
    const sgx_enclave_id_t eid,
    uint8_t **pp_sealed_sym_key, uint64_t *p_sealed_sym_key_len,
    uint8_t **pp_quote_sym_key, uint64_t *p_quote_sym_key_len
);

tksm_status_t tksm_export_sym_key(
    const sgx_enclave_id_t eid,
    const uint8_t* p_sealed_sym_key, const uint64_t sealed_sym_key_len,
    const uint8_t* p_pub_key, const uint64_t pub_key_len,
    const uint8_t* p_quote_pub_key, const uint64_t quote_pub_key_len,

    uint8_t **pp_enc_sym_key, uint64_t *p_enc_sym_key_len
);

tksm_status_t tksm_import_sym_key(
    const sgx_enclave_id_t eid,
    const uint8_t* p_sealed_priv_key, const uint64_t sealed_priv_key_len,
    const uint8_t* p_enc_sym_key, const uint64_t enc_sym_key_len,
    const uint8_t* p_quote_sym_key, const uint64_t quote_sym_key_len,

    uint8_t **pp_sealed_sym_key, uint64_t *p_sealed_sym_key_len
);

#endif /* _TKSM_API_H_ */