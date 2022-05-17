#include <stdio.h>
#include <string.h>

#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_quote_3.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_uae_launch.h>

#include <sgx_error.h>

#include "tksm_api.h"

#include "Enclave_u.h"

static void hexdump(const void *_p, uint64_t n)
{
    const int byte_per_line = 16;
    const uint8_t *p = (const uint8_t*)_p;
    for (uint64_t i = 0; i < n; i += byte_per_line) {
        printf("%08lx: ", i);
        for (int j = 0; j < byte_per_line && i + j < n; j++) {
            printf("%02x ", p[i + j]);
        }
        printf("\n");
    }
}

tksm_status_t tksm_gen_asym_key(
    const sgx_enclave_id_t eid,
    uint8_t **pp_pub_key, uint64_t *p_pub_key_len,
    uint8_t **pp_sealed_priv_key, uint64_t *p_sealed_priv_key_len,
    uint8_t **pp_quote_pub_key, uint64_t *p_quote_pub_key_len
) {
    tksm_status_t ret = TKSM_SUCCESS;
    uint64_t ecall_ret = TKSM_SUCCESS;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote = nullptr;
    sgx_target_info_t qe_target_info;
    sgx_report_t report;

    uint8_t* p_pub_key = nullptr;
    uint8_t* p_sealed_priv_key = nullptr;
    uint64_t sealed_priv_key_len = 0;
    const uint64_t pub_key_len = TKSM_RSA_KEY_SIZE;
    

    uint8_t pub_key_buffer[TKSM_RSA_KEY_SIZE] = {0};
    uint8_t sealed_priv_key_buffer[TKSM_SEALED_RSA_KEY_SIZE] = {0};

    if (!pp_pub_key || !p_pub_key_len || !pp_sealed_priv_key || !p_sealed_priv_key_len || !pp_quote_pub_key || !p_quote_pub_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }


    // Get QE's target info
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get QE's target info: %#x\n", qe3_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // Create the report for the app enclave
    sgx_ret = ecall_tksm_gen_asym_key(
        eid, &ecall_ret,
        &qe_target_info,
        pub_key_buffer, sizeof(pub_key_buffer),
        sealed_priv_key_buffer, sizeof(sealed_priv_key_buffer),
        &report
    );
    if (sgx_ret != SGX_SUCCESS || ecall_ret != TKSM_SUCCESS) {
        LOG("Failed to create the report: %#x, %#lx\n", sgx_ret, ecall_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // LOG("pub_key_buffer:\n");
    // hexdump(pub_key_buffer, sizeof(pub_key_buffer));

    // Get quote's size
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get QE's size: %#x\n", qe3_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    p_quote = static_cast<uint8_t*>(malloc(quote_size));
    if (p_quote == NULL) {
        LOG("Failed to allocate memory for quote\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }

    LOG("quote_size: %d\n", quote_size);

    // Get quote
    qe3_ret = sgx_qe_get_quote(&report,
        quote_size,
        p_quote);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get QE's quote: %#x\n", qe3_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_quote_buffer;
    }

    // Copy to outupt
    p_pub_key = static_cast<uint8_t*>(malloc(TKSM_RSA_KEY_SIZE));
    if (p_pub_key == NULL) {
        LOG("Failed to allocate memory for pub key\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_free_quote_buffer;
    }
    memcpy(p_pub_key, pub_key_buffer, pub_key_len);

    sealed_priv_key_len = TKSM_SEALED_RSA_KEY_SIZE;
    p_sealed_priv_key = static_cast<uint8_t*>(malloc(sealed_priv_key_len));
    if (p_sealed_priv_key == NULL) {
        LOG("Failed to allocate memory for sealed priv key\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_free_pub_key;
    }
    memcpy(p_sealed_priv_key, sealed_priv_key_buffer, sealed_priv_key_len);

    *pp_pub_key = p_pub_key;
    *p_pub_key_len = pub_key_len;
    *pp_sealed_priv_key = p_sealed_priv_key;
    *p_sealed_priv_key_len = sealed_priv_key_len;
    *pp_quote_pub_key = p_quote;
    *p_quote_pub_key_len = quote_size;

    return ret;

// err_free_sealed_priv_key:
    free(p_sealed_priv_key);
err_free_pub_key:
    free(p_pub_key);
err_free_quote_buffer:
    free(p_quote);
err_out:
    return ret;
}


tksm_status_t tksm_gen_sym_key(
    const sgx_enclave_id_t eid,
    uint8_t **pp_sealed_sym_key, uint64_t *p_sealed_sym_key_len,
    uint8_t **pp_quote_sym_key, uint64_t *p_quote_sym_key_len
) {
    tksm_status_t ret = TKSM_SUCCESS;
    uint64_t ecall_ret = TKSM_SUCCESS;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote = nullptr;
    sgx_target_info_t qe_target_info;
    sgx_report_t report;

    uint8_t *p_sealed_sym_key = nullptr;
    uint64_t sealed_sym_key_len = 0;

    uint8_t sealed_sym_key_buffer[TKSM_SEALED_SYM_KEY_SIZE] = {0};

    if (!pp_sealed_sym_key || !p_sealed_sym_key_len || !pp_quote_sym_key || !p_quote_sym_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    // Get QE's target info
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get QE's target info: %#x\n", qe3_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // Create the report for the app enclave
    sgx_ret = ecall_tksm_gen_sym_key(
        eid, &ecall_ret,
        &qe_target_info,
        sealed_sym_key_buffer, sizeof(sealed_sym_key_buffer),
        &report);
    if (sgx_ret != SGX_SUCCESS || ecall_ret != TKSM_SUCCESS) {
        LOG("Failed to create the report: %#x, %#lx\n", sgx_ret, ecall_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // Get quote's size
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get QE's size: %#x\n", qe3_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    p_quote = static_cast<uint8_t*>(malloc(quote_size));
    if (p_quote == NULL) {
        LOG("Failed to allocate memory for quote\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }


    // Get quote
    qe3_ret = sgx_qe_get_quote(&report,
        quote_size,
        p_quote);
    if (qe3_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get QE's quote: %#x\n", qe3_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_quote_buffer;
    }

    // Copy to outupt
    sealed_sym_key_len = TKSM_SEALED_SYM_KEY_SIZE;
    p_sealed_sym_key = static_cast<uint8_t*>(malloc(sealed_sym_key_len));
    if (p_sealed_sym_key == NULL) {
        LOG("Failed to allocate memory for sealed sym key\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_free_quote_buffer;
    }
    memcpy(p_sealed_sym_key, sealed_sym_key_buffer, sealed_sym_key_len);

    *pp_sealed_sym_key = p_sealed_sym_key;
    *p_sealed_sym_key_len = sealed_sym_key_len;
    *pp_quote_sym_key = p_quote;
    *p_quote_sym_key_len = quote_size;

    return ret;
   
// err_free_sealed_sym_key:
    free(p_sealed_sym_key);
err_free_quote_buffer:
    free(p_quote);
err_out:
    return ret;
}

tksm_status_t tksm_export_sym_key(
    const sgx_enclave_id_t eid,
    const uint8_t* p_sealed_sym_key, const uint64_t sealed_sym_key_len,
    const uint8_t* p_pub_key, const uint64_t pub_key_len,
    const uint8_t* p_quote_pub_key, const uint64_t quote_pub_key_len,

    uint8_t **pp_enc_sym_key, uint64_t *p_enc_sym_key_len
) {
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint64_t ecall_rc = TKSM_SUCCESS;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    // sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    sgx_ql_qe_report_info_t qve_report_info;
    // unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    uint32_t collateral_expiration_status = 1;
    uint8_t _enc_sym_key_buffer[TKSM_ENC_SYM_KEY_SIZE + sizeof(buf_t)] = { 0 };
    buf_t *enc_sym_key_buffer = (buf_t *)_enc_sym_key_buffer;
    const uint64_t enc_sym_key_buffer_size = sizeof(_enc_sym_key_buffer);
    uint8_t *p_enc_sym_key = nullptr;
    uint64_t enc_sym_key_len = 0;

    if (!p_sealed_sym_key || !p_pub_key || !p_quote_pub_key || !pp_enc_sym_key || !p_enc_sym_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    // Get tkms Enclave's target info
    rc = ecall_tksm_get_target_info(
        eid, &ecall_rc,
        &qve_report_info.app_enclave_target_info);
    if (rc != SGX_SUCCESS || ecall_rc != TKSM_SUCCESS) {
        LOG("Failed to get tkms Enclave's target info: %#x, %#lx\n", rc, ecall_rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    //call DCAP quote verify library to set QvE loading policy
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (dcap_ret != SGX_QL_SUCCESS)  {
        LOG("sgx_qv_set_enclave_load_policy success\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get quote supplemental data size: %#x\n", dcap_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    else if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t)) {
        LOG("Warning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    else {
        p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    }

    current_time = time(NULL);

    dcap_ret = sgx_qv_verify_quote(
        p_quote_pub_key, static_cast<uint32_t>(quote_pub_key_len),
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        &qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
    if (dcap_ret != SGX_QL_SUCCESS) {
        LOG("Failed to verify quote: %#x\n", dcap_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_supplemental_data;
    }

    // Export sym key
    rc = ecall_tksm_export_sym_key(
        eid, &ecall_rc,
        p_sealed_sym_key, sealed_sym_key_len,
        p_pub_key, pub_key_len,
        p_quote_pub_key, quote_pub_key_len,
        &qve_report_info,
        current_time,
        collateral_expiration_status,
        quote_verification_result,
        p_supplemental_data, supplemental_data_size,
        enc_sym_key_buffer, enc_sym_key_buffer_size);
    if (rc != SGX_SUCCESS || ecall_rc != TKSM_SUCCESS) {
        LOG("Failed to export sym key: %#x, %#lx\n", rc, ecall_rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_supplemental_data;
    }
    enc_sym_key_len = enc_sym_key_buffer->size;
    p_enc_sym_key = reinterpret_cast<uint8_t*>(malloc(enc_sym_key_len));
    if (p_enc_sym_key == NULL) {
        LOG("Failed to allocate memory for enc_sym_key\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_supplemental_data;
    }
    memcpy(p_enc_sym_key, enc_sym_key_buffer->data, enc_sym_key_len);
    *pp_enc_sym_key = p_enc_sym_key;
    *p_enc_sym_key_len = enc_sym_key_len;

    free(p_supplemental_data);
    return ret;
    
// err_free_enc_sym_key:
    free(p_enc_sym_key);
err_free_supplemental_data:
    free(p_supplemental_data);
err_out:
    return ret;
}

tksm_status_t tksm_import_sym_key(
    const sgx_enclave_id_t eid,
    const uint8_t* p_sealed_priv_key, const uint64_t sealed_priv_key_len,
    const uint8_t* p_enc_sym_key, const uint64_t enc_sym_key_len,
    const uint8_t* p_quote_sym_key, const uint64_t quote_sym_key_len,

    uint8_t **pp_sealed_sym_key, uint64_t *p_sealed_sym_key_len
) {
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint64_t ecall_rc = TKSM_SUCCESS;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    // sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    sgx_ql_qe_report_info_t qve_report_info;
    // unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    uint32_t collateral_expiration_status = 1;

    uint8_t *p_sealed_sym_key = nullptr;
    uint64_t sealed_sym_key_len = 0;

    uint8_t sealed_sym_key_buffer[TKSM_SEALED_SYM_KEY_SIZE] = {0};


    // Get tkms Enclave's target info
    rc = ecall_tksm_get_target_info(
        eid, &ecall_rc,
        &qve_report_info.app_enclave_target_info);
    if (rc != SGX_SUCCESS || ecall_rc != TKSM_SUCCESS) {
        LOG("Failed to get tkms Enclave's target info: %#x, %#lx\n", rc, ecall_rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    //call DCAP quote verify library to set QvE loading policy
    dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (dcap_ret != SGX_QL_SUCCESS)  {
        LOG("sgx_qv_set_enclave_load_policy success\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }    

    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret != SGX_QL_SUCCESS) {
        LOG("Failed to get quote supplemental data size: %#x\n", dcap_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    else if (supplemental_data_size != sizeof(sgx_ql_qv_supplemental_t)) {
        LOG("Warning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    else {
        p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    }

    current_time = time(NULL);

    dcap_ret = sgx_qv_verify_quote(
        p_quote_sym_key, static_cast<uint32_t>(quote_sym_key_len),
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        &qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
    if (dcap_ret != SGX_QL_SUCCESS) {
        LOG("Failed to verify quote: %#x\n", dcap_ret);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_supplemental_data;
    }

    rc = ecall_tksm_import_sym_key(
        eid, &ecall_rc,
        p_sealed_priv_key, sealed_priv_key_len,
        p_enc_sym_key, enc_sym_key_len,
        p_quote_sym_key, quote_sym_key_len,
        &qve_report_info,
        current_time,
        collateral_expiration_status,
        quote_verification_result,
        p_supplemental_data, supplemental_data_size,
        sealed_sym_key_buffer, sizeof(sealed_sym_key_buffer));
    if (rc != SGX_SUCCESS || ecall_rc != TKSM_SUCCESS) {
        LOG("Failed to import sym key: %#x, %#lx\n", rc, ecall_rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_supplemental_data;
    }

    sealed_sym_key_len = TKSM_SEALED_SYM_KEY_SIZE;
    p_sealed_sym_key = static_cast<uint8_t*>(malloc(sealed_sym_key_len));
    if (p_sealed_sym_key == NULL) {
        LOG("Failed to allocate memory for sealed sym key\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_free_supplemental_data;
    }
    memcpy(p_sealed_sym_key, sealed_sym_key_buffer, sealed_sym_key_len);
    
    *pp_sealed_sym_key = p_sealed_sym_key;
    *p_sealed_sym_key_len = sealed_sym_key_len;
    return ret;

err_free_supplemental_data:
    free(p_supplemental_data);
err_out:
    return ret;
}


tksm_status_t tksm_encrypt(
    const sgx_enclave_id_t eid,
    const uint8_t* p_sealed_sym_key, const uint64_t sealed_sym_key_len,
    const uint8_t* p_plaintext, const uint64_t plaintext_len,
    uint8_t** pp_ciphertext, uint64_t* p_ciphertext_len
) {
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint64_t ecall_rc = TKSM_SUCCESS;

    uint64_t ciphertext_len = plaintext_len + sizeof(tksm_aes_gcm_enc_t);
    tksm_aes_gcm_enc_t* p_ciphertext = static_cast<tksm_aes_gcm_enc_t*>(malloc(ciphertext_len));
    if (p_ciphertext == NULL) {
        LOG("Failed to allocate memory for ciphertext\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }

    rc = ecall_tksm_encrypt(
        eid, &ecall_rc,
        p_sealed_sym_key, sealed_sym_key_len,
        p_plaintext, plaintext_len,
        p_ciphertext, ciphertext_len);
    if (rc != SGX_SUCCESS || ecall_rc != TKSM_SUCCESS) {
        LOG("Failed to encrypt: %#x, %#lx\n", rc, ecall_rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_ciphertext;
    }

    *pp_ciphertext = reinterpret_cast<uint8_t *>(p_ciphertext);
    *p_ciphertext_len = ciphertext_len;
    return ret;

err_free_ciphertext:
    free(p_ciphertext);
err_out:
    return ret;
}

tksm_status_t tksm_decrypt(
    const sgx_enclave_id_t eid,
    const uint8_t* p_sealed_sym_key, const uint64_t sealed_sym_key_len,
    const uint8_t* p_ciphertext, const uint64_t ciphertext_len,
    uint8_t** pp_plaintext, uint64_t* p_plaintext_len
) {
    hexdump(nullptr, 0);
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint64_t ecall_rc = TKSM_SUCCESS;

    uint64_t plaintext_len = ciphertext_len - sizeof(tksm_aes_gcm_enc_t);
    uint8_t* p_plaintext = static_cast<uint8_t*>(malloc(plaintext_len));
    if (p_plaintext == NULL) {
        LOG("Failed to allocate memory for plaintext\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }

    // LOG("before ecall dec_plain_text:\n");
    // hexdump(p_plaintext, 0x40);

    rc = ecall_tksm_decrypt(
        eid, &ecall_rc,
        p_sealed_sym_key, sealed_sym_key_len,
        reinterpret_cast<const tksm_aes_gcm_enc_t *>(p_ciphertext), ciphertext_len,
        p_plaintext, plaintext_len);

    if (rc != SGX_SUCCESS || ecall_rc != TKSM_SUCCESS) {
        LOG("Failed to decrypt: %#x, %#lx\n", rc, ecall_rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_plaintext;
    }

    // LOG("after ecall dec_plain_text:\n");
    // hexdump(p_plaintext, 0x40);


    *pp_plaintext = p_plaintext;
    *p_plaintext_len = plaintext_len;
    return ret;


err_free_plaintext:
    free(p_plaintext);
err_out:
    return ret;
}