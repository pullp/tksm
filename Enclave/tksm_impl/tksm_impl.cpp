
#include <string.h>

#include <sgx_error.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <sgx_dcap_tvl.h> // sgx_tvl_verify_qve_report_and_identity
#include <sgx_quote_3.h>

#include "Enclave.h"
#include "tksm_common.h"
#include "tksm_error.h"

#include "Enclave_t.h"

void test() {
    sgx_sealed_data_t sealed_data;
    LOG("sgx_sealed_data_t: %#x\n", sizeof(sealed_data));
    LOG("sgx_sealed_data_t: %#x\n", sizeof(sealed_data.aes_data.payload_size));
    size_t of1, of2, of3;
    of1 = offsetof(sgx_sealed_data_t, plain_text_offset);
    of2 = offsetof(sgx_sealed_data_t, reserved);
    of3 = offsetof(sgx_sealed_data_t, aes_data);
    LOG("%#x, %#x, %#x\n", of1, of2, of3);
    // LOG("%p - %p\n", &sealed_data.aes_data.payload, &sealed_data);
}

uint64_t ecall_tksm_get_target_info(sgx_target_info_t* target_info) {
    return sgx_self_target(target_info);
}

uint64_t ecall_tksm_gen_asym_key(
    const sgx_target_info_t* p_qe3_target, 
    uint8_t* p_pub_key, uint64_t pub_key_len, 
    uint8_t* p_sealed_priv_key, uint64_t sealed_priv_key_len, 
    sgx_report_t* p_report) 
{
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    
    // Generate asymmetric key pair
    const int key_size = TKSM_RSA_KEY_SIZE;
    const int e_byte_size = TKSM_RSA_EXP_SIZE;
    uint32_t sealed_data_size = 0;
    sgx_sealed_data_t* p_sealed_data = nullptr;
    int e = TKSM_RSA_DEFAULT_EXP;
    tksm_rsa_priv_key_t priv_key;
    tksm_rsa_priv_key_t *p_priv_key = &priv_key;
    tksm_rsa_pub_key_t *_p_pub_key = reinterpret_cast<tksm_rsa_pub_key_t *>(&priv_key.n);
    
    uint8_t *p_e = reinterpret_cast<uint8_t*>(&e);
    uint8_t p_p[key_size] = {0};
    uint8_t p_q[key_size] = {0};
    uint8_t p_dmp1[key_size] = {0};
    uint8_t p_dmq1[key_size] = {0};
    uint8_t p_iqmp[key_size] = {0};

    sgx_sha256_hash_t hash;
    sgx_report_data_t report_data;
    sgx_report_t report_buffer;

    static_assert(sizeof(hash) <= sizeof(report_data), "report_data must be smaller than hash");

    if (!p_qe3_target || !p_pub_key || !p_sealed_priv_key || !p_report || !pub_key_len || !sealed_priv_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    memset(&priv_key, 0, sizeof(priv_key));
    memset(&hash, 0, sizeof(hash));
    memset(&report_data, 0, sizeof(report_data));
    memset(&report_buffer, 0, sizeof(report_buffer));

    // test();
    
    // LOG("Generate asymmetric key pair\n");
    // 1. Generate RSA key pair
    rc = sgx_create_rsa_key_pair(
        key_size, e_byte_size, 
        p_priv_key->n, p_priv_key->d, p_e,
        p_p, p_q,
        p_dmp1, p_dmq1, p_iqmp);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_create_rsa_key_pair failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    if (e != TKSM_RSA_DEFAULT_EXP) {
        LOG("e changed to %d\n", e);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // LOG("priv_key.n:\n");
    // hexdump(p_priv_key->n, TKSM_RSA_KEY_SIZE);
    // LOG("priv_key.d:\n");
    // hexdump(p_priv_key->d, TKSM_RSA_KEY_SIZE);

    // 2. Seal the private key
    sealed_data_size = sgx_calc_sealed_data_size(0, sizeof(priv_key));
    if (sealed_data_size == UINT32_MAX) {
        LOG("sgx_calc_sealed_data_size failed\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    // LOG("sealed_data_size: %d\n", sealed_data_size);
    p_sealed_data = static_cast<sgx_sealed_data_t*>(calloc(1, sealed_data_size));
    if (p_sealed_data == NULL) {
        LOG("calloc failed\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }
    rc = sgx_seal_data(
        0, nullptr,
        sizeof(priv_key), reinterpret_cast<uint8_t*>(p_priv_key),
        sealed_data_size, p_sealed_data
    );
    if (rc != SGX_SUCCESS) {
        LOG("sgx_seal_data failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_sealed_data;
    }

    // LOG("seal policy: %#x\n", p_sealed_data->key_request.key_policy);

    // 3. Calc hash(pub_key)
    rc = sgx_sha256_msg(reinterpret_cast<uint8_t*>(_p_pub_key), sizeof(*_p_pub_key), &hash);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_sha256_msg failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_sealed_data;
    }
    memcpy(&report_data, &hash, sizeof(hash));

    // LOG("pubkey:\n");
    // hexdump(_p_pub_key, TKSM_RSA_KEY_SIZE);
    // LOG("pubkey hash:\n");
    // hexdump(&hash, 0x20);

    // LOG("report data:\n");
    // hexdump(&report_data, sizeof(report_data));

    // 4. Generate report
    rc = sgx_create_report(p_qe3_target, &report_data, &report_buffer);
    if (rc != SGX_SUCCESS) {
        LOG("create_report failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_sealed_data;
    }
    // LOG("Report generated: %#x\n", rc);

    // 5. Copy to untrusted side
    if (pub_key_len < sizeof(*_p_pub_key)) {
        LOG("pub_key_len is too small\n");
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_sealed_data;
    }
    if (sealed_priv_key_len < sealed_data_size) {
        LOG("sealed_priv_key_len is too small\n");
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_sealed_data;
    }

    if (pub_key_len < sizeof(*_p_pub_key)) {
        LOG("pub_key_len is too small (%#lx, %#lx)\n", pub_key_len, sizeof(*_p_pub_key));
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_sealed_data;
    }
    if (sealed_priv_key_len < sealed_data_size) {
        LOG("sealed_priv_key_len is too small (%#lx, %#lx)\n", sealed_priv_key_len, sealed_data_size);
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_sealed_data;
    }


    memcpy(p_pub_key, _p_pub_key, sizeof(*_p_pub_key));
    memcpy(p_sealed_priv_key, p_sealed_data, sealed_data_size);
    memcpy(p_report, &report_buffer, sizeof(report_buffer));

err_free_sealed_data:
    free(p_sealed_data);
err_out:
    return ret;
}

uint64_t ecall_tksm_gen_sym_key(
    const sgx_target_info_t* p_qe3_target, 
    uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len, sgx_report_t* p_report)
{
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint32_t sealed_data_size = 0;
    sgx_sealed_data_t* p_sealed_data = nullptr;
    sgx_sha256_hash_t hash;
    sgx_report_data_t report_data;
    sgx_report_t report_buffer;

    static_assert(sizeof(hash) <= sizeof(report_data), "report_data must be smaller than hash");

    if (!p_qe3_target || !p_sealed_sym_key || !p_report || !sealed_sym_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    memset(&hash, 0, sizeof(hash));
    memset(&report_data, 0, sizeof(report_data));
    memset(&report_buffer, 0, sizeof(report_buffer));
    
    // Generate AES key
    uint8_t aes_key[TKSM_AES_KEY_SIZE] = {0};
    rc = sgx_read_rand(aes_key, TKSM_AES_KEY_SIZE);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_read_rand failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    LOG("AES key:\n");
    hexdump(aes_key, TKSM_AES_KEY_SIZE);

    // Calc hash of the AES key
    rc = sgx_sha256_msg(aes_key, TKSM_AES_KEY_SIZE, &hash);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_sha256_msg failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    memcpy(&report_data, &hash, sizeof(hash));
    
    // Generate report
    rc = sgx_create_report(p_qe3_target, &report_data, &report_buffer);
    if (rc != SGX_SUCCESS) {
        LOG("create_report failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // Seal the AES key
    sealed_data_size = sgx_calc_sealed_data_size(0, sizeof(aes_key));
    if (sealed_data_size == UINT32_MAX) {
        LOG("sgx_calc_sealed_data_size failed\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    p_sealed_data = static_cast<sgx_sealed_data_t*>(calloc(1, sealed_data_size));
    if (p_sealed_data == NULL) {
        LOG("calloc failed\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_out;
    }
    rc = sgx_seal_data(
        0, nullptr,
        sizeof(aes_key), reinterpret_cast<uint8_t*>(aes_key),
        sealed_data_size, p_sealed_data);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_seal_data failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_sealed_data;
    }

    // Copy to untrusted side
    if (sealed_sym_key_len < sealed_data_size) {
        LOG("sealed_sym_key_len is too small: (%#lx, %#lx)\n", sealed_sym_key_len, sealed_data_size);
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_sealed_data;
    }

    memcpy(p_sealed_sym_key, p_sealed_data, sealed_data_size);
    memcpy(p_report, &report_buffer, sizeof(report_buffer));

err_free_sealed_data:
    free(p_sealed_data);
err_out:
    return ret;
}

uint64_t ecall_tksm_export_sym_key(
    const uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len, 
    const uint8_t* p_pub_key, uint64_t pub_key_len, 
    const uint8_t* p_quote_pub_key, uint64_t quote_pub_key_len, 
    const sgx_ql_qe_report_info_t* p_qve_report_info, 
    time_t expiration_check_date, 
    uint32_t collateral_expiration_status, 
    sgx_ql_qv_result_t quote_verification_result,
    const uint8_t* p_supplemental_data, uint32_t supplemental_data_size, 
    
    buf_t* p_enc_sym_key, uint64_t enc_sym_key_len) 
{
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    quote3_error_t tvl_rc = SGX_QL_SUCCESS;
    sgx_sha256_hash_t hash;
    const sgx_quote3_t *p_quote = reinterpret_cast<const sgx_quote3_t*>(p_quote_pub_key);
    uint8_t aes_key_buffer[TKSM_AES_KEY_SIZE] = {0};
    uint32_t unsealed_aes_key_len = sizeof(aes_key_buffer);
    uint8_t enc_aes_key_buffer[TKSM_RSA_KEY_SIZE] = {0};
    size_t enc_aes_key_len = sizeof(enc_aes_key_buffer);
    void *rsa_pub_key = nullptr;
    const int rsa_mod_size = TKSM_RSA_KEY_SIZE;
    const int rsa_exp_size = TKSM_RSA_EXP_SIZE;
    const uint32_t rsa_exp = TKSM_RSA_DEFAULT_EXP;

    if (!p_sealed_sym_key || !p_pub_key || !p_quote_pub_key || !p_qve_report_info || !p_supplemental_data || !sealed_sym_key_len || !pub_key_len || !quote_pub_key_len || !supplemental_data_size || !enc_sym_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    UNUSED(sealed_sym_key_len);
    memset(&hash, 0, sizeof(hash));

    // Verify quote
    tvl_rc = sgx_tvl_verify_qve_report_and_identity(
        p_quote_pub_key, static_cast<uint32_t>(quote_pub_key_len),
        p_qve_report_info,
        expiration_check_date,
        collateral_expiration_status,
        quote_verification_result,
        p_supplemental_data, supplemental_data_size,
        QVE_ISVSVN_THRESHOLD_DEFAULT);
    if (tvl_rc != SGX_QL_SUCCESS) {
        LOG("sgx_tvl_verify_qve_report_and_identity failed: %#x\n", tvl_rc);
        ret = TKSM_ERROR_INVALID_QUOTE;
        goto err_out;
    }

    // Check hash(pub_key) == hash in quote
    rc = sgx_sha256_msg(p_pub_key, static_cast<uint32_t>(pub_key_len), &hash);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_sha256_msg failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }
    // LOG("pubkey:\n");
    // hexdump(p_pub_key, TKSM_RSA_KEY_SIZE);

    // LOG("hash of pub key:\n");
    // hexdump(&hash, 0x20);

    // LOG("report data:\n");
    // // const uint8_t *report_data = ;
    // hexdump(p_qve_report_info->qe_report.body.report_data.d, 0x20);

    // LOG("quote report data:\n");
    // hexdump(
    //     p_quote->report_body.report_data.d,
    //     0x20
    // );

    if (memcmp(&hash, p_quote->report_body.report_data.d, sizeof(hash)) != 0) {
        LOG("hash of pub key does not match hash in quote\n");
        ret = TKSM_ERROR_INVALID_QUOTE;
        goto err_out;
    }

    // Unseal the AES key

    rc = sgx_unseal_data(
        reinterpret_cast<const sgx_sealed_data_t *>(p_sealed_sym_key), 
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

    // Encrypt the AES key with public key
    rc = sgx_create_rsa_pub1_key(
        rsa_mod_size, rsa_exp_size,
        p_pub_key,
        reinterpret_cast<const uint8_t*>(&rsa_exp),
        &rsa_pub_key);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_create_rsa_pub1y_key failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    rc = sgx_rsa_pub_encrypt_sha256(
        rsa_pub_key,
        enc_aes_key_buffer, &enc_aes_key_len,
        aes_key_buffer, sizeof(aes_key_buffer)
    );
    if (rc != SGX_SUCCESS) {
        LOG("sgx_rsa_pub_encrypt_sha256 failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_rsa_pub_key;
    }
    // LOG("enc_aes_key_len: %#lx\n", enc_aes_key_len);
    // LOG("enc_aes_key:\n");
    // hexdump(enc_aes_key_buffer, enc_aes_key_len);
    
    // Copy to untrusted side
    if (enc_sym_key_len + sizeof(buf_t) < enc_aes_key_len) {
        LOG("enc_sym_key_len is too small (%#lx, %#lx)\n", enc_sym_key_len, enc_aes_key_len);
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_rsa_pub_key;
    }

    p_enc_sym_key->size = enc_aes_key_len;
    memcpy(p_enc_sym_key->data, enc_aes_key_buffer, enc_aes_key_len);
    
err_free_rsa_pub_key:
    sgx_free_rsa_key(rsa_pub_key, SGX_RSA_PUBLIC_KEY, rsa_mod_size, rsa_exp_size);
err_out:
    return ret;
}

uint64_t ecall_tksm_import_sym_key(
    const uint8_t* p_sealed_priv_key, uint64_t sealed_priv_key_len, 
    const uint8_t* p_enc_sym_key, uint64_t enc_sym_key_len, 
    const uint8_t* p_quote_sym_key, uint64_t quote_sym_key_len, 
    const sgx_ql_qe_report_info_t* p_qve_report_info, 
    time_t expiration_check_date, 
    uint32_t collateral_expiration_status, 
    sgx_ql_qv_result_t quote_verification_result, 
    const uint8_t* p_supplemental_data, uint32_t supplemental_data_size, 
    
    uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len) 
{
    tksm_status_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    quote3_error_t tvl_rc = SGX_QL_SUCCESS;
    tksm_rsa_priv_key_t unsealed_rsa_priv_key;
    uint32_t unsealed_rsa_priv_key_len = sizeof(unsealed_rsa_priv_key);
    const int rsa_n_byte_size = TKSM_RSA_KEY_SIZE;
    const int rsa_e_byte_size = TKSM_RSA_EXP_SIZE;
    const int rsa_d_byte_size = TKSM_RSA_KEY_SIZE;
    const uint32_t rsa_exp = TKSM_RSA_DEFAULT_EXP;
    void *rsa_priv_key = nullptr;
    uint8_t dec_aes_key[TKSM_RSA_KEY_SIZE];
    uint64_t dec_aes_key_len = sizeof(dec_aes_key);
    sgx_sha256_hash_t hash;
    const sgx_quote3_t *p_quote = reinterpret_cast<const sgx_quote3_t*>(p_quote_sym_key);
    uint32_t sealed_data_size = 0;
    sgx_sealed_data_t* p_sealed_data = nullptr;

    if (!p_sealed_priv_key || !p_enc_sym_key || !p_quote_sym_key || !p_sealed_sym_key || !p_qve_report_info || !p_supplemental_data || !sealed_priv_key_len || !enc_sym_key_len || !quote_sym_key_len || !sealed_sym_key_len) {
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    UNUSED(sealed_priv_key_len);
    memset(&hash, 0, sizeof(hash));

    // Unseal the private key
    rc = sgx_unseal_data(
        reinterpret_cast<const sgx_sealed_data_t *>(p_sealed_priv_key), 
        nullptr, 0,
        reinterpret_cast<uint8_t*>(&unsealed_rsa_priv_key), &unsealed_rsa_priv_key_len);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_unseal_data failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // Decrypt the AES key
    rc = sgx_create_rsa_priv1_key(
        rsa_n_byte_size, rsa_e_byte_size, rsa_d_byte_size,
        unsealed_rsa_priv_key.n, reinterpret_cast<const uint8_t*>(&rsa_exp), unsealed_rsa_priv_key.d,
        &rsa_priv_key
    );
    if (rc != SGX_SUCCESS) {
        LOG("sgx_create_rsa_priv1_key failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // LOG("enc_aes_key_len: %#lx\n", enc_sym_key_len);
    // LOG("enc_aes_key:\n");
    // hexdump(p_enc_sym_key, enc_sym_key_len);
    // LOG("unsealed_rsa_priv_key.n:\n");
    // hexdump(unsealed_rsa_priv_key.n, TKSM_RSA_KEY_SIZE);
    // LOG("unsealed_rsa_priv_key.d:\n");
    // hexdump(unsealed_rsa_priv_key.d, TKSM_RSA_KEY_SIZE);


    rc = sgx_rsa_priv_decrypt_sha256(
        rsa_priv_key,
        dec_aes_key, &dec_aes_key_len,
        p_enc_sym_key, enc_sym_key_len
    );
    if (rc != SGX_SUCCESS) {
        LOG("sgx_rsa_priv_decrypt_sha256 failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_rsa_priv_key;
    }
    if (dec_aes_key_len != TKSM_AES_KEY_SIZE) {
        LOG("dec_aes_key_len is invalid (%#lx, %#lx)\n", dec_aes_key_len, sizeof(dec_aes_key));
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_rsa_priv_key;
    }

    // Verify quote
    tvl_rc = sgx_tvl_verify_qve_report_and_identity(
        p_quote_sym_key, static_cast<uint32_t>(quote_sym_key_len),
        p_qve_report_info,
        expiration_check_date,
        collateral_expiration_status,
        quote_verification_result,
        p_supplemental_data, supplemental_data_size,
        QVE_ISVSVN_THRESHOLD_DEFAULT);
    if (tvl_rc != SGX_QL_SUCCESS) {
        LOG("sgx_tvl_verify_qve_report_and_identity failed: %#x\n", tvl_rc);
        ret = TKSM_ERROR_INVALID_QUOTE;
        goto err_free_rsa_priv_key;
    }

    // compare hash(aes_key) with hash in quote
    rc = sgx_sha256_msg(dec_aes_key, static_cast<uint32_t>(dec_aes_key_len), &hash);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_sha256_msg failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_rsa_priv_key;
    }

    if (memcmp(&hash, p_quote->report_body.report_data.d, sizeof(hash)) != 0) {
        LOG("hash of pub key does not match hash in quote\n");
        ret = TKSM_ERROR_INVALID_QUOTE;
        goto err_free_rsa_priv_key;
    }

    // LOG("dec_aes_key:\n");
    // hexdump(dec_aes_key, TKSM_AES_KEY_SIZE);

    // Seal the AES key
    sealed_data_size = sgx_calc_sealed_data_size(0, static_cast<uint32_t>(dec_aes_key_len));
    if (sealed_data_size == UINT32_MAX) {
        LOG("sgx_calc_sealed_data_size failed\n");
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_rsa_priv_key;
    }
    p_sealed_data = static_cast<sgx_sealed_data_t*>(calloc(1, sealed_data_size));
    if (p_sealed_data == NULL) {
        LOG("calloc failed\n");
        ret = TKSM_ERROR_OUT_OF_MEMORY;
        goto err_free_rsa_priv_key;
    }
    rc = sgx_seal_data(
        0, nullptr,
        static_cast<uint32_t>(dec_aes_key_len), reinterpret_cast<uint8_t*>(dec_aes_key),
        sealed_data_size, p_sealed_data);
    if (rc != SGX_SUCCESS) {
        LOG("sgx_seal_data failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_free_sealed_data;
    }
    
    // Copy to untrusted side
    if (sealed_sym_key_len < sealed_data_size) {
        LOG("sealed_sym_key_len is too small: (%#lx, %#lx)\n", sealed_sym_key_len, sealed_data_size);
        ret = TKSM_ERROR_INVALID_PARAMETER;
        goto err_free_sealed_data;
    }

    memcpy(p_sealed_sym_key, p_sealed_data, sealed_data_size);


err_free_sealed_data:
    free(p_sealed_data);
err_free_rsa_priv_key:
    sgx_free_rsa_key(rsa_priv_key, SGX_RSA_PRIVATE_KEY, rsa_n_byte_size, rsa_e_byte_size);
err_out:
    return ret;
}


// for test purpose
uint64_t ecall_tksm_encrypt(const uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len, const uint8_t* p_plaintext, uint64_t plaintext_len, tksm_aes_gcm_enc_t* p_ciphertext, uint64_t ciphertext_len) {
    uint64_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint8_t aes_key_buffer[TKSM_AES_KEY_SIZE] = {0};
    uint32_t unsealed_aes_key_len = sizeof(aes_key_buffer);
    // const int IV_LEN = 12;
    // const int MAC_LEN = 16;
    // const uint8_t iv[TKSM_AES_GCM_IV_SIZE] = {'g', 'r', 'e', 'e', 'n', 's', 'e', 'c', 'u', 'r', 'i', 't', 'y'};
    // uint8_t mac[TKSM_AES_GCM_MAC_SIZE] = {0};
    UNUSED(sealed_sym_key_len);
    UNUSED(ciphertext_len);

    memcpy(p_ciphertext->iv, "greedisgood.", TKSM_AES_GCM_IV_SIZE);


    rc = sgx_unseal_data(
        reinterpret_cast<const sgx_sealed_data_t *>(p_sealed_sym_key), 
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

    // p_ciphertext = p_ciphertext + TKSM_AES_GCM_ENC_LEN_PLUS;
    rc = sgx_rijndael128GCM_encrypt(
        reinterpret_cast<sgx_aes_gcm_128bit_key_t *>(aes_key_buffer),
        p_plaintext,
        static_cast<uint32_t>(plaintext_len),
        p_ciphertext->data,
        p_ciphertext->iv,
        TKSM_AES_GCM_IV_SIZE,
        nullptr,
        0,
        reinterpret_cast<sgx_aes_gcm_128bit_tag_t *>(p_ciphertext->mac));
    
    if (rc != SGX_SUCCESS) {
        LOG("sgx_rijndael128GCM_encrypt failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }

    // LOG("aes_key_buffer:\n");
    // hexdump(aes_key_buffer, TKSM_AES_KEY_SIZE);

    // LOG("plain text:\n");
    // hexdump(p_plaintext, plaintext_len);

    // LOG("cipher text:\n");
    // hexdump(p_ciphertext, ciphertext_len);

err_out:
    return ret;
}

// for test purpose
uint64_t ecall_tksm_decrypt(
    const uint8_t* p_sealed_sym_key, uint64_t sealed_sym_key_len, 
    const tksm_aes_gcm_enc_t* p_ciphertext, uint64_t ciphertext_len, 
    uint8_t* p_plaintext, uint64_t plaintext_len) {
    uint64_t ret = TKSM_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint8_t aes_key_buffer[TKSM_AES_KEY_SIZE] = {0};
    uint32_t unsealed_aes_key_len = sizeof(aes_key_buffer);
    UNUSED(sealed_sym_key_len);
    UNUSED(ciphertext_len);
    UNUSED(plaintext_len);


    rc = sgx_unseal_data(
        reinterpret_cast<const sgx_sealed_data_t *>(p_sealed_sym_key), 
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


    rc = sgx_rijndael128GCM_decrypt(
        reinterpret_cast<sgx_aes_gcm_128bit_key_t *>(aes_key_buffer),
        p_ciphertext->data,
        static_cast<uint32_t>(ciphertext_len - sizeof(tksm_aes_gcm_enc_t)),
        p_plaintext,
        p_ciphertext->iv,
        TKSM_AES_GCM_IV_SIZE,
        nullptr,
        0,
        reinterpret_cast<const sgx_aes_gcm_128bit_tag_t *>(p_ciphertext->mac));
    
    if (rc != SGX_SUCCESS) {
        LOG("sgx_rijndael128GCM_decrypt failed: %#x\n", rc);
        ret = TKSM_ERROR_UNEXPECTED;
        goto err_out;
    }


    // LOG("aes_key_buffer:\n");
    // hexdump(aes_key_buffer, TKSM_AES_KEY_SIZE);

    // LOG("plain text:\n");
    // hexdump(p_plaintext, plaintext_len);

    // LOG("cipher text:\n");
    // hexdump(p_ciphertext, ciphertext_len);

err_out:
    // ret = TKSM_ERROR_UNEXPECTED;
    return ret;
}


