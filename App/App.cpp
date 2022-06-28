/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include <string>
#include <fstream>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "tksm_api.h"
#include "flas_api.h"

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wunused"
/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void save_file(const char *filename, const uint8_t *data, size_t size)
{
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("Failed to open file %s\n", filename);
        return;
    }
    size_t n = fwrite(data, 1, size, fp);
    if (n != size) {
        printf("Failed to write file %s (%d, %d)\n", filename, n, size);
        return;
    }

    fclose(fp);
}

static vector<uint8_t> readBinaryContent(const string& filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        printf("Error: Unable to open quote file %s\n", filePath.c_str());
        return {};
    }

    file.seekg(0, ios_base::end);
    streampos fileSize = file.tellg();

    file.seekg(0, ios_base::beg);
    vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char*>(retVal.data()), fileSize);
    file.close();
    return retVal;
}

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

void test_gen_asym_key(const sgx_enclave_id_t eid) {
    tksm_status_t ret = TKSM_SUCCESS;

    uint8_t *p_pub_key = nullptr, *p_sealed_priv_key = nullptr, *p_quote_pub_key = nullptr;
    uint64_t pub_key_len = 0, sealed_priv_key_len = 0, quote_pub_key_len = 0;

    ret = tksm_gen_asym_key(
        eid,
        &p_pub_key, &pub_key_len,
        &p_sealed_priv_key, &sealed_priv_key_len,
        &p_quote_pub_key, &quote_pub_key_len
    );
    if (ret != TKSM_SUCCESS) {
        printf("Error: tksm_gen_asym_key failed: %d\n", ret);
        return;
    }
    
    save_file("pub_key.dat", p_pub_key, pub_key_len);
    save_file("sealed_priv_key.dat", p_sealed_priv_key, sealed_priv_key_len);
    save_file("quote_pub_key.dat", p_quote_pub_key, quote_pub_key_len);
    free(p_pub_key);
    free(p_sealed_priv_key);
    free(p_quote_pub_key);
    LOG("ecall_tksm_gen_asym_key: %ld\n", ret);
}

void test_gen_sym_key(const sgx_enclave_id_t eid) {
    tksm_status_t ret = TKSM_SUCCESS;

    uint8_t *p_sealed_sym_key = nullptr, *p_quote_sym_key = nullptr;
    uint64_t sealed_sym_key_len = 0, quote_sym_key_len = 0;

    ret = tksm_gen_sym_key(
        eid,
        &p_sealed_sym_key, &sealed_sym_key_len,
        &p_quote_sym_key, &quote_sym_key_len
    );
    if (ret != TKSM_SUCCESS) {
        printf("Error: tksm_gen_sym_key failed: %d\n", ret);
        return;
    }

    save_file("sealed_sym_key.dat", p_sealed_sym_key, sealed_sym_key_len);
    save_file("quote_sym_key.dat", p_quote_sym_key, quote_sym_key_len);
    free(p_quote_sym_key);
    free(p_quote_sym_key);
    LOG("ecall_tksm_gen_sym_key: %ld\n", ret);
}

void test_export_sym_key(const sgx_enclave_id_t eid) {
    tksm_status_t ret = TKSM_SUCCESS;

    auto pub_key = readBinaryContent("pub_key.dat");
    // auto sealed_priv_key = readBinaryContent("sealed_priv_key.dat");
    auto quote_pub_key = readBinaryContent("quote_pub_key.dat");
    auto sealed_sym_key = readBinaryContent("sealed_sym_key.dat");
    // auto quote_sym_key = readBinaryContent("quote_sym_key.dat");

    uint8_t *p_enc_sym_key = nullptr;
    uint64_t enc_sym_key_len = 0;

    ret = tksm_export_sym_key(
        eid,
        sealed_sym_key.data(), sealed_sym_key.size(),
        pub_key.data(), pub_key.size(),
        quote_pub_key.data(), quote_pub_key.size(),

        &p_enc_sym_key, &enc_sym_key_len
    );
    if (ret != TKSM_SUCCESS) {
        printf("Error: tksm_export_sym_key failed: %d\n", ret);
        return;
    }

    save_file("enc_sym_key.dat", p_enc_sym_key, enc_sym_key_len);
    free(p_enc_sym_key);
    
    LOG("ecall_tksm_export_sym_key: %#lx\n", ret);
}

void test_import_sym_key(const sgx_enclave_id_t eid) {
    tksm_status_t ret = TKSM_SUCCESS;
    // auto pub_key = readBinaryContent("pub_key.dat");
    auto sealed_priv_key = readBinaryContent("sealed_priv_key.dat");
    // auto quote_pub_key = readBinaryContent("quote_pub_key.dat");
    // auto sealed_sym_key = readBinaryContent("sealed_sym_key.dat");
    auto quote_sym_key = readBinaryContent("quote_sym_key.dat");
    auto enc_sym_key = readBinaryContent("enc_sym_key.dat");


    uint8_t *p_sealed_sym_key2 = nullptr;
    uint64_t sealed_sym_key_len2 = 0;

    ret = tksm_import_sym_key(
        eid,
        sealed_priv_key.data(), sealed_priv_key.size(),
        enc_sym_key.data(), enc_sym_key.size(),
        quote_sym_key.data(), quote_sym_key.size(),
        &p_sealed_sym_key2, &sealed_sym_key_len2
    );
    if (ret != TKSM_SUCCESS) {
        printf("Error: tksm_import_sym_key failed: %d\n", ret);
        return;
    }

    free(p_sealed_sym_key2);
    LOG("ecall_tksm_import_sym_key: %#lx\n", ret);
}

tksm_status_t encrypt_file(const sgx_enclave_id_t eid, const std::string &plain_file_path, const std::string &enc_file_path) {
    tksm_status_t ret = TKSM_SUCCESS;
    uint8_t *cipher_text = nullptr;
    uint64_t cipher_text_len = 0;

    auto sealed_sym_key = readBinaryContent("sealed_sym_key.dat");
    if (sealed_sym_key.size() == 0) {
        LOG("sealed_sym_key is empty\n");
        return TKSM_ERROR_INVALID_PARAMETER;
    }
    // auto plaintext = readBinaryContent("sealed_sym_key.dat");

    auto plaintext = readBinaryContent(plain_file_path);
    if (plaintext.size() == 0) {
        LOG("plaintext is empty\n");
        return TKSM_ERROR_INVALID_PARAMETER;
    }
    // LOG("[f] plaintext:\n");
    // hexdump(plaintext.data(), plaintext.size());

    ret = tksm_encrypt(
        eid,
        sealed_sym_key.data(), sealed_sym_key.size(),
        reinterpret_cast<uint8_t*>(plaintext.data()), plaintext.size(),
        &cipher_text, &cipher_text_len
    );
    if (ret != TKSM_SUCCESS) {
        LOG("ecall_tksm_encrypt failed: %#lx\n", ret);
        return ret;
    }

    save_file(enc_file_path.c_str(), cipher_text, cipher_text_len);
    free(cipher_text);

    // LOG("encrypt_file: %#lx\n", ret);
    return ret;
}


tksm_status_t decrypt_file(const sgx_enclave_id_t eid, const std::string &enc_file_path, const std::string &dec_file_path) {
    tksm_status_t ret = TKSM_SUCCESS;
    uint8_t *dec_text = nullptr;
    uint64_t dec_text_len = 0;

    auto sealed_sym_key = readBinaryContent("sealed_sym_key.dat");
    if (sealed_sym_key.size() == 0) {
        LOG("sealed_sym_key is empty\n");
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    auto ciphertext = readBinaryContent(enc_file_path);
    if (ciphertext.size() == 0) {
        LOG("ciphertext is empty\n");
        return TKSM_ERROR_INVALID_PARAMETER;
    }

    ret = tksm_decrypt(
        eid,
        sealed_sym_key.data(), sealed_sym_key.size(),
        reinterpret_cast<uint8_t*>(ciphertext.data()), ciphertext.size(),
        &dec_text, &dec_text_len
    );
    if (ret != TKSM_SUCCESS) {
        LOG("ecall_tksm_decrypt failed: %#lx\n", ret);
        return ret;
    }

    save_file(dec_file_path.c_str(), dec_text, dec_text_len);
    free(dec_text);

    // LOG("encrypt_file: %#lx\n", ret);
    return ret;
}


void test_encrypt(const sgx_enclave_id_t eid) {
    tksm_status_t ret = TKSM_SUCCESS;
    // auto sealed_sym_key = readBinaryContent("sealed_sym_key.dat");
    ret = encrypt_file(eid, "/root/master/my_code/states/s1.dat", "./states/s1.enc2");
    if (ret != TKSM_SUCCESS)
        LOG("Error: encrypt_file failed: %d\n", ret);
    else
        LOG("encrypt_file success\n");
}

void test_decrypt(const sgx_enclave_id_t eid) {
    tksm_status_t ret = TKSM_SUCCESS;
    ret = decrypt_file(eid, "./states/s1.enc", "./states/s1.dec2");
    if (ret != TKSM_SUCCESS)
        LOG("Error: decrypt_file failed: %d\n", ret);
    else
        LOG("decrypt_file success\n");
}




void test(const sgx_enclave_id_t eid) {
    hexdump(nullptr, 0);
    UNUSED(eid);
    // LOG("???\n");
    // test_gen_asym_key(eid);
    // test_gen_sym_key(eid);
    // test_export_sym_key(eid);
    // test_import_sym_key(eid);
    // test_encrypt(eid);
    // test_decrypt(eid);

    // encrypt_file(
    //     eid,
    //     "/root/master/my_code/states/s1.dat", 
    //     "./states/s1.enc"
    // );

    // encrypt_file(
    //     eid,
    //     "/root/master/my_code/states/s2.dat", 
    //     "./states/s2.enc"
    // );

    // encrypt_file(
    //     eid,
    //     "/root/master/my_code/states/s3.dat", 
    //     "./states/s3.enc"
    // );

    // encrypt_file(
    //     eid,
    //     "./plaintext",
    //     "./encrypted"
    // );

    // decrypt_file(
    //     eid,
    //     "./encrypted2",
    //     "./decrypted2"
    // );

    

    test_FLASEM();
    // test_FLASServer();
}

#pragma GCC diagnostic pop
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        LOG("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    
    /* Utilize trusted libraries */ 
    // ecall_libcxx_functions();
    test(global_eid);
    
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    LOG("Info: tksm enclave successfully returned.\n");

    //printf("Enter a character before exit ...\n");
    //getchar();
    return 0;
}

