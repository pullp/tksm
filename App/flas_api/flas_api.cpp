#include "flas_api.h"

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <memory>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <asio.hpp>
#pragma GCC diagnostic pop

#include <sgx_error.h>      /* sgx_status_t */
#include <sgx_eid.h>    /* sgx_enclave_id_t */
#include "sgx_urts.h"


#include "flas_common.h"
#include "flas_error.h"
#include "App.h"

#include "Enclave_u.h"

using std::ifstream;
using std::ios;
using std::ios_base;
using std::streampos;
// using std::make_unique;
using asio::ip::tcp;

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
 
FLASEM::FLASEM(const string &enclave_path, const string &skey_path, const uint64_t client_total, const uint64_t epoch_max)
: epoch_max_(epoch_max),
    client_total_(client_total),
    epoch_cur_(0),
    state_received_(0)
    {
    LOG("FLASEM constructor\n");
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(enclave_path.c_str(),
                            SGX_DEBUG_FLAG,
                            NULL,
                            NULL,
                            &this->eid_,
                            NULL);
    if (ret != SGX_SUCCESS) {
        LOG("sgx_create_enclave error: %#x\n", ret);
        abort();
    }

    this->sealed_aes_key_ = readBinaryContent(skey_path);
    if (this->sealed_aes_key_.empty()) {
        LOG("Error: Unable to read sealed AES key\n");
        abort();
    }

}

FLASEM::~FLASEM() {
    LOG("FLASEM destructor\n");
    sgx_destroy_enclave(this->eid_);
}


flas_status_t FLASEM::add_state(uint64_t epoch_idx, uint64_t sample_cnt, vector<uint8_t> enc_state) {
    if (epoch_idx != this->epoch_cur_) {
        LOG("Error: epoch_idx != epoch_cur\n");
        return FLAS_ERROR_UNEXPECTED;
    }
    if (epoch_idx > this->epoch_max_) {
        LOG("Error: epoch_idx > this->epoch_max_\n");
        return FLAS_ERROR_UNEXPECTED;
    }
    if (this->enc_state_vec_.size() >= this->client_total_) {
        LOG("Error: this->enc_state_vec_.size() >= this->client_total_\n");
        return FLAS_ERROR_TOO_MUCH_LOCAL_STATE;
    }
    this->sample_cnt_vec_.push_back(sample_cnt);
    this->enc_state_vec_.push_back(std::move(enc_state));
    // this->state_received_++;
    return FLAS_SUCCESS;
}

flas_status_t FLASEM::do_agg() {
    flas_status_t ret = FLAS_SUCCESS;
    sgx_status_t rc = SGX_SUCCESS;
    uint64_t ecall_rc = FLAS_SUCCESS;
    uint64_t enc_states_cnt = this->enc_state_vec_.size();
    enc_state_t enc_global_state;

    // if (state_received_ != client_total_) {
    //     LOG("Error: state_received_ != client_total_\n");
    //     return FLAS_ERROR_LACK_OF_LOCAL_STATE;
    // }
    // if (this->state_returned_ != this->client_total_) {
    //     LOG("Error: state_returned_ != 0\n");
    //     return FLAS_ERROR_UNEXPECTED;
    // }

    if (this->enc_state_vec_.size() != this->client_total_) {
        LOG("Error: No state to aggregate\n");
        return FLAS_ERROR_LACK_OF_LOCAL_STATE;
    }
    enc_states_t *enc_states = static_cast<enc_states_t*>(malloc(sizeof(enc_states_t) + sizeof(tksm_aes_gcm_enc_t*) * enc_states_cnt));
    enc_states->cnt = enc_states_cnt;
    if (enc_states == NULL) {
        LOG("Error: Unable to allocate memory for enc_states\n");
        ret = FLAS_ERROR_UNEXPECTED;
        goto err_out;
    }
    // enc_states->weight_cnt = 2940; // for test purporse. todo
    // enc_states->weight_cnt = 6; // for test purporse. todo
    enc_states->weight_cnt = (this->enc_state_vec_[0].size() - sizeof(tksm_aes_gcm_enc_t) - sizeof(state_t)) / sizeof(float);
    LOG("weight_cnt: %ld\n", enc_states->weight_cnt);
    for (size_t i = 0; i < enc_states_cnt; i++) {
        enc_states->ptrs[i] = reinterpret_cast<tksm_aes_gcm_enc_t*>(this->enc_state_vec_[i].data());
    }
    // LOG("data_size: %d\n", enc_states->ptrs[0]->data_size);
    // LOG("ptrs[0] (%p):\n", enc_states->ptrs[0]);
    // hexdump(enc_states->ptrs[0], sizeof(tksm_aes_gcm_enc_t) + 0x40);

    enc_global_state.reserve(this->enc_state_vec_[0].size());
    enc_global_state.resize(this->enc_state_vec_[0].size());

    rc = ecall_flas_agg(
        this->eid_, &ecall_rc, 
        this->sealed_aes_key_.data(), this->sealed_aes_key_.size(),
        enc_states,
        reinterpret_cast<tksm_aes_gcm_enc_t*>(enc_global_state.data())
        );
    
    if (rc != SGX_SUCCESS) {
        LOG("ecall_flas_agg error: %#x\n", rc);
        ret = FLAS_ERROR_UNEXPECTED;
        goto err_free_enc_states;
    } else if (ecall_rc != FLAS_SUCCESS) {
        LOG("ecall_flas_agg error: %#lx\n", ecall_rc);
        ret = FLAS_ERROR_UNEXPECTED;
        goto err_free_enc_states;
    }

    this->enc_global_state_vec_.push_back(std::move(enc_global_state));
    // this->enc_global_state_ = std::move(enc_global_state);

    // LOG("this->enc_global_states_:\n");
    // hexdump(this->enc_global_state_.data(), 0x40);
    epoch_cur_ ++;
    state_received_ = 0;
    enc_state_vec_.clear();
    sample_cnt_vec_.clear();

    
err_free_enc_states:
    free(enc_states);
err_out:
    return ret;
}

uint64_t FLASEM::get_global_state_size(uint64_t epoch_idx) {
    if(epoch_idx >= this->enc_global_state_vec_.size()) {
        LOG("[-] epoch_idx too big: (%#lx, %#lx)\n", epoch_idx, this->enc_global_state_vec_.size());
        return 0;
    }
    return this->enc_global_state_vec_[epoch_idx].size();
}

const FLASEM::enc_state_t& FLASEM::get_global_state(uint64_t epoch_idx) {
    if(epoch_idx >= this->enc_global_state_vec_.size()) {
        LOG("[!] epoch_idx too big");
        abort();
    }
    return this->enc_global_state_vec_[epoch_idx];
}


void test_FLASEM() {
    hexdump(nullptr, 0);
    
    flas_status_t ret = FLAS_SUCCESS;
    auto enc_state1 = readBinaryContent("./states/s1.enc");
    auto enc_state2 = readBinaryContent("./states/s2.enc");
    auto enc_state3 = readBinaryContent("./states/s3.enc");

    uint64_t epoch_idx = 0, sample_cnt = 100;

    FLASEM em("./enclave.signed.so", "./sealed_sym_key.dat", 3, 10);
    ret = em.add_state(epoch_idx, sample_cnt, std::move(enc_state1));
    LOG("add_state1: %#x\n", ret);
    ret = em.add_state(epoch_idx, sample_cnt, std::move(enc_state2));
    LOG("add_state2: %#x\n", ret);
    ret = em.add_state(epoch_idx, sample_cnt, std::move(enc_state3));
    LOG("add_state3: %#x\n", ret);

    ret = em.do_agg();
    LOG("do_agg: %#x\n", ret);

}

void test_FLASServer() {
    try {
        asio::io_context io_context;
        auto p_em = std::make_shared<FLASEM>("./enclave.signed.so", "./sealed_sym_key.dat", 3, 100);
        FLASServer server(io_context, 666, p_em);
        io_context.run();
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

}