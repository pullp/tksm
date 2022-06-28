#ifndef _FLAS_API_H_
#define _FLAS_API_H_

#include <string>
#include <vector>
#include <memory>
#include <iostream>

#include <stdio.h>
#include <sgx_error.h>      /* sgx_status_t */
#include <sgx_eid.h>    /* sgx_enclave_id_t */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <asio.hpp>
#pragma GCC diagnostic pop


#include "flas_common.h"
#include "flas_error.h"

// using std::make_unique;
// using std::shared_ptr;
using std::unique_ptr;
using std::string;
using std::vector;

using asio::ip::tcp;

// #define LOG(...) do { printf("[u][%s:%d:%s] ", __FILE__, __LINE__, __FUNCTION__);  printf(__VA_ARGS__); } while (0)
#define LOG(...) 


#define HEADER_MAGIC 0xdeadbeef
#define HEADER_OP_ADD_STATE 0x1
#define HEADER_OP_GET_STATE 0x2
#define HEADER_OP_GET_INIG_CONFIG 0x3
typedef struct _req_header_t {
    uint32_t magic;
    uint32_t op_type;
    uint64_t client_id;
    uint64_t nonce;
    uint64_t sample_cnt;
    uint64_t epoch_idx;
    uint64_t payload_size;
} req_header_t;


#define HEADER_RC_SUCCESS 0
#define HEADER_RC_FAILURE 1
typedef struct _resp_header_t {
    uint32_t magic;
    uint32_t op_type;
    uint64_t client_id;
    uint64_t rc;
    uint64_t epoch_idx;
    uint64_t payload_size;
} resp_header_t;


// FLAS Enclave Manager
class FLASEM {
public:
    typedef vector<uint8_t> enc_state_t ;
    FLASEM(const string &enclave_path, const string &skey_path, const uint64_t client_total, const uint64_t epoch_max); 

    ~FLASEM();

    flas_status_t get_initial_state();
    flas_status_t add_state(uint64_t epoch_idx, uint64_t sample_cnt, vector<uint8_t> enc_state);
    flas_status_t do_agg();
    uint64_t get_global_state_size(uint64_t epoch_idx);
    const enc_state_t& get_global_state(uint64_t epoch_idx);

private:
    const uint64_t epoch_max_;
    const uint64_t client_total_;
    sgx_enclave_id_t eid_;
    vector<uint8_t> sealed_aes_key_;

    vector<enc_state_t> enc_state_vec_;
    vector<uint64_t> sample_cnt_vec_;
    vector<enc_state_t> enc_global_state_vec_;
    // enc_state_t enc_global_state_;
    uint64_t epoch_cur_;
    uint64_t state_received_;
    // uint64_t state_returned_;
};


// // FLAS Clients Manager
// class FLASCM {
// public:
//     FLASCM(const string &enclave_path, const string &skey_path);

// }

class TCPConnection 
    : public std::enable_shared_from_this<TCPConnection>
{
public:
    typedef std::shared_ptr<TCPConnection> pointer;

    static pointer create(asio::io_context& io_context, std::shared_ptr<FLASEM> p_em)
    {
        return pointer(new TCPConnection(io_context, p_em));
    }

    tcp::socket& socket()
    {
        return socket_;
    }

    void start()
    {
        std::cout << "[*] TCPConnection::start()" << std::endl;

        asio::async_read(
            socket_, 
            // asio::buffer(buffer_), 
            asio::buffer(&this->req_header_buf_, sizeof(this->req_header_buf_)),
            asio::transfer_exactly(sizeof(this->req_header_buf_)),
            std::bind(&TCPConnection::handle_read_header, shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2)
        );
    }

private:
    TCPConnection(asio::io_context& io_context, std::shared_ptr<FLASEM> p_em)
        : socket_(io_context),
        p_em_(p_em)
    {
        this->resp_header_buf_.magic = HEADER_MAGIC;
    }
    
    void handle_write_resp_payload(
        const asio::error_code& ec/*error*/,
        size_t n/*bytes_transferred*/) 
    {
        if (ec) {
            LOG("[-] handle_write_resp_payload: %s\n", ec.message().c_str());
            return;
        }

        LOG("[+] handle_write_resp_payload: %#lx bytes\n", n);
    }

    void handle_write_resp_header(const asio::error_code& ec/*error*/,
        size_t n/*bytes_transferred*/)
    {
        if (ec || n != sizeof(this->resp_header_buf_)) {
            LOG("[-] handle_write_resp_header: %s\n", ec.message().c_str());
            abort();
        }
        if (!this->resp_header_buf_.payload_size)
            return;
        // LOG("write %#x bytes\n", n);

        switch(this->resp_header_buf_.op_type) {
            case HEADER_OP_ADD_STATE:
                // this->handle_write_resp_add_state(ec, n);
                LOG("[*] write_resp_add_state()\n");
                break;
            case HEADER_OP_GET_STATE: {
                // this->handle_write_resp_get_state(ec, n);
                const FLASEM::enc_state_t &enc_state = p_em_->get_global_state(this->req_header_buf_.epoch_idx);
                LOG("[*] before write response header\n");
                asio::async_write(
                    socket_, 
                    asio::buffer(enc_state.data(), enc_state.size()),
                    // buffer_,
                    std::bind(&TCPConnection::handle_write_resp_payload, shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2));
                LOG("[*] after write response header\n");
            }

        }

    }

    void handle_read_header(const asio::error_code& ec/*error*/,
        size_t n/*bytes_transferred*/)
    {
        if (ec) {
            LOG("[-] handle_read_header: %s\n", ec.message().c_str());
            return;
        }
        if (n != sizeof(this->req_header_buf_)) {
            LOG("[-] handle_read_header: n != sizeof(this->req_header_buf_)\n");
            return;
        }

        LOG("magic: %x\n", this->req_header_buf_.magic);
        LOG("op_type: %x\n", this->req_header_buf_.op_type);
        LOG("client_id: %lx\n", this->req_header_buf_.client_id);
        LOG("nonce: %lx\n", this->req_header_buf_.nonce);
        LOG("sample_cnt: %lx\n", this->req_header_buf_.sample_cnt);
        LOG("epoch_idx: %lx\n", this->req_header_buf_.epoch_idx);
        LOG("payload_size: %lx\n", this->req_header_buf_.payload_size);

        payload_buf_.resize(this->req_header_buf_.payload_size);
        asio::async_read(
            socket_, 
            // asio::buffer(buffer_), 
            asio::buffer(payload_buf_),
            asio::transfer_exactly(payload_buf_.size()),
            std::bind(&TCPConnection::handle_read_payload, shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2)
        );
    }

    void handle_read_payload(const asio::error_code& ec/*error*/,
        size_t n/*bytes_transferred*/)
    {
        if (ec) {
            LOG("[-] handle_read_payload: %s\n", ec.message().c_str());
            return;
        }
        if (n != this->req_header_buf_.payload_size) {
            LOG("[-] handle_read_payload: n != header_buf_.payload_size\n");
            return;
        }
        switch (this->req_header_buf_.op_type) {
        case HEADER_OP_ADD_STATE: {
            this->resp_header_buf_.op_type = HEADER_OP_ADD_STATE;
            this->resp_header_buf_.epoch_idx = this->req_header_buf_.epoch_idx;
            this->resp_header_buf_.payload_size = 0;
            if (p_em_->add_state(
                this->req_header_buf_.epoch_idx, this->req_header_buf_.sample_cnt, this->payload_buf_) 
                != FLAS_SUCCESS) {
                LOG("[-] handle_read_payload: add_state failed\n");
                this->resp_header_buf_.rc = HEADER_RC_FAILURE;
            } else {
                this->resp_header_buf_.rc = HEADER_RC_SUCCESS;
            }
            LOG("[*] try do_agg\n");
            p_em_->do_agg();
            break;
        }
        
        case HEADER_OP_GET_STATE: {
            this->resp_header_buf_.op_type = HEADER_OP_GET_STATE;
            this->resp_header_buf_.epoch_idx = this->req_header_buf_.epoch_idx;
            // const FLASEM::enc_state_t &enc_state = p_em_->get_global_state(this->req_header_buf_.epoch_idx);
            uint64_t enc_state_size = p_em_->get_global_state_size(this->req_header_buf_.epoch_idx);
            if (enc_state_size == 0) {
                this->resp_header_buf_.rc = HEADER_RC_FAILURE;
                this->resp_header_buf_.payload_size = 0;
            } else {
                this->resp_header_buf_.rc = HEADER_RC_SUCCESS;
                this->resp_header_buf_.payload_size = enc_state_size;
                // this->resp_payload_buf_.resize(enc_state.size());
            }
            // LOG("[*] get_global_state: %lx\n", enc_state.size());
            break;
        }
        
        default:
            break;
        }
        // std::cout << "[*] read " << n << "bytes" << std::endl;
        LOG("[*] before write response header\n");
        asio::async_write(
            socket_, 
            asio::buffer(&this->resp_header_buf_, sizeof(this->resp_header_buf_)),
            // buffer_,
            std::bind(&TCPConnection::handle_write_resp_header, shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
        LOG("[*] after write response header\n");
    }

    tcp::socket socket_;
    std::string message_;
    req_header_t req_header_buf_;
    resp_header_t resp_header_buf_;
    std::vector<uint8_t> payload_buf_;
    //   std::array <uint, 128> buffer_;
    asio::streambuf buffer_;
    std::shared_ptr<FLASEM> p_em_;
};


class FLASServer {
public:
    FLASServer(
        asio::io_context& io_context, 
        uint16_t port, 
        std::shared_ptr<FLASEM> p_em)
        : io_context_(io_context),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
        p_em_(p_em)
    {
        start_accept();
    }

private:
    void start_accept()
    {
        TCPConnection::pointer new_connection =
        TCPConnection::create(io_context_, p_em_);

        acceptor_.async_accept(new_connection->socket(),
            std::bind(&FLASServer::handle_accept, this, new_connection,
            std::placeholders::_1));
    }

    void handle_accept(TCPConnection::pointer new_connection,
        const asio::error_code& error)
    {
        if (!error)
            new_connection->start();
        start_accept();
    }

    asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    std::shared_ptr<FLASEM> p_em_;
};

void test_FLASEM();
void test_FLASServer();

#endif // _FLAS_API_H_