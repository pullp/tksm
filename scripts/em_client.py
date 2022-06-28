# from struct import pack, unpack
# import enum
import struct
import time
# import psutil
# from threading import local

import numpy as np
# from pwn import remote

import aes_utils
import state

FLAS_ADDR = ("127.0.0.1", 666)

HEADER_MAGIC = 0xdeadbeef
HEADER_OP_ADD_STATE  = 0x1
HEADER_OP_GET_STATE  = 0x2

REQ_HEADER_SIZE = 48
RESP_HEADER_SIZE = 32

import socket

class Remote:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
    
    def send(self, data):
        self.sock.sendall(data)
    
    def recv(self, n):
        return self.sock.recv(n)
    
    def recvnb(self, n):
        buf = b''
        while len(buf) < n:
            tmp = self.sock.recv(n - len(buf))
            buf += tmp
            if not tmp:
                break
        if len(buf) != n:
            print(f"{n}, {len(buf)}")
            raise Exception("connection closed")
        return buf

    def close(self):
        self.sock.close()

def pack_req_header(op_type, client_id, nonce, sample_cnt, epoch_idx, payload_size):
    
    p =  struct.pack('<I', HEADER_MAGIC)
    p += struct.pack("<I", op_type)
    p += struct.pack('<Q', client_id)
    p += struct.pack('<Q', nonce)
    p += struct.pack('<Q', sample_cnt)
    p += struct.pack('<Q', epoch_idx)
    p += struct.pack('<Q', payload_size)

    return p

def unpack_req_header(p):
    res = (
        struct.unpack('<I', p[0:4])[0], 
        struct.unpack('<I', p[4:8])[0], 
        struct.unpack('<Q', p[8:16])[0], 
        struct.unpack('<Q', p[16:24])[0], 
        struct.unpack('<Q', p[24:32])[0], 
        struct.unpack('<Q', p[32:40])[0],
        struct.unpack('<Q', p[40:48])[0]
    )
    return res

def pack_resp_header(op_type, rc, epoch_idx, payload_size):
    p =  struct.pack('<I', HEADER_MAGIC)
    p += struct.pack("<I", op_type)
    p += struct.pack('<Q', rc)
    p += struct.pack('<Q', epoch_idx)
    p += struct.pack('<Q', payload_size)
    return p

def unpack_resp_header(p):
    res = (
        struct.unpack('<I', p[0:4])[0], 
        struct.unpack('<I', p[4:8])[0], 
        struct.unpack('<Q', p[8:16])[0], 
        struct.unpack('<Q', p[16:24])[0],
        struct.unpack('<Q', p[24:32])[0]
    )
    return res


def update_state(addr, epoch_idx, sample_cnt, payload):
    # io = remote(*addr)
    io = Remote(*addr)
    s = pack_req_header(
        HEADER_OP_ADD_STATE,
        1,
        0x1234,
        sample_cnt,
        epoch_idx,
        len(payload))
    
    s += payload
    io.send(s)
    resp_header  = io.recv(RESP_HEADER_SIZE)
    resp_header = unpack_resp_header(resp_header)
    io.close()
    return resp_header

def get_state(addr, epoch_idx):
    # io = remote(*addr)
    io = Remote(*addr)
    req = pack_req_header(
        HEADER_OP_GET_STATE,
        0,
        0,
        0,
        epoch_idx,
        0)
    io.send(req)
    resp_header  = io.recv(RESP_HEADER_SIZE)
    resp_header = unpack_resp_header(resp_header)
    # return resp_header, io
    data = io.recvnb(resp_header[4])
    # # data = io.recvrepeat(3)
    # print(f"{len(data)}, {resp_header[4]}")
    assert(len(data) == resp_header[4])
    # io.close()
    return resp_header, data

# prettify the output
def pf(resp_header):
    if resp_header[0] != HEADER_MAGIC:
        print("Invalid header magic")
        return
    s = f"op_type: {resp_header[1]:x}\n"
    s += f"rc: {resp_header[2]:x}\n"
    s += f"epoch_idx: {resp_header[3]:x}\n"
    s += f"payload_size: {resp_header[4]:x}\n"
    print(s)
    return s

def rFedAvg_enc(addr, epoch_idx, sample_cnts, local_states, shape_info):
    assert(len(sample_cnts) == len(local_states))
    for i in range(len(sample_cnts)):
        sample_cnt = sample_cnts[i]
        local_state = local_states[i]
        local_state_packed = state.pack_state(local_state)
        local_state_packed_enc = aes_utils.encrypt(aes_utils.KEY, local_state_packed, aes_utils.NONCE)
        resp = update_state(addr, epoch_idx, sample_cnt, local_state_packed_enc)
        # print(f"update state {i}")
        # pf(resp)
    
    resp, rglobal_state_packed_enc = get_state(addr, epoch_idx)
    if resp[2] != 0:
        print("get state failed")
        return None
    rglobal_state_packed = aes_utils.decrypt(aes_utils.KEY, rglobal_state_packed_enc)
    rglobal_state = state.unpack_state(rglobal_state_packed, shape_info)
    return rglobal_state
    
def state_is_eq(s1, s2):
    if s1.keys() != s2.keys():
        return False
    for k in global_state.keys():
        l = global_state[k]
        rl = rglobal_state[k]
        # print(f"{np.isclose(l, rl).all()}")
        if not np.isclose(l, rl).all():
            print(f"differrent: {k}\n{l}\n{rl}")
            return False
    return True


def extract_state_shape_info(state):
    shape_info = {}
    for k in state.keys():
        shape_info[k] = state[k].shape
    return shape_info

# HOST = '0.0.0.0'
# PORT = 7000

def test_socket_client(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect()

    while True:
        outdata = input('please input message: ')
        print('send: ' + outdata)
        s.send(outdata.encode())
        
        indata = s.recv(1024)
        if len(indata) == 0: # connection closed
            s.close()
            print('server closed connection.')
            break
        print('recv: ' + indata.decode())

if __name__ == "__main__":
    # shape_info, _ = state.generate_rand_params()
    ratios = [1.0 / 3.0] * 3
    sample_cnts = [0x100] * 3


    t1s = []
    t2s = []

    for i in range(7):
        ## Save states
        _, s1 = state.generate_rand_params()
        _, s2 = state.generate_rand_params()
        _, s3 = state.generate_rand_params()
        shape_info = extract_state_shape_info(s1)

        # state.save_state(s1, "s1.dat")
        # state.save_state(s2, "s2.dat")
        # state.save_state(s3, "s3.dat")

        # s1 = state.load_state("s1.dat", shape_info)
        # s2 = state.load_state("s2.dat", shape_info)
        # s3 = state.load_state("s3.dat", shape_info)

        local_states = [s1, s2, s3]
        st = time.time()
        global_state = state.FedAvg(local_states, ratios)
        ed = time.time()
        t1 = ed - st
        t1s.append(t1)
        print("FedAvg: ", t1)
        st = time.time()
        rglobal_state = rFedAvg_enc(FLAS_ADDR, i, sample_cnts, local_states, shape_info)
        ed = time.time()
        t2 = ed - st 
        t2s.append(t2)
        print("rFedAvg: ", t2)
        if rglobal_state is None:
            print("rglobal_state is None")
            continue
        state_is_eq(global_state, rglobal_state)

# local_states_packed = list(map(state.pack_state, local_states))

# local_states_packed_enc = list(map(lambda m: aes_utils.encrypt(aes_utils.KEY, m, aes_utils.NONCE), local_states_packed))

# for (i, payload) in enumerate(local_states_packed_enc):
#     print(f"update state {i}")
#     resp = update_state(FLAS_ADDR, 0, 0x100, payload)
#     pf(resp)
#     # input("Press Enter to continue...")
#     # open(f"../states/s{i + 1}.enc", "wb").write(payload)

# resp, rglobal_state_packed_enc = get_state(FLAS_ADDR, 0)

# rglobal_state_packed = aes_utils.decrypt(aes_utils.KEY, rglobal_state_packed_enc)
# rglobal_state = state.unpack_state(rglobal_state_packed, shape_info)


# io.interactive()


def gen_enc_state(weight_cnt, path):
    s = b'\x00' * 4 * weight_cnt
    s = struct.pack("<Q", weight_cnt) + s
    s_enc = aes_utils.encrypt(aes_utils.KEY, s, aes_utils.NONCE)
    open(path, "wb").write(s_enc)
    # return s_enc
    