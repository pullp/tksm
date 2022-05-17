import copy
import struct
from turtle import shape
import numpy as np
import pandas as pd
import torch
import json
from collections import OrderedDict
from functools import reduce


def dumps_state(state):
    layers = []
    keys = state.keys()
    for k in keys:
        w = state[k]
        w_np = np.array(w)
        w_l = w_np.tolist()
        w_s = json.dumps(w_l)
        layers.append((k, w_s))
    return json.dumps(layers)

def loads_state(s):
    res = OrderedDict()
    layers_s = json.loads(s)
    for (k, w_s) in layers_s:
        w_l = json.loads(w_s)
        w_np = np.array(w_l)
        w = torch.tensor(w_np, dtype=torch.float32)
        res[k] = w
    return res

def pack_tensor(t):
    return t.cpu().numpy().tobytes()

def unpack_tensor(t, shape):
    return torch.tensor(np.frombuffer(t, dtype=np.float32).reshape(shape), dtype=torch.float32)

def get_shape_product(shape):
    res = reduce(lambda a, b: a * b, shape, 1)
    # print(f"shape: {shape}, product: {res}")
    return res


# corresponding to `state_t`
def pack_state(state):
    weights = b''
    cnt = 0
    for k in state.keys():
        w_raw = state[k]
        w_ba = pack_tensor(w_raw)
        weights += w_ba
        cnt += get_shape_product(w_raw.shape)
    
    return struct.pack("<Q", cnt) + weights

def unpack_state(ba, shape_info):
    assert(8 <= len(ba))
    res = OrderedDict()
    cnt = struct.unpack("<Q", ba[:8])[0]
    cnt *= 4 # 4 bytes per float
    assert(cnt < 1e6)
    w_ba = ba[8:]

    for k in shape_info.keys():
        shape = shape_info[k]
        shape_cnt = get_shape_product(shape)
        shape_cnt *= 4 # 4 bytes per float
        assert(shape_cnt <= len(w_ba))
        w_raw = unpack_tensor(w_ba[:shape_cnt], shape)
        # assert(len(w_raw) == shape_cnt)
        w_ba = w_ba[shape_cnt:]
        cnt -= shape_cnt
        res[k] = w_raw
    assert(len(w_ba) == 0)
    return res


def generate_rand_params():
    s = OrderedDict()
    s['0'] = torch.rand((1, 2, 3), dtype=torch.float32)
    s['1'] = torch.rand((3, 4, 5), dtype=torch.float32)
    s['2'] = torch.rand((4, 5, 6), dtype=torch.float32)
    s['3'] = torch.rand((5, 6, 7), dtype=torch.float32)
    s['4'] = torch.rand((6, 7, 8), dtype=torch.float32)
    s['5'] = torch.rand((7, 8, 9), dtype=torch.float32)
    s['6'] = torch.rand((8, 9, 10), dtype=torch.float32)
    s['7'] = torch.rand((9, 10, 11), dtype=torch.float32)

    shape_info = OrderedDict()
    shape_info['0'] = (1, 2, 3)
    shape_info['1'] = (3, 4, 5)
    shape_info['2'] = (4, 5, 6)
    shape_info['3'] = (5, 6, 7)
    shape_info['4'] = (6, 7, 8)
    shape_info['5'] = (7, 8, 9)
    shape_info['6'] = (8, 9, 10)
    shape_info['7'] = (9, 10, 11)

    return shape_info, s

STATE_DIR = "./states"
def save_state(s, filename):
    with open(f"{STATE_DIR}/{filename}", 'wb') as f:
        f.write(pack_state(s))

def load_state(filename, shape_info):
    with open(f"{STATE_DIR}/{filename}", 'rb') as f:
        ba = f.read()
    return unpack_state(ba, shape_info)

def FedAvg(l_params, ratios):
    print(f"[*] {len(l_params)} - {len(ratios)}")
    assert(len(l_params) == len(ratios))
    avg_params = copy.deepcopy(l_params[0]) 
    for k in avg_params.keys():
        avg_params[k] = torch.mul(avg_params[k], ratios[0])
    for k in avg_params.keys():
        for i in range(1, len(l_params)):
            avg_params[k] += torch.mul(l_params[i][k], ratios[i])
        avg_params[k] = torch.div(avg_params[k], sum(ratios))
    return avg_params

# shape_info, _ = generate_rand_params()
# ratios = [1.0 / 3.0] * 3

## Save states
# _, s1 = generate_rand_params()
# _, s2 = generate_rand_params()
# _, s3 = generate_rand_params()
# local_states = [s1, s2, s3]

# global_state = FedAvg(local_states, ratios)

# save_state(s1, "s1.dat")
# save_state(s2, "s2.dat")
# save_state(s3, "s3.dat")
# save_state(global_state, "global.dat")

## Load states
# s1 = load_state("s1.dat", shape_info)
# s2 = load_state("s2.dat", shape_info)
# s3 = load_state("s3.dat", shape_info)
# local_states = [s1, s2, s3]

# global_state = load_state("global.dat", shape_info)
# global_state2 = FedAvg(local_states, ratios)

# arr = [0.232604, 0.477567, 0.875223, 0.410289, 0.709902, 0.339463]




# s_packed = pack_state(s1)
# s_unpacked = unpack_state(s_packed, shape_info)

# for k in s.keys():
#     w1 = s[k]
#     w2 = s_unpacked[k]
#     assert(torch.eq(w1, w2).all() == True)