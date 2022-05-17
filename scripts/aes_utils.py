import struct
from Crypto.Cipher import AES

KEY = b"\x10\x48\x0e\xc5\xc4\xe8\xac\xa8\xfd\xc7\xf5\x20\xef\x22\xc4\xb9"
NONCE = b"greedisgood."

def unpack_enc_data(s):
    nonce = s[0:12]
    padding = s[12:16]
    mac = s[16:32]
    data_size = struct.unpack('<Q', s[32:40])[0]
    data = s[40:]
    assert(len(data) == data_size)

    return nonce, mac, data

def pack_enc_data(nonce, mac, data):
    s = nonce
    s += b'\x00' * 4 # padding
    s += mac 
    s += struct.pack("<Q", len(data))
    s += data
    return s

def encrypt(key, plaintext, nonce):
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, mac = aes.encrypt_and_digest(plaintext)
    return pack_enc_data(nonce, mac, ciphertext)

def decrypt(key, ciphertext):
    nonce, mac, data = unpack_enc_data(ciphertext)
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(data, mac)
    return plaintext
    

# key = b"a" * 16
# nonce = b"greedisgood." # also known as iv in SGX-SDK

# s = open('./encrypted', 'rb').read()
# nonce, mac, data = unpack_enc_data(s)

# cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)

# dec = cipher.decrypt_and_verify(data, mac)


# plaintext = open('plaintext', 'rb').read()
# ciphertext = encrypt(KEY, plaintext, NONCE)

# open("encrypted2", "wb").write(ciphertext)