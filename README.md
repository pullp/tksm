# Trusted Key Synchronization Module

## APIs
- generate_asymmetric_key
    - input: None
    - output: pub_key, Sealed(priv_key), Quote(hash(pub_key))
- generate_symmetric_key
    - input: None
    - output: Sealed(sym_key), Quote(hash(sym_key))
- export_symmetric_key
    - input: Sealed(sym_key), pub_key2, Quote(hash(pub_key2))
    - output: Enc(sym_key, pub_key2)
- import_symmetric_key
    - input: Sealed(priv_key), Enc(sym_key, pub_key), Quote(hash(sym_key))
    - output: Sealed(sym_key)
