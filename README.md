# Trusted Key Synchronization Module

A Intel SGX based module for synchronizing AES keys among many SGX enabled platforms.

## Quick Start

```bash
make
./app
```

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

## References

- [SGX Development Environment Setup](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
- [Setup A Local PCCS Service Tutorial](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html)