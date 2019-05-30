This is a very simple wrapper around algorand forked libsodium with vrf.


## Install libsodium of algorand

```shell
$ git clone https://github.com/algorand/libsodium
$ cd libsodium
$ ./autogen.sh
$ make && make check
$ sudo make install 
```


## Install pyvrf

```shell
$ git clone https://github.com/hamstory/pyvrf
$ cd pyvrf
$ pip install .
```

## VRF constants

```
pyvrf.crypto_vrf_secretkeybytes     # 64
pyvrf.crypto_vrf_publickeybytes     # 32
pyvrf.crypto_vrf_seedbytes          # 32
pyvrf.crypto_vrf_proofbytes         # 80
pyvrf.crypto_vrf_outputbytes        # 64
```

Note that secret key is 64 byte. Here, secret key consists of seed(32byte) + public key(32byte).

## Example

```python
import pyvrf

pk, sk = pyvrf.crypto_vrf_keypair()
print(pk.hex())
print(sk.hex())
```

More usages are in `tests/test_pyvrf.py`


## VRF functions

### `crypto_vrf_keypair()`

Internally generates a random seed and generates a secret key and a public key.

### `crypto_vrf_keypair_from_seed(seed: bytes)`

Creates a secret key and a public key with the given random seed.

### `crypto_vrf_is_valid_key(pk: bytes)`

Ensure that the public key is a valid key.

### `crypto_vrf_prove(sk: bytes, message: bytes)`

Create a proof with a secret key and a message.

### `crypto_vrf_proof_to_hash(proof: bytes)`

Use the generated proof to get a random hash. This function does not validate the proof. To verify and get the random hash, you should use the `crypto_vrf_verify` function.

### `crypto_vrf_verify(pk: bytes, proof: bytes, message: bytes)`

Verify the proof with the message, public key and get the random hash coming out of the proof.

### `crypto_vrf_sk_to_pk(sk: bytes)`

Get the public key from the secret key

### `crypto_vrf_sk_to_seed(sk: bytes)`

Get the seed from the secret key
