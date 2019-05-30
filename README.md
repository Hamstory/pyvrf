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
$ pip install .
```

## VRF types

```
pyvrf.crypto_vrf_secretkeybytes == 64
pyvrf.crypto_vrf_publickeybytes == 32
pyvrf.crypto_vrf_seedbytes == 32
pyvrf.crypto_vrf_proofbytes == 80
pyvrf.crypto_vrf_outputbytes == 64
```

secret key가 64 byte인 것에 주의. 여기서 secret key는 seed(32byte) + public key(32byte)를 연결한 값이다.

## Example

Refer to `tests/test_pyvrf`


## VRF functions

### `crypto_vrf_keypair()`

내부적으로 random seed생성 하고 secret key와 public key를 생성한다.

### `crypto_vrf_keypair_from_seed(seed: bytes)`

주어진 random seed를 가지고 secret key와 public key를 생성한다.

### `crypto_vrf_is_valid_key(pk: bytes)`

해당 public key가 제대로된 key인지 확인한다.

### `crypto_vrf_prove(sk: bytes, message: bytes)`

secret key와 message를 가지고 proof를 생성한다.

### `crypto_vrf_proof_to_hash(proof: bytes)`

생성된 proof를 이용해서 random hash를 가져온다. 이 함수는 proof를 검증하지 않는다. 검증하고 결과 random hash를 받아오기 위해서는 `crypto_vrf_verify` 함수를 이용해야 한다.

### `crypto_vrf_verify(pk: bytes, proof: bytes, message: bytes)`

proof를 message, public key를 이용해서 검증하고 해당 proof를 통해 나오는 random hash를 가져온다.

### `crypto_vrf_sk_to_pk(sk: bytes)`

secret key에서 public key를 가져온다(secret key의 뒤 32byte가 이미 public key).

### `crypto_vrf_sk_to_seed(sk: bytes)`

secret key에서 seed를 가져온다(secret key의 앞 32byte가 이미 seed).

