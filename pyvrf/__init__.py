import ctypes
import ctypes.util

sodium = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium') or ctypes.util.find_library('libsodium'))
if not sodium._name:
    raise ValueError('Unable to find libsodium')


crypto_vrf_publickeybytes = sodium.crypto_vrf_publickeybytes()
crypto_vrf_secretkeybytes = sodium.crypto_vrf_secretkeybytes()
crypto_vrf_seedbytes = sodium.crypto_vrf_seedbytes()
crypto_vrf_proofbytes = sodium.crypto_vrf_proofbytes()
crypto_vrf_outputbytes = sodium.crypto_vrf_outputbytes()


def __check(code):
    if code != 0:
        raise ValueError


def crypto_vrf_keypair():
    pk = ctypes.create_string_buffer(crypto_vrf_publickeybytes)
    sk = ctypes.create_string_buffer(crypto_vrf_secretkeybytes)
    __check(sodium.crypto_vrf_keypair(pk, sk))
    return pk.raw, sk.raw


def crypto_vrf_keypair_from_seed(seed: bytes):
    if seed is None:
        raise ValueError("Invalid parameters")
    if not (len(seed) == crypto_vrf_seedbytes):
        raise ValueError("Invalid seed")

    pk = ctypes.create_string_buffer(crypto_vrf_publickeybytes)
    sk = ctypes.create_string_buffer(crypto_vrf_secretkeybytes)
    __check(sodium.crypto_vrf_keypair_from_seed(pk, sk, ctypes.c_char_p(seed)))
    return pk.raw, sk.raw


def crypto_vrf_is_valid_key(pk: bytes):
    if pk is None:
        raise ValueError("Invalid parameters")
    if not (len(pk) == crypto_vrf_publickeybytes):
        raise ValueError("Invalid public key")

    result = sodium.crypto_vrf_is_valid_key(ctypes.c_char_p(pk))
    return result == 1


def crypto_vrf_prove(sk: bytes, message: bytes):
    if None in (sk, message):
        raise ValueError("Invalid parameters")
    if not (len(sk) == crypto_vrf_secretkeybytes):
        raise ValueError("Invalid secret key")

    proof = ctypes.create_string_buffer(crypto_vrf_proofbytes)
    __check(sodium.crypto_vrf_ietfdraft03_prove(proof, ctypes.c_char_p(sk),
                                                ctypes.c_char_p(message),
                                                len(message)))
    return proof.raw


def crypto_vrf_verify(pk: bytes, proof: bytes, message: bytes):
    if None in (pk, proof, message):
        raise ValueError("Invalid parameters")
    if not (len(pk) == crypto_vrf_publickeybytes):
        raise ValueError("Invalid public key")
    if not (len(proof) == crypto_vrf_proofbytes):
        raise ValueError("Invalid proof")

    output = ctypes.create_string_buffer(crypto_vrf_outputbytes)
    __check(sodium.crypto_vrf_verify(output, ctypes.c_char_p(pk),
                                     ctypes.c_char_p(proof),
                                     ctypes.c_char_p(message), len(message)))
    return output.raw


def crypto_vrf_proof_to_hash(proof: bytes):
    if proof is None:
        raise ValueError("Invalid parameters")
    if not (len(proof) == crypto_vrf_proofbytes):
        raise ValueError("Invalid proof")

    output = ctypes.create_string_buffer(crypto_vrf_outputbytes)
    __check(sodium.crypto_vrf_proof_to_hash(output, ctypes.c_char_p(proof)))
    return output.raw


def crypto_vrf_sk_to_pk(sk: bytes):
    if sk is None:
        raise ValueError("Invalid parameters")
    if not (len(sk) == crypto_vrf_secretkeybytes):
        raise ValueError("Invalid secret key")

    pk = ctypes.create_string_buffer(crypto_vrf_publickeybytes)
    sodium.crypto_vrf_sk_to_pk(pk, sk)
    return pk.raw


def crypto_vrf_sk_to_seed(sk: bytes):
    if sk is None:
        raise ValueError("Invalid parameters")
    if not (len(sk) == crypto_vrf_secretkeybytes):
        raise ValueError("Invalid secret key")

    seed = ctypes.create_string_buffer(crypto_vrf_seedbytes)
    sodium.crypto_vrf_sk_to_seed(seed, ctypes.c_char_p(sk))
    return seed.raw
