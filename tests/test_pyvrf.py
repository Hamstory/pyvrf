import unittest

import pyvrf


TEST_SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
TEST_PK = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
TEST_PROOF = bytes.fromhex('b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900')
TEST_OUTPUT = bytes.fromhex('5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc')
TEST_MSG = b''


class TestPyvrf(unittest.TestCase):
    def test_vrf_constants(self):
        self.assertEqual(pyvrf.crypto_vrf_secretkeybytes, 64)
        self.assertEqual(pyvrf.crypto_vrf_publickeybytes, 32)
        self.assertEqual(pyvrf.crypto_vrf_seedbytes, 32)
        self.assertEqual(pyvrf.crypto_vrf_proofbytes, 80)
        self.assertEqual(pyvrf.crypto_vrf_outputbytes, 64)

    def test_crypto_vrf_keypair(self):
        pk, sk = pyvrf.crypto_vrf_keypair()
        self.assertEqual(pk, sk[32:])

    def test_crypto_vrf_keypair_from_seed(self):
        pk, sk = pyvrf.crypto_vrf_keypair_from_seed(TEST_SEED)
        self.assertEqual(pk, TEST_PK)

    def test_crypto_vrf_is_valid_key(self):
        pk, sk = pyvrf.crypto_vrf_keypair_from_seed(TEST_SEED)

        result = pyvrf.crypto_vrf_is_valid_key(pk)
        self.assertTrue(result)

    def test_crypto_vrf_prove(self):
        pk, sk = pyvrf.crypto_vrf_keypair_from_seed(TEST_SEED)

        proof = pyvrf.crypto_vrf_prove(sk, TEST_MSG)
        self.assertEqual(proof, TEST_PROOF)

    def test_crypto_vrf_verify(self):
        pk, sk = pyvrf.crypto_vrf_keypair_from_seed(TEST_SEED)

        output = pyvrf.crypto_vrf_verify(pk, TEST_PROOF, TEST_MSG)
        self.assertEqual(output, TEST_OUTPUT)

        with self.assertRaises(ValueError):
            pyvrf.crypto_vrf_verify(pk, b'0' + TEST_PROOF[1:], TEST_MSG)

        with self.assertRaises(ValueError):
            pyvrf.crypto_vrf_verify(pk, TEST_PROOF, b'123')

    def test_crypto_proof_to_hash(self):
        output = pyvrf.crypto_vrf_proof_to_hash(TEST_PROOF)
        self.assertEqual(output, TEST_OUTPUT)

        output = pyvrf.crypto_vrf_proof_to_hash(b'0' + TEST_PROOF[1:])
        self.assertNotEqual(output, TEST_OUTPUT)

        with self.assertRaises(ValueError):
            pyvrf.crypto_vrf_proof_to_hash(TEST_PROOF[1:])

    def test_crypto_vrf_sk_to_pk(self):
        pk, sk = pyvrf.crypto_vrf_keypair_from_seed(TEST_SEED)

        self.assertEqual(pk, pyvrf.crypto_vrf_sk_to_pk(sk))

    def test_crypto_vrf_sk_to_seed(self):
        pk, sk = pyvrf.crypto_vrf_keypair_from_seed(TEST_SEED)

        self.assertEqual(TEST_SEED, pyvrf.crypto_vrf_sk_to_seed(sk))

