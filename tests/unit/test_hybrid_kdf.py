
import unittest

from modules.encryption.ecdh import (
    generate_keypair,
    derive_shared_secret,
)
from modules.encryption.pqc_kem import (
    generate_keypair as kem_generate,
    encapsulate,
    decapsulate,
)
from modules.encryption.key_derivation import (
    derive_session_keys,
    keys_match,
)


class TestHybridKDF(unittest.TestCase):

    def test_real_hybrid_key_agreement(self):
        client_private, client_public = generate_keypair()
        server_private, server_public = generate_keypair()

        client_ecdh = derive_shared_secret(
            client_private, server_public
        )
        server_ecdh = derive_shared_secret(
            server_private, client_public
        )

        kem_public, kem_private = kem_generate()
        ciphertext, client_kem = encapsulate(kem_public)
        server_kem = decapsulate(kem_private, ciphertext)

        # Canonical transcript fixture for this test only.
        transcript = (
            b"PQVPN-v1-test"
            + client_public
            + server_public
            + kem_public
            + ciphertext
        )

        client_keys = derive_session_keys(
            client_ecdh, client_kem, transcript
        )
        server_keys = derive_session_keys(
            server_ecdh, server_kem, transcript
        )

        self.assertTrue(keys_match(client_keys, server_keys))
        self.assertEqual(len(client_keys.client_to_server_key), 32)
        self.assertEqual(len(client_keys.server_to_client_key), 32)

        self.assertNotEqual(
            client_keys.client_to_server_key,
            client_keys.server_to_client_key,
        )

    def test_transcript_binding(self):
        x = b"\x11" * 32
        pq = b"\x22" * 32

        a = derive_session_keys(x, pq, b"handshake-A")
        b = derive_session_keys(x, pq, b"handshake-B")

        self.assertFalse(keys_match(a, b))

    def test_secret_binding(self):
        pq = b"\x22" * 32

        a = derive_session_keys(
            b"\x11" * 32, pq, b"handshake"
        )
        b = derive_session_keys(
            b"\x33" * 32, pq, b"handshake"
        )

        self.assertFalse(keys_match(a, b))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            derive_session_keys(
                b"short", b"\x22" * 32, b"handshake"
            )

        with self.assertRaises(ValueError):
            derive_session_keys(
                b"\x11" * 32, b"\x22" * 32, b""
            )


if __name__ == "__main__":
    unittest.main()
