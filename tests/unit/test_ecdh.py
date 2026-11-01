
import unittest

from modules.encryption.ecdh import (
    generate_keypair,
    derive_shared_secret,
)


class TestX25519(unittest.TestCase):

    def test_matching_shared_secrets(self):
        alice_private, alice_public = generate_keypair()
        bob_private, bob_public = generate_keypair()

        alice_secret = derive_shared_secret(
            alice_private, bob_public
        )
        bob_secret = derive_shared_secret(
            bob_private, alice_public
        )

        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(len(alice_secret), 32)

    def test_invalid_public_key_length(self):
        private_key, _ = generate_keypair()

        with self.assertRaises(ValueError):
            derive_shared_secret(private_key, b"invalid")

    def test_different_peers_different_secrets(self):
        alice_private, _ = generate_keypair()
        _, bob_public = generate_keypair()
        _, charlie_public = generate_keypair()

        secret_bob = derive_shared_secret(
            alice_private, bob_public
        )
        secret_charlie = derive_shared_secret(
            alice_private, charlie_public
        )

        self.assertNotEqual(secret_bob, secret_charlie)


if __name__ == "__main__":
    unittest.main()
