
import unittest

from modules.encryption.pqc_kem import (
    generate_keypair,
    encapsulate,
    decapsulate,
    KEMError,
    PUBLIC_KEY_BYTES,
    SECRET_KEY_BYTES,
    CIPHERTEXT_BYTES,
    SHARED_SECRET_BYTES,
)


class TestMLKEM1024(unittest.TestCase):

    def test_shared_secret_agreement(self):
        public_key, secret_key = generate_keypair()

        ciphertext, sender_secret = encapsulate(
            public_key
        )

        receiver_secret = decapsulate(
            secret_key, ciphertext
        )

        self.assertEqual(
            sender_secret, receiver_secret
        )
        self.assertEqual(
            len(sender_secret), SHARED_SECRET_BYTES
        )

    def test_standard_output_lengths(self):
        public_key, secret_key = generate_keypair()
        ciphertext, shared_secret = encapsulate(
            public_key
        )

        self.assertEqual(
            len(public_key), PUBLIC_KEY_BYTES
        )
        self.assertEqual(
            len(secret_key), SECRET_KEY_BYTES
        )
        self.assertEqual(
            len(ciphertext), CIPHERTEXT_BYTES
        )
        self.assertEqual(
            len(shared_secret), SHARED_SECRET_BYTES
        )

    def test_invalid_public_key_rejected(self):
        with self.assertRaises(KEMError):
            encapsulate(b"invalid")

    def test_invalid_ciphertext_rejected(self):
        _, secret_key = generate_keypair()

        with self.assertRaises(KEMError):
            decapsulate(secret_key, b"invalid")

    def test_independent_exchanges(self):
        public_key, secret_key = generate_keypair()

        ciphertext1, secret1 = encapsulate(public_key)
        ciphertext2, secret2 = encapsulate(public_key)

        self.assertNotEqual(ciphertext1, ciphertext2)
        self.assertNotEqual(secret1, secret2)

        self.assertEqual(
            decapsulate(secret_key, ciphertext1),
            secret1,
        )
        self.assertEqual(
            decapsulate(secret_key, ciphertext2),
            secret2,
        )


if __name__ == "__main__":
    unittest.main()

