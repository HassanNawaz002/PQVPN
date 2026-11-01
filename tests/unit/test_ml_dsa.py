
import unittest

from modules.encryption.ml_dsa import (
    generate_keypair,
    sign_message,
    verify_signature,
    public_key_fingerprint,
    verify_pinned_identity,
    SignatureError,
)


class TestMLDSA65(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.secret_key = generate_keypair()
        cls.message = b"PQVPN gateway handshake transcript"
        cls.signature = sign_message(
            cls.secret_key,
            cls.message,
        )

    def test_valid_signature(self):
        self.assertTrue(
            verify_signature(
                self.public_key,
                self.message,
                self.signature,
            )
        )

    def test_modified_message_rejected(self):
        self.assertFalse(
            verify_signature(
                self.public_key,
                b"modified handshake",
                self.signature,
            )
        )

    def test_modified_signature_rejected(self):
        altered = bytearray(self.signature)
        altered[0] ^= 1

        self.assertFalse(
            verify_signature(
                self.public_key,
                self.message,
                bytes(altered),
            )
        )

    def test_wrong_public_key_rejected(self):
        other_public, _ = generate_keypair()

        self.assertFalse(
            verify_signature(
                other_public,
                self.message,
                self.signature,
            )
        )

    def test_pinned_gateway_identity(self):
        fingerprint = public_key_fingerprint(
            self.public_key
        )

        self.assertTrue(
            verify_pinned_identity(
                self.public_key,
                fingerprint,
                self.message,
                self.signature,
            )
        )

        self.assertFalse(
            verify_pinned_identity(
                self.public_key,
                "0" * 64,
                self.message,
                self.signature,
            )
        )

    def test_invalid_secret_key_rejected(self):
        with self.assertRaises(SignatureError):
            sign_message(b"invalid", self.message)


if __name__ == "__main__":
    unittest.main()
