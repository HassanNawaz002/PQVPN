
"""Tests for PQVPN identity-bound PSK authentication."""

import os
import unittest

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.client_identity_auth import (
    ClientIdentityAuthError,
    make_identity_proof,
    verify_identity_proof,
    validate_client_id,
)


class TestClientIdentityAuth(unittest.TestCase):

    def setUp(self):
        self.client_id = "client-a"
        self.psk = os.urandom(32)
        self.challenge = os.urandom(32)

        self.keys = SessionKeys(
            client_to_server_key=os.urandom(32),
            server_to_client_key=os.urandom(32),
            client_nonce_prefix=os.urandom(4),
            server_nonce_prefix=os.urandom(4),
        )

    def make_proof(self):
        return make_identity_proof(
            self.client_id,
            self.psk,
            self.challenge,
            self.keys,
        )

    def verify(self, proof, **changes):
        values = {
            "client_id": self.client_id,
            "psk": self.psk,
            "challenge": self.challenge,
            "keys": self.keys,
            "received": proof,
        }
        values.update(changes)
        return verify_identity_proof(**values)

    def test_valid_proof(self):
        self.assertTrue(
            self.verify(self.make_proof())
        )

    def test_proof_length(self):
        self.assertEqual(
            len(self.make_proof()),
            48,
        )

    def test_wrong_client_identity_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                client_id="client-b",
            )
        )

    def test_wrong_psk_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                psk=os.urandom(32),
            )
        )

    def test_wrong_challenge_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                challenge=os.urandom(32),
            )
        )

    def test_wrong_session_keys_rejected(self):
        other_keys = SessionKeys(
            os.urandom(32),
            os.urandom(32),
            os.urandom(4),
            os.urandom(4),
        )

        self.assertFalse(
            self.verify(
                self.make_proof(),
                keys=other_keys,
            )
        )

    def test_tampered_proof_rejected(self):
        proof = bytearray(self.make_proof())
        proof[0] ^= 1

        self.assertFalse(
            self.verify(bytes(proof))
        )

    def test_short_proof_rejected(self):
        self.assertFalse(
            self.verify(b"invalid")
        )

    def test_invalid_identity_rejected(self):
        with self.assertRaises(ClientIdentityAuthError):
            validate_client_id("../client-a")

    def test_empty_identity_rejected(self):
        with self.assertRaises(ClientIdentityAuthError):
            validate_client_id("")

    def test_invalid_psk_length_rejected(self):
        with self.assertRaises(ClientIdentityAuthError):
            make_identity_proof(
                self.client_id,
                b"short",
                self.challenge,
                self.keys,
            )

    def test_distinct_client_proofs(self):
        proof_a = make_identity_proof(
            "client-a",
            self.psk,
            self.challenge,
            self.keys,
        )

        proof_b = make_identity_proof(
            "client-b",
            self.psk,
            self.challenge,
            self.keys,
        )

        self.assertNotEqual(
            proof_a,
            proof_b,
        )


if __name__ == "__main__":
    unittest.main()
