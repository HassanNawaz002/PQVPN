
"""Tests for PQVPN cryptographic rekey predecessor proof."""

import os
import unittest

from modules.networking.transport.rekey_ownership import (
    CHALLENGE_SIZE,
    PROOF_SIZE,
    RekeyOwnershipError,
    derive_ownership_key,
    make_rekey_ownership_proof,
    verify_rekey_ownership_proof,
)


class TestRekeyOwnership(unittest.TestCase):

    def setUp(self):
        self.old_id = os.urandom(16)
        self.new_id = os.urandom(16)
        self.challenge = os.urandom(CHALLENGE_SIZE)

        self.old_c2s = os.urandom(32)
        self.old_s2c = os.urandom(32)
        self.new_c2s = os.urandom(32)
        self.new_s2c = os.urandom(32)

    def make_proof(self):
        return make_rekey_ownership_proof(
            self.old_id,
            self.new_id,
            self.challenge,
            self.old_c2s,
            self.old_s2c,
            self.new_c2s,
            self.new_s2c,
        )

    def verify(self, proof, **changes):
        values = {
            "old_session_id": self.old_id,
            "new_session_id": self.new_id,
            "challenge": self.challenge,
            "old_client_to_server_key": self.old_c2s,
            "old_server_to_client_key": self.old_s2c,
            "new_client_to_server_key": self.new_c2s,
            "new_server_to_client_key": self.new_s2c,
        }

        values.update(changes)

        return verify_rekey_ownership_proof(
            proof,
            **values,
        )

    def test_valid_ownership_proof(self):
        proof = self.make_proof()

        self.assertEqual(len(proof), PROOF_SIZE)
        self.assertTrue(self.verify(proof))

    def test_wrong_old_session_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                old_session_id=os.urandom(16),
            )
        )

    def test_wrong_new_session_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                new_session_id=os.urandom(16),
            )
        )

    def test_wrong_challenge_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                challenge=os.urandom(CHALLENGE_SIZE),
            )
        )

    def test_wrong_old_keys_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                old_client_to_server_key=os.urandom(32),
            )
        )

    def test_wrong_new_keys_rejected(self):
        self.assertFalse(
            self.verify(
                self.make_proof(),
                new_server_to_client_key=os.urandom(32),
            )
        )

    def test_tampered_proof_rejected(self):
        proof = bytearray(self.make_proof())
        proof[-1] ^= 1

        self.assertFalse(
            self.verify(bytes(proof))
        )

    def test_invalid_proof_length_rejected(self):
        self.assertFalse(
            self.verify(b"invalid")
        )

    def test_identical_session_ids_rejected(self):
        with self.assertRaises(RekeyOwnershipError):
            make_rekey_ownership_proof(
                self.old_id,
                self.old_id,
                self.challenge,
                self.old_c2s,
                self.old_s2c,
                self.new_c2s,
                self.new_s2c,
            )

    def test_invalid_key_length_rejected(self):
        with self.assertRaises(RekeyOwnershipError):
            derive_ownership_key(
                b"short",
                self.old_s2c,
            )

    def test_domain_separated_ownership_key(self):
        key = derive_ownership_key(
            self.old_c2s,
            self.old_s2c,
        )

        self.assertEqual(len(key), PROOF_SIZE)
        self.assertNotEqual(key, self.old_c2s)
        self.assertNotEqual(key, self.old_s2c)


if __name__ == "__main__":
    unittest.main()
