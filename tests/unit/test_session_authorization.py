
"""PQVPN session authorization unit-level integration tests."""

import os
import unittest

from modules.encryption.key_derivation import (
    SessionKeys,
)

from modules.networking.transport.session_authorization import (
    make_challenge,
    make_proof,
    check_proof,
    make_accept,
    check_accept,
)


class TestSessionAuthorization(unittest.TestCase):

    def setUp(self):
        self.keys = SessionKeys(
            client_to_server_key=os.urandom(32),
            server_to_client_key=os.urandom(32),
            client_nonce_prefix=os.urandom(4),
            server_nonce_prefix=os.urandom(4),
        )

        self.psk = os.urandom(32)
        self.challenge = make_challenge()

    def test_proof(self):
        proof = make_proof(
            self.psk,
            self.challenge,
            self.keys,
        )

        self.assertTrue(
            check_proof(
                self.psk,
                self.challenge,
                self.keys,
                proof,
            )
        )

    def test_wrong_psk(self):
        proof = make_proof(
            self.psk,
            self.challenge,
            self.keys,
        )

        self.assertFalse(
            check_proof(
                os.urandom(32),
                self.challenge,
                self.keys,
                proof,
            )
        )

    def test_wrong_challenge(self):
        proof = make_proof(
            self.psk,
            self.challenge,
            self.keys,
        )

        self.assertFalse(
            check_proof(
                self.psk,
                make_challenge(),
                self.keys,
                proof,
            )
        )

    def test_accept(self):
        proof = make_proof(
            self.psk,
            self.challenge,
            self.keys,
        )

        session_id = os.urandom(16)

        acceptance = make_accept(
            self.keys,
            session_id,
            self.challenge,
            proof,
        )

        self.assertEqual(
            check_accept(
                self.keys,
                acceptance,
                self.challenge,
                proof,
            ),
            session_id,
        )

    def test_tampered_accept(self):
        proof = make_proof(
            self.psk,
            self.challenge,
            self.keys,
        )

        acceptance = bytearray(
            make_accept(
                self.keys,
                os.urandom(16),
                self.challenge,
                proof,
            )
        )

        acceptance[-1] ^= 1

        with self.assertRaises(ValueError):
            check_accept(
                self.keys,
                bytes(acceptance),
                self.challenge,
                proof,
            )


if __name__ == "__main__":
    unittest.main()
