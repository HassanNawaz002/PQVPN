
"""Gateway multi-client authorization security tests."""

import os
import unittest

from gateway.client_credentials import (
    ClientCredentialRegistry,
)

from gateway.client_authorization import (
    ClientAuthorizationService,
    ClientAuthorizationError,
    AuthorizedClient,
)

from modules.encryption.key_derivation import SessionKeys

from modules.networking.transport.client_identity_auth import (
    make_identity_proof,
)


class TestClientAuthorization(unittest.TestCase):

    def setUp(self):
        self.credentials = ClientCredentialRegistry()

        self.psk_a = os.urandom(32)
        self.psk_b = os.urandom(32)

        self.credentials.add_client(
            "client-a",
            self.psk_a,
        )

        self.credentials.add_client(
            "client-b",
            self.psk_b,
        )

        self.service = ClientAuthorizationService(
            self.credentials
        )

        self.challenge = os.urandom(32)

        self.keys = SessionKeys(
            client_to_server_key=os.urandom(32),
            server_to_client_key=os.urandom(32),
            client_nonce_prefix=os.urandom(4),
            server_nonce_prefix=os.urandom(4),
        )

    def proof(self, client_id, psk, challenge=None, keys=None):
        return make_identity_proof(
            client_id,
            psk,
            self.challenge if challenge is None else challenge,
            self.keys if keys is None else keys,
        )

    def authorize(self, client_id, proof):
        return self.service.authorize(
            client_id,
            self.challenge,
            self.keys,
            proof,
        )

    def test_client_a_authorized(self):
        result = self.authorize(
            "client-a",
            self.proof("client-a", self.psk_a),
        )

        self.assertEqual(
            result,
            AuthorizedClient("client-a"),
        )

    def test_client_b_authorized(self):
        result = self.authorize(
            "client-b",
            self.proof("client-b", self.psk_b),
        )

        self.assertEqual(
            result.client_id,
            "client-b",
        )

    def test_cross_client_psk_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.authorize(
                "client-b",
                self.proof("client-b", self.psk_a),
            )

    def test_identity_swapping_rejected(self):
        proof = self.proof("client-a", self.psk_a)

        with self.assertRaises(ClientAuthorizationError):
            self.authorize("client-b", proof)

    def test_wrong_psk_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.authorize(
                "client-a",
                self.proof("client-a", os.urandom(32)),
            )

    def test_unknown_client_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.authorize(
                "client-c",
                self.proof("client-c", os.urandom(32)),
            )

    def test_revoked_client_rejected(self):
        proof = self.proof("client-a", self.psk_a)

        self.credentials.revoke("client-a")

        with self.assertRaises(ClientAuthorizationError):
            self.authorize("client-a", proof)

    def test_revocation_does_not_affect_other_client(self):
        self.credentials.revoke("client-a")

        result = self.authorize(
            "client-b",
            self.proof("client-b", self.psk_b),
        )

        self.assertEqual(result.client_id, "client-b")

    def test_wrong_challenge_rejected(self):
        proof = self.proof(
            "client-a",
            self.psk_a,
            challenge=os.urandom(32),
        )

        with self.assertRaises(ClientAuthorizationError):
            self.authorize("client-a", proof)

    def test_wrong_session_keys_rejected(self):
        other_keys = SessionKeys(
            os.urandom(32),
            os.urandom(32),
            os.urandom(4),
            os.urandom(4),
        )

        proof = self.proof(
            "client-a",
            self.psk_a,
            keys=other_keys,
        )

        with self.assertRaises(ClientAuthorizationError):
            self.authorize("client-a", proof)

    def test_tampered_proof_rejected(self):
        proof = bytearray(
            self.proof("client-a", self.psk_a)
        )

        proof[-1] ^= 1

        with self.assertRaises(ClientAuthorizationError):
            self.authorize("client-a", bytes(proof))

    def test_short_proof_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.authorize("client-a", b"invalid")

    def test_invalid_identity_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.authorize(
                "../client-a",
                b"x" * 48,
            )

    def test_authorized_result_does_not_expose_psk(self):
        result = self.authorize(
            "client-a",
            self.proof("client-a", self.psk_a),
        )

        self.assertFalse(hasattr(result, "psk"))

    def test_invalid_registry_rejected(self):
        with self.assertRaises(TypeError):
            ClientAuthorizationService(object())


if __name__ == "__main__":
    unittest.main()
