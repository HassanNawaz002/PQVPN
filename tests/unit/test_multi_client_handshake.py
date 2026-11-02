
"""Tests for gateway multi-client TCP authentication flow."""

import os
import unittest
from unittest.mock import MagicMock, patch

from gateway.client_credentials import ClientCredentialRegistry
from gateway.client_authorization import (
    ClientAuthorizationService,
    ClientAuthorizationError,
)
from gateway.multi_client_handshake import authenticate_connection

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.client_identity_auth import (
    make_identity_proof,
)


class TestMultiClientHandshake(unittest.TestCase):

    def setUp(self):
        self.credentials = ClientCredentialRegistry()
        self.psk_a = os.urandom(32)
        self.psk_b = os.urandom(32)

        self.credentials.add_client("client-a", self.psk_a)
        self.credentials.add_client("client-b", self.psk_b)

        self.service = ClientAuthorizationService(
            self.credentials
        )

        self.keys = SessionKeys(
            client_to_server_key=os.urandom(32),
            server_to_client_key=os.urandom(32),
            client_nonce_prefix=os.urandom(4),
            server_nonce_prefix=os.urandom(4),
        )

        self.challenge = os.urandom(32)

    def run_handshake(self, client_id, psk, *, proof=None):
        connection = MagicMock()

        if proof is None:
            proof = make_identity_proof(
                client_id,
                psk,
                self.challenge,
                self.keys,
            )

        with (
            patch(
                "gateway.multi_client_handshake."
                "receive_identity_preface",
                return_value=client_id,
            ),
            patch(
                "gateway.multi_client_handshake."
                "receive_tcp_message",
                side_effect=[b"hello", b"finished"],
            ),
            patch(
                "gateway.multi_client_handshake."
                "decode_client_hello",
                return_value="client-hello",
            ),
            patch(
                "gateway.multi_client_handshake."
                "server_respond",
                return_value=("state", "server-hello"),
            ),
            patch(
                "gateway.multi_client_handshake."
                "encode_server_hello",
                return_value=b"server-frame",
            ),
            patch(
                "gateway.multi_client_handshake."
                "send_tcp_message",
            ),
            patch(
                "gateway.multi_client_handshake."
                "decode_client_finished",
                return_value=b"client-finished",
            ),
            patch(
                "gateway.multi_client_handshake."
                "server_finish",
                return_value=self.keys,
            ),
            patch(
                "gateway.multi_client_handshake."
                "make_challenge",
                return_value=self.challenge,
            ),
            patch(
                "gateway.multi_client_handshake."
                "read_exact",
                return_value=proof,
            ),
        ):
            result = authenticate_connection(
                connection,
                (b"public", b"private"),
                self.service,
            )

        return result, connection

    def test_client_a_authenticated(self):
        result, _ = self.run_handshake(
            "client-a", self.psk_a
        )
        self.assertEqual(result.client_id, "client-a")

    def test_client_b_authenticated(self):
        result, _ = self.run_handshake(
            "client-b", self.psk_b
        )
        self.assertEqual(result.client_id, "client-b")

    def test_session_keys_returned(self):
        result, _ = self.run_handshake(
            "client-a", self.psk_a
        )
        self.assertIs(result.keys, self.keys)

    def test_wrong_psk_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.run_handshake("client-a", os.urandom(32))

    def test_cross_client_psk_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.run_handshake("client-b", self.psk_a)

    def test_unknown_client_rejected(self):
        with self.assertRaises(ClientAuthorizationError):
            self.run_handshake("client-c", os.urandom(32))

    def test_revoked_client_rejected(self):
        self.credentials.revoke("client-a")
        with self.assertRaises(ClientAuthorizationError):
            self.run_handshake("client-a", self.psk_a)

    def test_identity_swap_rejected(self):
        proof = make_identity_proof(
            "client-a",
            self.psk_a,
            self.challenge,
            self.keys,
        )

        with self.assertRaises(ClientAuthorizationError):
            self.run_handshake(
                "client-b",
                self.psk_b,
                proof=proof,
            )

    def test_connection_timeout_configured(self):
        _, connection = self.run_handshake(
            "client-a", self.psk_a
        )
        connection.settimeout.assert_called_once_with(10)

    def test_invalid_authorization_service_rejected(self):
        with self.assertRaises(TypeError):
            authenticate_connection(
                MagicMock(),
                (b"public", b"private"),
                object(),
            )


if __name__ == "__main__":
    unittest.main()
