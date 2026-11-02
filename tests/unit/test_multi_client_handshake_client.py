
"""Unit tests for PQVPN client identity handshake integration."""

import os
import unittest
from unittest.mock import MagicMock, patch

from modules.encryption.key_derivation import SessionKeys

from modules.networking.transport.handshake_client import (
    connect_gateway,
    validate_fingerprint,
)

from modules.networking.transport.client_identity_auth import (
    ClientIdentityAuthError,
)


FINGERPRINT = "a" * 64


class TestMultiClientHandshakeClient(unittest.TestCase):

    def setUp(self):
        self.psk = os.urandom(32)

        self.keys = SessionKeys(
            client_to_server_key=os.urandom(32),
            server_to_client_key=os.urandom(32),
            client_nonce_prefix=os.urandom(4),
            server_nonce_prefix=os.urandom(4),
        )

        self.session_id = os.urandom(16)

    def _run_mock_handshake(self, client_id=None):
        """Execute the client function with mocked network/crypto."""

        socket_context = MagicMock()
        connection = MagicMock()
        socket_context.__enter__.return_value = connection

        with (
            patch(
                "modules.networking.transport.handshake_client."
                "socket.create_connection",
                return_value=socket_context,
            ) as create_connection,
            patch(
                "modules.networking.transport.handshake_client."
                "load_psk",
                return_value=self.psk,
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "client_start",
                return_value=("state", "hello"),
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "encode_client_hello",
                return_value=b"client-frame",
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "send_tcp_message",
            ) as send_message,
            patch(
                "modules.networking.transport.handshake_client."
                "receive_tcp_message",
                return_value=b"server-frame",
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "decode_server_hello",
                return_value="server-hello",
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "client_finish",
                return_value=(self.keys, b"handshake-proof"),
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "encode_client_finished",
                return_value=b"finished-frame",
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "read_exact",
                side_effect=[b"c" * 32, b"a" * 64],
            ),
            patch(
                "modules.networking.transport.handshake_client."
                "make_proof",
                return_value=b"l" * 48,
            ) as legacy_proof,
            patch(
                "modules.networking.transport.handshake_client."
                "make_identity_proof",
                return_value=b"m" * 48,
            ) as identity_proof,
            patch(
                "modules.networking.transport.handshake_client."
                "send_identity_preface",
            ) as send_identity,
            patch(
                "modules.networking.transport.handshake_client."
                "check_accept",
                return_value=self.session_id,
            ) as check_accept,
        ):
            result = connect_gateway(
                "127.0.0.1",
                51821,
                FINGERPRINT,
                client_id=client_id,
            )

            return {
                "result": result,
                "connection": connection,
                "create_connection": create_connection,
                "send_message": send_message,
                "legacy_proof": legacy_proof,
                "identity_proof": identity_proof,
                "send_identity": send_identity,
                "check_accept": check_accept,
            }

    def test_legacy_mode_does_not_send_identity(self):
        result = self._run_mock_handshake()

        result["send_identity"].assert_not_called()
        result["legacy_proof"].assert_called_once()
        result["identity_proof"].assert_not_called()

    def test_multi_client_mode_sends_identity(self):
        result = self._run_mock_handshake("client-a")

        result["send_identity"].assert_called_once_with(
            result["connection"],
            "client-a",
        )

    def test_multi_client_uses_identity_bound_proof(self):
        result = self._run_mock_handshake("client-a")

        result["identity_proof"].assert_called_once_with(
            "client-a",
            self.psk,
            b"c" * 32,
            self.keys,
        )

        result["legacy_proof"].assert_not_called()

    def test_multi_client_sends_identity_proof(self):
        result = self._run_mock_handshake("client-a")

        result["connection"].sendall.assert_called_with(
            b"m" * 48
        )

    def test_multi_client_acceptance_uses_identity_proof(self):
        result = self._run_mock_handshake("client-a")

        result["check_accept"].assert_called_once_with(
            self.keys,
            b"a" * 64,
            b"c" * 32,
            b"m" * 48,
        )

    def test_multi_client_returns_session(self):
        result = self._run_mock_handshake("client-a")

        self.assertIs(
            result["result"][0],
            self.keys,
        )

        self.assertEqual(
            result["result"][1],
            self.session_id,
        )

    def test_invalid_identity_rejected_before_connection(self):
        with patch(
            "modules.networking.transport.handshake_client."
            "socket.create_connection"
        ) as create_connection:

            with self.assertRaises(ClientIdentityAuthError):
                connect_gateway(
                    "127.0.0.1",
                    51821,
                    FINGERPRINT,
                    client_id="../invalid",
                )

            create_connection.assert_not_called()

    def test_invalid_fingerprint_rejected(self):
        with self.assertRaises(ValueError):
            validate_fingerprint("invalid")

    def test_valid_fingerprint_accepted(self):
        self.assertEqual(
            validate_fingerprint(FINGERPRINT),
            FINGERPRINT,
        )

    def test_legacy_mode_returns_session(self):
        result = self._run_mock_handshake()

        self.assertEqual(
            result["result"][1],
            self.session_id,
        )


if __name__ == "__main__":
    unittest.main()
