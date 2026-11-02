
"""Multi-client TCP session registration tests."""

import os
import unittest
from unittest.mock import MagicMock, patch

from gateway.client_credentials import ClientCredentialRegistry
from gateway.multi_client_tcp_server import MultiClientTCPServer
from gateway.multi_client_handshake import AuthenticatedHandshake

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_authorization import (
    check_accept,
)


class TestMultiClientTCPServer(unittest.TestCase):

    def setUp(self):
        self.credentials = ClientCredentialRegistry()

        self.credentials.add_client("client-a", os.urandom(32))
        self.credentials.add_client("client-b", os.urandom(32))

        self.server = MultiClientTCPServer(
            (b"public", b"private"),
            self.credentials,
            {
                "client-a": "10.77.0.2",
                "client-b": "10.77.0.3",
            },
        )

        self.keys = SessionKeys(
            os.urandom(32),
            os.urandom(32),
            os.urandom(4),
            os.urandom(4),
        )

        self.challenge = os.urandom(32)
        self.proof = os.urandom(48)

    def handshake(self, client_id):
        return AuthenticatedHandshake(
            client_id,
            self.keys,
            self.challenge,
            self.proof,
        )

    def establish(self, client_id):
        connection = MagicMock()

        with patch(
            "gateway.multi_client_tcp_server.authenticate_connection",
            return_value=self.handshake(client_id),
        ):
            result = self.server.handle_connection(connection)

        return result, connection

    def test_client_a_registered(self):
        (client_id, sid), _ = self.establish("client-a")

        self.assertEqual(client_id, "client-a")
        self.assertEqual(
            self.server.sessions.owner_of_session(sid),
            "client-a",
        )

    def test_client_b_registered(self):
        (client_id, sid), _ = self.establish("client-b")

        self.assertEqual(client_id, "client-b")
        self.assertEqual(
            self.server.sessions.owner_of_session(sid),
            "client-b",
        )

    def test_distinct_session_ids(self):
        (_, sid_a), _ = self.establish("client-a")
        (_, sid_b), _ = self.establish("client-b")

        self.assertNotEqual(sid_a, sid_b)

    def test_both_clients_remain_active(self):
        (_, sid_a), _ = self.establish("client-a")
        (_, sid_b), _ = self.establish("client-b")

        self.assertEqual(
            self.server.sessions.active_session("client-a"),
            sid_a,
        )
        self.assertEqual(
            self.server.sessions.active_session("client-b"),
            sid_b,
        )

    def test_acceptance_authentication(self):
        (_, sid), connection = self.establish("client-a")

        acceptance = connection.sendall.call_args.args[0]

        self.assertEqual(
            check_accept(
                self.keys,
                acceptance,
                self.challenge,
                self.proof,
            ),
            sid,
        )

    def test_revoked_client_rejected(self):
        self.credentials.revoke("client-a")

        with self.assertRaises(Exception):
            self.establish("client-a")

        self.assertEqual(self.server.sessions.session_count(), 0)

    def test_unregistered_assignment_rejected(self):
        with self.assertRaises(Exception):
            MultiClientTCPServer(
                (b"public", b"private"),
                self.credentials,
                {"client-c": "10.77.0.4"},
            )

    def test_duplicate_tunnel_ip_rejected(self):
        with self.assertRaises(Exception):
            MultiClientTCPServer(
                (b"public", b"private"),
                self.credentials,
                {
                    "client-a": "10.77.0.2",
                    "client-b": "10.77.0.2",
                },
            )


if __name__ == "__main__":
    unittest.main()
