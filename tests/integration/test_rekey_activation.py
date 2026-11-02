
"""Integration tests for authenticated PQVPN session activation."""

import os
import unittest

from gateway.session_manager import SessionManager, SessionError
from modules.encryption.key_derivation import SessionKeys
from modules.encryption.cipher_suites import ReplayError
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.session_control import (
    encode_rekey_activate,
    is_rekey_ack,
)


def create_session(manager):
    keys = SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )

    session_id = manager.create(
        keys,
        "server",
        authorized=True,
    )

    client = SecureSessionTransport(
        session_id,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
    )

    return session_id, client


class TestRekeyActivation(unittest.TestCase):

    def setUp(self):
        self.manager = SessionManager()
        self.peer = ("127.0.0.1", 45000)

        self.old_id, self.old_client = create_session(
            self.manager
        )

        self.new_id, self.new_client = create_session(
            self.manager
        )

        # Bind the existing active session to its UDP endpoint.
        ping = self.old_client.encrypt(b"PING")

        self.manager.process_tunnel_datagram(
            self.old_id,
            ping,
            self.peer,
        )

    def activate_new(self):
        request = self.new_client.encrypt(
            encode_rekey_activate()
        )

        response = self.manager.process_rekey_activation(
            self.new_id,
            request,
            self.peer,
        )

        return request, response

    def test_valid_activation(self):
        _, response = self.activate_new()

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )

        self.assertTrue(
            is_rekey_ack(
                self.new_client.decrypt(response)
            )
        )

    def test_old_session_retired(self):
        self.activate_new()

        with self.assertRaises(SessionError):
            self.manager.get(self.old_id)

    def test_wrong_endpoint_rejected(self):
        request = self.new_client.encrypt(
            encode_rekey_activate()
        )

        with self.assertRaises(SessionError):
            self.manager.process_rekey_activation(
                self.new_id,
                request,
                ("127.0.0.1", 45001),
            )

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )

    def test_invalid_control_payload_rejected(self):
        request = self.new_client.encrypt(b"PING")

        with self.assertRaises(SessionError):
            self.manager.process_rekey_activation(
                self.new_id,
                request,
                self.peer,
            )

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )

    def test_duplicate_packet_rejected(self):
        request, _ = self.activate_new()

        with self.assertRaises(ReplayError):
            self.manager.process_rekey_activation(
                self.new_id,
                request,
                self.peer,
            )

    def test_fresh_retry_returns_ack(self):
        self.activate_new()

        retry = self.new_client.encrypt(
            encode_rekey_activate()
        )

        response = self.manager.process_rekey_activation(
            self.new_id,
            retry,
            self.peer,
        )

        self.assertTrue(
            is_rekey_ack(
                self.new_client.decrypt(response)
            )
        )

    def test_unbound_old_session_rejected(self):
        manager = SessionManager()

        old_id, _ = create_session(manager)
        new_id, client = create_session(manager)

        request = client.encrypt(
            encode_rekey_activate()
        )

        with self.assertRaises(SessionError):
            manager.process_rekey_activation(
                new_id,
                request,
                self.peer,
            )

        self.assertEqual(
            manager.active_session_id(),
            old_id,
        )


if __name__ == "__main__":
    unittest.main()
