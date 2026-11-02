
"""PQVPN encrypted session handover integration tests."""

import os
import unittest
from modules.encryption.cipher_suites import ReplayError
from gateway.session_manager import SessionManager, SessionError
from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)


def make_session(manager):
    keys = SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )

    sid = manager.create(
        keys,
        "server",
        authorized=True,
    )

    client = SecureSessionTransport(
        sid,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
    )

    return sid, client


class TestEncryptedSessionHandover(unittest.TestCase):

    def setUp(self):
        self.manager = SessionManager()
        self.peer = ("127.0.0.1", 45000)

        self.old_id, self.old_client = make_session(
            self.manager
        )

        self.new_id, self.new_client = make_session(
            self.manager
        )

    def send_ping(self, sid, client):
        packet = client.encrypt(b"PING")

        return self.manager.process_tunnel_datagram(
            sid,
            packet,
            self.peer,
        )

    def test_old_session_works_while_new_staged(self):
        result = self.send_ping(
            self.old_id,
            self.old_client,
        )

        self.assertEqual(result, ("ping", None))

    def test_staged_session_cannot_send_traffic(self):
        with self.assertRaises(SessionError):
            self.send_ping(
                self.new_id,
                self.new_client,
            )

    def test_new_session_works_after_activation(self):
        self.manager.activate(self.new_id)

        result = self.send_ping(
            self.new_id,
            self.new_client,
        )

        self.assertEqual(result, ("ping", None))

    def test_old_session_rejected_after_activation(self):
        self.manager.activate(self.new_id)

        with self.assertRaises(SessionError):
            self.send_ping(
                self.old_id,
                self.old_client,
            )


    def test_replay_rejected_after_activation(self):
        """Authenticated replay must be rejected after handover."""

        self.manager.activate(self.new_id)

        packet = self.new_client.encrypt(b"PING")

        # First packet must be accepted.
        result = self.manager.process_tunnel_datagram(
            self.new_id,
            packet,
            self.peer,
        )

        self.assertEqual(result, ("ping", None))

        # Replaying the same authenticated packet must fail.
        with self.assertRaises(ReplayError):
            self.manager.process_tunnel_datagram(
                self.new_id,
                packet,
                self.peer,
            )


if __name__ == "__main__":
    unittest.main()
