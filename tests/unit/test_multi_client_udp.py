
"""Multi-client encrypted UDP security regression tests."""

import os
import unittest

from gateway.multi_client_registry import MultiClientSessionManager
from gateway.multi_client_udp import (
    MultiClientUDPEngine,
    MultiClientUDPError,
)
from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)


def new_keys():
    return SessionKeys(
        os.urandom(32),
        os.urandom(32),
        os.urandom(4),
        os.urandom(4),
    )


def client_transport(sid, keys):
    return SecureSessionTransport(
        sid,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
    )


class TestMultiClientUDP(unittest.TestCase):

    def setUp(self):
        self.registry = MultiClientSessionManager()
        self.registry.register_client("client-a", "10.77.0.2")
        self.registry.register_client("client-b", "10.77.0.3")

        self.engine = MultiClientUDPEngine(self.registry)

        self.sid_a = os.urandom(16)
        self.sid_b = os.urandom(16)

        self.keys_a = new_keys()
        self.keys_b = new_keys()

        self.registry.register_session("client-a", self.sid_a)
        self.registry.register_session("client-b", self.sid_b)

        self.engine.register_authenticated(
            "client-a", self.sid_a, self.keys_a
        )
        self.engine.register_authenticated(
            "client-b", self.sid_b, self.keys_b
        )

        self.client_a = client_transport(self.sid_a, self.keys_a)
        self.client_b = client_transport(self.sid_b, self.keys_b)

        self.peer_a = ("127.0.0.1", 41001)
        self.peer_b = ("127.0.0.1", 41002)

    def test_client_a_encrypted_ping(self):
        packet = self.client_a.encrypt(b"PING")
        response = self.engine.process(packet, self.peer_a)
        self.assertEqual(self.client_a.decrypt(response), b"PONG")

    def test_client_b_encrypted_ping(self):
        packet = self.client_b.encrypt(b"PING")
        response = self.engine.process(packet, self.peer_b)
        self.assertEqual(self.client_b.decrypt(response), b"PONG")

    def test_both_clients_independent(self):
        self.engine.process(
            self.client_a.encrypt(b"PING"), self.peer_a
        )
        self.engine.process(
            self.client_b.encrypt(b"PING"), self.peer_b
        )

        self.assertEqual(
            self.engine.bound_peer(self.sid_a), self.peer_a
        )
        self.assertEqual(
            self.engine.bound_peer(self.sid_b), self.peer_b
        )

    def test_replay_rejected(self):
        packet = self.client_a.encrypt(b"PING")
        self.engine.process(packet, self.peer_a)

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(packet, self.peer_a)

    def test_tampering_rejected(self):
        packet = bytearray(self.client_a.encrypt(b"PING"))
        packet[-1] ^= 1

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(bytes(packet), self.peer_a)

    def test_wrong_endpoint_rejected(self):
        self.engine.process(
            self.client_a.encrypt(b"PING"), self.peer_a
        )

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                self.client_a.encrypt(b"PING"), self.peer_b
            )

    def test_failed_auth_does_not_bind_endpoint(self):
        packet = bytearray(self.client_a.encrypt(b"PING"))
        packet[-1] ^= 1

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(bytes(packet), self.peer_a)

        self.assertIsNone(self.engine.bound_peer(self.sid_a))

    def test_cross_client_key_rejected(self):
        wrong = client_transport(self.sid_a, self.keys_b)

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                wrong.encrypt(b"PING"), self.peer_a
            )

    def test_unknown_session_rejected(self):
        unknown = client_transport(os.urandom(16), new_keys())

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                unknown.encrypt(b"PING"), self.peer_a
            )

    def test_plaintext_rejected(self):
        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                self.sid_a + b"PING", self.peer_a
            )

    def test_unsupported_payload_rejected(self):
        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                self.client_a.encrypt(b"DATA"), self.peer_a
            )

    def test_staged_session_cannot_send(self):
        staged = os.urandom(16)
        keys = new_keys()

        self.registry.register_session("client-a", staged)
        self.engine.register_authenticated("client-a", staged, keys)

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                client_transport(staged, keys).encrypt(b"PING"),
                self.peer_a,
            )

    def test_cross_client_registration_rejected(self):
        with self.assertRaises(MultiClientUDPError):
            self.engine.register_authenticated(
                "client-b", self.sid_a, new_keys()
            )

    def test_duplicate_transport_rejected(self):
        with self.assertRaises(MultiClientUDPError):
            self.engine.register_authenticated(
                "client-a", self.sid_a, self.keys_a
            )

    def test_revocation_blocks_client_a(self):
        self.engine.revoke_client("client-a")

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                self.client_a.encrypt(b"PING"), self.peer_a
            )

    def test_revocation_preserves_client_b(self):
        self.engine.revoke_client("client-a")

        response = self.engine.process(
            self.client_b.encrypt(b"PING"), self.peer_b
        )

        self.assertEqual(self.client_b.decrypt(response), b"PONG")

    def test_expired_or_removed_session_rejected(self):
        self.registry.remove_session("client-a", self.sid_a)

        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                self.client_a.encrypt(b"PING"), self.peer_a
            )

    def test_invalid_address_rejected(self):
        with self.assertRaises(MultiClientUDPError):
            self.engine.process(
                self.client_a.encrypt(b"PING"),
                ("127.0.0.1", 0),
            )


if __name__ == "__main__":
    unittest.main()
