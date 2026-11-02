
"""Real localhost UDP socket tests for two encrypted clients."""

import os
import unittest

from gateway.multi_client_registry import MultiClientSessionManager
from gateway.multi_client_udp import MultiClientUDPEngine
from gateway.multi_client_udp_dispatch import process_one

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.packet_framing import TYPE_DATA


def new_keys():
    return SessionKeys(
        os.urandom(32),
        os.urandom(32),
        os.urandom(4),
        os.urandom(4),
    )


class TestMultiClientUDPSocket(unittest.TestCase):

    def setUp(self):
        self.registry = MultiClientSessionManager()
        self.engine = MultiClientUDPEngine(self.registry)

        self.gateway = UDPTransport(timeout=1.0)
        self.client_a = UDPTransport(timeout=1.0)
        self.client_b = UDPTransport(timeout=1.0)

        self.clients = {}

        for name, ip, udp in (
            ("client-a", "10.77.0.2", self.client_a),
            ("client-b", "10.77.0.3", self.client_b),
        ):
            sid = os.urandom(16)
            keys = new_keys()

            self.registry.register_client(name, ip)
            self.registry.register_session(name, sid)
            self.engine.register_authenticated(name, sid, keys)

            crypto = SecureSessionTransport(
                sid,
                keys.client_to_server_key,
                keys.client_nonce_prefix,
                CLIENT_TO_SERVER,
                keys.server_to_client_key,
                keys.server_nonce_prefix,
                SERVER_TO_CLIENT,
            )

            self.clients[name] = (udp, crypto, sid)

    def tearDown(self):
        self.client_a.close()
        self.client_b.close()
        self.gateway.close()

    def exchange(self, name):
        udp, crypto, _sid = self.clients[name]

        udp.send(
            self.gateway.address,
            TYPE_DATA,
            crypto.encrypt(b"PING"),
        )

        self.assertTrue(process_one(self.gateway, self.engine))

        kind, encrypted, address = udp.receive()

        self.assertEqual(kind, TYPE_DATA)
        self.assertEqual(address, self.gateway.address)
        self.assertEqual(crypto.decrypt(encrypted), b"PONG")

    def test_real_client_a(self):
        self.exchange("client-a")

    def test_real_client_b(self):
        self.exchange("client-b")

    def test_real_two_clients(self):
        self.exchange("client-a")
        self.exchange("client-b")
        self.exchange("client-a")
        self.exchange("client-b")

    def test_real_replay_rejected(self):
        udp, crypto, _ = self.clients["client-a"]
        packet = crypto.encrypt(b"PING")

        udp.send(self.gateway.address, TYPE_DATA, packet)
        self.assertTrue(process_one(self.gateway, self.engine))
        udp.receive()

        udp.send(self.gateway.address, TYPE_DATA, packet)
        self.assertFalse(process_one(self.gateway, self.engine))

    def test_real_revocation_isolated(self):
        self.exchange("client-a")
        self.engine.revoke_client("client-a")

        udp, crypto, _ = self.clients["client-a"]
        udp.send(
            self.gateway.address,
            TYPE_DATA,
            crypto.encrypt(b"PING"),
        )

        self.assertFalse(process_one(self.gateway, self.engine))
        self.exchange("client-b")


if __name__ == "__main__":
    unittest.main()
