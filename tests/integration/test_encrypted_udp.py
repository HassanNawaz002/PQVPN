
"""Encrypted UDP loopback integration tests."""

import os
import socket
import threading
import unittest

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.packet_framing import TYPE_DATA
from gateway.session_manager import SessionManager, SessionError
from gateway.udp_gateway import process_one


class TestEncryptedUDP(unittest.TestCase):

    def setUp(self):
        self.keys = SessionKeys(
            client_to_server_key=os.urandom(32),
            server_to_client_key=os.urandom(32),
            client_nonce_prefix=os.urandom(4),
            server_nonce_prefix=os.urandom(4),
        )

        self.sid = os.urandom(16)

        self.sessions = SessionManager()
        self.sessions.register(
            self.sid,
            self.keys,
            "server",
            authorized=True,
        )

        self.client_crypto = SecureSessionTransport(
            self.sid,
            self.keys.client_to_server_key,
            self.keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
            self.keys.server_to_client_key,
            self.keys.server_nonce_prefix,
            SERVER_TO_CLIENT,
        )

        self.gateway = UDPTransport(
            host="127.0.0.1",
            port=0,
            timeout=2,
        )

        self.client = UDPTransport(
            host="127.0.0.1",
            port=0,
            timeout=2,
        )

    def tearDown(self):
        self.client.close()
        self.gateway.close()

    def test_encrypted_ping_pong(self):
        packet = self.client_crypto.encrypt(b"PING")

        self.client.send(
            self.gateway.address,
            TYPE_DATA,
            packet,
        )

        self.assertTrue(
            process_one(self.gateway, self.sessions)
        )

        kind, response, address = self.client.receive()

        self.assertEqual(kind, TYPE_DATA)
        self.assertEqual(address, self.gateway.address)
        self.assertEqual(
            self.client_crypto.decrypt(response),
            b"PONG",
        )

    def test_replayed_udp_packet_rejected(self):
        packet = self.client_crypto.encrypt(b"PING")

        self.client.send(
            self.gateway.address,
            TYPE_DATA,
            packet,
        )
        self.assertTrue(
            process_one(self.gateway, self.sessions)
        )

        self.client.send(
            self.gateway.address,
            TYPE_DATA,
            packet,
        )
        self.assertFalse(
            process_one(self.gateway, self.sessions)
        )

    def test_tampered_packet_rejected(self):
        packet = bytearray(
            self.client_crypto.encrypt(b"PING")
        )
        packet[-1] ^= 1

        self.client.send(
            self.gateway.address,
            TYPE_DATA,
            bytes(packet),
        )

        self.assertFalse(
            process_one(self.gateway, self.sessions)
        )

    def test_unknown_session_rejected(self):
        packet = self.client_crypto.encrypt(b"PING")

        unknown = os.urandom(16)
        while unknown == self.sid:
            unknown = os.urandom(16)

        packet = unknown + packet[16:]

        self.client.send(
            self.gateway.address,
            TYPE_DATA,
            packet,
        )

        self.assertFalse(
            process_one(self.gateway, self.sessions)
        )

    def test_unauthorized_session_rejected(self):
        manager = SessionManager()

        with self.assertRaises(SessionError):
            manager.register(
                self.sid,
                self.keys,
                "server",
                authorized=False,
            )

    def test_duplicate_session_rejected(self):
        with self.assertRaises(SessionError):
            self.sessions.register(
                self.sid,
                self.keys,
                "server",
                authorized=True,
            )


if __name__ == "__main__":
    unittest.main()
