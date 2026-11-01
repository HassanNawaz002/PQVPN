
"""Integration tests for encrypted session transport."""

import os
import unittest

from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    SessionTransportError,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)

from modules.encryption.cipher_suites import (
    PacketError,
    ReplayError,
)


class TestSecureSessionTransport(unittest.TestCase):

    def setUp(self):
        session_id = os.urandom(16)

        client_key = os.urandom(32)
        server_key = os.urandom(32)

        client_nonce = os.urandom(4)
        server_nonce = os.urandom(4)

        self.client = SecureSessionTransport(
            session_id=session_id,
            send_key=client_key,
            send_nonce_prefix=client_nonce,
            send_direction=CLIENT_TO_SERVER,
            receive_key=server_key,
            receive_nonce_prefix=server_nonce,
            receive_direction=SERVER_TO_CLIENT,
        )

        self.server = SecureSessionTransport(
            session_id=session_id,
            send_key=server_key,
            send_nonce_prefix=server_nonce,
            send_direction=SERVER_TO_CLIENT,
            receive_key=client_key,
            receive_nonce_prefix=client_nonce,
            receive_direction=CLIENT_TO_SERVER,
        )

    def test_client_to_server(self):
        packet = self.client.encrypt(b"PING")
        self.assertEqual(
            self.server.decrypt(packet),
            b"PING",
        )

    def test_server_to_client(self):
        packet = self.server.encrypt(b"PONG")
        self.assertEqual(
            self.client.decrypt(packet),
            b"PONG",
        )

    def test_replay_rejected(self):
        packet = self.client.encrypt(b"PING")

        self.server.decrypt(packet)

        with self.assertRaises(ReplayError):
            self.server.decrypt(packet)

    def test_tampering_rejected(self):
        packet = bytearray(
            self.client.encrypt(b"Sensitive data")
        )

        packet[-1] ^= 1

        with self.assertRaises(PacketError):
            self.server.decrypt(bytes(packet))

    def test_wrong_session_rejected(self):
        packet = self.client.encrypt(b"PING")

        wrong_session = os.urandom(16)

        while wrong_session == self.server.session_id:
            wrong_session = os.urandom(16)

        forged = (
            wrong_session + packet[16:]
        )

        with self.assertRaises(SessionTransportError):
            self.server.decrypt(forged)

    def test_invalid_session_id_rejected(self):
        with self.assertRaises(SessionTransportError):
            SecureSessionTransport(
                session_id=b"short",
                send_key=os.urandom(32),
                send_nonce_prefix=os.urandom(4),
                send_direction=CLIENT_TO_SERVER,
                receive_key=os.urandom(32),
                receive_nonce_prefix=os.urandom(4),
                receive_direction=SERVER_TO_CLIENT,
            )

    def test_multiple_packets(self):
        for number in range(100):
            message = f"Packet-{number}".encode()

            packet = self.client.encrypt(message)

            self.assertEqual(
                self.server.decrypt(packet),
                message,
            )

    def test_bidirectional_exchange(self):
        request = self.client.encrypt(
            b"Hello AWS"
        )

        self.assertEqual(
            self.server.decrypt(request),
            b"Hello AWS",
        )

        response = self.server.encrypt(
            b"Hello Windows"
        )

        self.assertEqual(
            self.client.decrypt(response),
            b"Hello Windows",
        )


if __name__ == "__main__":
    unittest.main()
