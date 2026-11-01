
"""PQVPN Sprint 07: bidirectional data-plane security tests."""

import os
import unittest

from modules.encryption.cipher_suites import (
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
    PacketError,
    ReplayError,
)
from modules.encryption.packet_encryptor import PacketEncryptor
from modules.decryption.aead_decryptor import PacketDecryptor
from modules.encryption.ml_dsa import (
    generate_keypair,
    public_key_fingerprint,
)
from modules.encryption.hybrid_handshake import (
    client_start,
    server_respond,
    client_finish,
    server_finish,
)


class TestBidirectionalSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.identity_public, cls.identity_secret = generate_keypair()
        cls.fingerprint = public_key_fingerprint(cls.identity_public)

    def setUp(self):
        client_state, hello = client_start()

        server_state, response = server_respond(
            hello,
            self.identity_public,
            self.identity_secret,
        )

        self.client_keys, proof = client_finish(
            client_state,
            response,
            self.fingerprint,
        )

        self.server_keys = server_finish(server_state, proof)

        self.client_sender = PacketEncryptor(
            self.client_keys.client_to_server_key,
            self.client_keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
        )

        self.server_receiver = PacketDecryptor(
            self.server_keys.client_to_server_key,
            self.server_keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
            window_size=8,
        )

        self.server_sender = PacketEncryptor(
            self.server_keys.server_to_client_key,
            self.server_keys.server_nonce_prefix,
            SERVER_TO_CLIENT,
        )

        self.client_receiver = PacketDecryptor(
            self.client_keys.server_to_client_key,
            self.client_keys.server_nonce_prefix,
            SERVER_TO_CLIENT,
            window_size=8,
        )

    def test_client_to_server(self):
        packet = self.client_sender.encrypt(b"Client request")
        self.assertEqual(
            self.server_receiver.decrypt(packet),
            b"Client request",
        )

    def test_server_to_client(self):
        packet = self.server_sender.encrypt(b"Gateway response")
        self.assertEqual(
            self.client_receiver.decrypt(packet),
            b"Gateway response",
        )

    def test_bidirectional_exchange(self):
        request = self.client_sender.encrypt(b"PING")
        self.assertEqual(
            self.server_receiver.decrypt(request),
            b"PING",
        )

        response = self.server_sender.encrypt(b"PONG")
        self.assertEqual(
            self.client_receiver.decrypt(response),
            b"PONG",
        )

    def test_directional_key_isolation(self):
        self.assertNotEqual(
            self.client_keys.client_to_server_key,
            self.client_keys.server_to_client_key,
        )

        self.assertNotEqual(
            self.client_keys.client_nonce_prefix,
            self.client_keys.server_nonce_prefix,
        )

    def test_wrong_session_key_rejected(self):
        packet = self.client_sender.encrypt(b"Private data")

        unrelated_receiver = PacketDecryptor(
            os.urandom(32),
            self.client_keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
        )

        with self.assertRaises(PacketError):
            unrelated_receiver.decrypt(packet)

    def test_wrong_nonce_prefix_rejected(self):
        packet = self.client_sender.encrypt(b"Private data")

        incorrect_receiver = PacketDecryptor(
            self.server_keys.client_to_server_key,
            self.server_keys.server_nonce_prefix,
            CLIENT_TO_SERVER,
        )

        with self.assertRaises(PacketError):
            incorrect_receiver.decrypt(packet)

    def test_out_of_order_within_window(self):
        packets = [
            self.client_sender.encrypt(str(i).encode())
            for i in range(10)
        ]

        self.assertEqual(
            self.server_receiver.decrypt(packets[9]),
            b"9",
        )

        self.assertEqual(
            self.server_receiver.decrypt(packets[2]),
            b"2",
        )

        self.assertEqual(
            self.server_receiver.decrypt(packets[5]),
            b"5",
        )

    def test_packet_outside_replay_window_rejected(self):
        packets = [
            self.client_sender.encrypt(str(i).encode())
            for i in range(10)
        ]

        self.server_receiver.decrypt(packets[9])

        with self.assertRaises(ReplayError):
            self.server_receiver.decrypt(packets[1])

    def test_duplicate_in_reverse_direction_rejected(self):
        packet = self.server_sender.encrypt(b"Response")

        self.client_receiver.decrypt(packet)

        with self.assertRaises(ReplayError):
            self.client_receiver.decrypt(packet)

    def test_empty_payload_roundtrip(self):
        packet = self.client_sender.encrypt(b"")

        self.assertEqual(
            self.server_receiver.decrypt(packet),
            b"",
        )

    def test_cross_session_packet_rejected(self):
        packet = self.client_sender.encrypt(b"Session A")

        other_client_state, other_hello = client_start()

        other_server_state, other_response = server_respond(
            other_hello,
            self.identity_public,
            self.identity_secret,
        )

        _, other_proof = client_finish(
            other_client_state,
            other_response,
            self.fingerprint,
        )

        other_keys = server_finish(
            other_server_state,
            other_proof,
        )

        other_receiver = PacketDecryptor(
            other_keys.client_to_server_key,
            other_keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
        )

        with self.assertRaises(PacketError):
            other_receiver.decrypt(packet)


if __name__ == "__main__":
    unittest.main()
