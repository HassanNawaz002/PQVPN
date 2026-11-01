
import unittest

from modules.encryption.cipher_suites import (
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
    PacketError,
    ReplayError,
    SequenceExhausted,
    MAX_SEQUENCE,
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


class TestPacketSecurity(unittest.TestCase):

    def setUp(self):
        public, secret = generate_keypair()
        fingerprint = public_key_fingerprint(public)

        client_state, hello = client_start()
        server_state, response = server_respond(
            hello, public, secret
        )

        self.client_keys, proof = client_finish(
            client_state, response, fingerprint
        )
        self.server_keys = server_finish(
            server_state, proof
        )

        self.sender = PacketEncryptor(
            self.client_keys.client_to_server_key,
            self.client_keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
        )
        self.receiver = PacketDecryptor(
            self.server_keys.client_to_server_key,
            self.server_keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
        )

    def test_encrypted_packet_roundtrip(self):
        packet = self.sender.encrypt(b"hello PQVPN")
        self.assertEqual(
            self.receiver.decrypt(packet),
            b"hello PQVPN",
        )

    def test_ciphertext_differs_from_plaintext(self):
        packet = self.sender.encrypt(b"secret message")
        self.assertNotIn(b"secret message", packet)

    def test_unique_nonce_per_packet(self):
        first = self.sender.encrypt(b"same")
        second = self.sender.encrypt(b"same")
        self.assertNotEqual(first, second)

    def test_duplicate_packet_rejected(self):
        packet = self.sender.encrypt(b"data")
        self.receiver.decrypt(packet)

        with self.assertRaises(ReplayError):
            self.receiver.decrypt(packet)

    def test_tampered_ciphertext_rejected(self):
        packet = bytearray(self.sender.encrypt(b"data"))
        packet[-1] ^= 1

        with self.assertRaises(PacketError):
            self.receiver.decrypt(bytes(packet))

    def test_tampered_header_rejected(self):
        packet = bytearray(self.sender.encrypt(b"data"))
        packet[2] ^= 1

        with self.assertRaises(PacketError):
            self.receiver.decrypt(bytes(packet))

    def test_failed_auth_does_not_consume_sequence(self):
        packet = self.sender.encrypt(b"valid")
        altered = bytearray(packet)
        altered[-1] ^= 1

        with self.assertRaises(PacketError):
            self.receiver.decrypt(bytes(altered))

        self.assertEqual(self.receiver.decrypt(packet), b"valid")

    def test_out_of_order_packets(self):
        packets = [
            self.sender.encrypt(str(i).encode())
            for i in range(3)
        ]

        self.assertEqual(self.receiver.decrypt(packets[2]), b"2")
        self.assertEqual(self.receiver.decrypt(packets[0]), b"0")
        self.assertEqual(self.receiver.decrypt(packets[1]), b"1")

    def test_wrong_direction_rejected(self):
        packet = self.sender.encrypt(b"data")

        wrong_receiver = PacketDecryptor(
            self.server_keys.client_to_server_key,
            self.server_keys.client_nonce_prefix,
            SERVER_TO_CLIENT,
        )

        with self.assertRaises(PacketError):
            wrong_receiver.decrypt(packet)

    def test_sequence_exhaustion(self):
        self.sender._next_sequence = MAX_SEQUENCE
        self.sender.encrypt(b"last")

        with self.assertRaises(SequenceExhausted):
            self.sender.encrypt(b"must fail")


if __name__ == "__main__":
    unittest.main()
