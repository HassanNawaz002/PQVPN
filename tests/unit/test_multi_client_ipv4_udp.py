
"""Security tests for authenticated multi-client IPv4 over UDP.

No real TUN interface or AWS connection is required.
"""

import ipaddress
import os
import struct
import unittest

from gateway.multi_client_registry import MultiClientSessionManager
from gateway.multi_client_ipv4_udp import (
    MultiClientIPv4UDPEngine,
    MultiClientIPv4UDPError,
)
from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
    decode_ipv4_payload,
)


def make_ipv4(source, destination, payload=b"PQVPN-test"):
    """Create a structurally valid IPv4 packet with checksum."""
    total_length = 20 + len(payload)

    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", total_length)
    header[8] = 64
    header[9] = 253  # Experimental protocol number

    header[12:16] = ipaddress.IPv4Address(source).packed
    header[16:20] = ipaddress.IPv4Address(destination).packed

    words = struct.unpack("!10H", header)
    total = sum(words)

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    checksum = (~total) & 0xFFFF
    header[10:12] = struct.pack("!H", checksum)

    return bytes(header) + payload


class TestMultiClientIPv4UDP(unittest.TestCase):

    def setUp(self):
        self.registry = MultiClientSessionManager()

        self.registry.register_client(
            "client-a", "10.77.0.2"
        )
        self.registry.register_client(
            "client-b", "10.77.0.3"
        )

        self.sid_a = os.urandom(16)
        self.sid_b = os.urandom(16)

        self.keys_a = self.make_keys()
        self.keys_b = self.make_keys()

        self.registry.register_session(
            "client-a", self.sid_a
        )
        self.registry.register_session(
            "client-b", self.sid_b
        )

        self.engine = MultiClientIPv4UDPEngine(
            self.registry
        )

        self.engine.register_authenticated(
            "client-a",
            self.sid_a,
            self.keys_a,
        )
        self.engine.register_authenticated(
            "client-b",
            self.sid_b,
            self.keys_b,
        )

        self.crypto_a = self.make_client_transport(
            self.sid_a, self.keys_a
        )
        self.crypto_b = self.make_client_transport(
            self.sid_b, self.keys_b
        )

        self.peer_a = ("127.0.0.1", 41001)
        self.peer_b = ("127.0.0.1", 41002)

    @staticmethod
    def make_keys():
        return SessionKeys(
            os.urandom(32),
            os.urandom(32),
            os.urandom(4),
            os.urandom(4),
        )

    @staticmethod
    def make_client_transport(sid, keys):
        return SecureSessionTransport(
            sid,
            keys.client_to_server_key,
            keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
            keys.server_to_client_key,
            keys.server_nonce_prefix,
            SERVER_TO_CLIENT,
        )

    @staticmethod
    def encrypted_ipv4(crypto, source, destination):
        packet = make_ipv4(source, destination)
        return crypto.encrypt(
            encode_ipv4_payload(packet)
        )

    def bind_a(self):
        datagram = self.encrypted_ipv4(
            self.crypto_a,
            "10.77.0.2",
            "10.77.0.1",
        )
        return self.engine.receive_ipv4(
            datagram,
            self.peer_a,
        )

    def bind_b(self):
        datagram = self.encrypted_ipv4(
            self.crypto_b,
            "10.77.0.3",
            "10.77.0.1",
        )
        return self.engine.receive_ipv4(
            datagram,
            self.peer_b,
        )

    def test_client_a_encrypted_ipv4(self):
        route = self.bind_a()

        self.assertEqual(route.client_id, "client-a")
        self.assertEqual(route.source, "10.77.0.2")
        self.assertEqual(route.destination, "10.77.0.1")

    def test_client_b_encrypted_ipv4(self):
        route = self.bind_b()

        self.assertEqual(route.client_id, "client-b")
        self.assertEqual(route.source, "10.77.0.3")

    def test_two_clients_independent(self):
        route_a = self.bind_a()
        route_b = self.bind_b()

        self.assertNotEqual(
            route_a.session_id,
            route_b.session_id,
        )

        self.assertEqual(
            self.engine.bound_peer(self.sid_a),
            self.peer_a,
        )
        self.assertEqual(
            self.engine.bound_peer(self.sid_b),
            self.peer_b,
        )

    def test_client_a_cannot_spoof_b(self):
        datagram = self.encrypted_ipv4(
            self.crypto_a,
            "10.77.0.3",
            "10.77.0.1",
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram, self.peer_a
            )

        self.assertIsNone(
            self.engine.bound_peer(self.sid_a)
        )

    def test_client_b_cannot_spoof_a(self):
        datagram = self.encrypted_ipv4(
            self.crypto_b,
            "10.77.0.2",
            "10.77.0.1",
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram, self.peer_b
            )

    def test_replay_rejected(self):
        datagram = self.encrypted_ipv4(
            self.crypto_a,
            "10.77.0.2",
            "10.77.0.1",
        )

        self.engine.receive_ipv4(
            datagram, self.peer_a
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram, self.peer_a
            )

    def test_tampering_rejected(self):
        datagram = bytearray(
            self.encrypted_ipv4(
                self.crypto_a,
                "10.77.0.2",
                "10.77.0.1",
            )
        )
        datagram[-1] ^= 0x01

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                bytes(datagram), self.peer_a
            )

        self.assertIsNone(
            self.engine.bound_peer(self.sid_a)
        )

    def test_wrong_endpoint_rejected(self):
        self.bind_a()

        datagram = self.encrypted_ipv4(
            self.crypto_a,
            "10.77.0.2",
            "10.77.0.1",
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram,
                ("127.0.0.1", 49999),
            )

    def test_internet_destination_rejected(self):
        datagram = self.encrypted_ipv4(
            self.crypto_a,
            "10.77.0.2",
            "8.8.8.8",
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram, self.peer_a
            )

    def test_outbound_encrypted_for_a(self):
        self.bind_a()

        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.2",
        )

        peer, encrypted = (
            self.engine.encrypt_ipv4_reply(packet)
        )

        self.assertEqual(peer, self.peer_a)

        plaintext = self.crypto_a.decrypt(encrypted)
        decoded = decode_ipv4_payload(plaintext)

        self.assertEqual(decoded.packet, packet)

    def test_outbound_encrypted_for_b(self):
        self.bind_b()

        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.3",
        )

        peer, encrypted = (
            self.engine.encrypt_ipv4_reply(packet)
        )

        self.assertEqual(peer, self.peer_b)

        plaintext = self.crypto_b.decrypt(encrypted)
        decoded = decode_ipv4_payload(plaintext)

        self.assertEqual(decoded.packet, packet)

    def test_revocation_blocks_inbound(self):
        self.bind_a()
        self.engine.revoke_client("client-a")

        datagram = self.encrypted_ipv4(
            self.crypto_a,
            "10.77.0.2",
            "10.77.0.1",
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram, self.peer_a
            )

    def test_revocation_blocks_outbound(self):
        self.bind_a()
        self.engine.revoke_client("client-a")

        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.2",
        )

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.encrypt_ipv4_reply(packet)

    def test_revoking_a_preserves_b(self):
        self.bind_a()
        self.bind_b()

        self.engine.revoke_client("client-a")

        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.3",
        )

        peer, encrypted = (
            self.engine.encrypt_ipv4_reply(packet)
        )

        self.assertEqual(peer, self.peer_b)
        self.assertEqual(
            decode_ipv4_payload(
                self.crypto_b.decrypt(encrypted)
            ).packet,
            packet,
        )

    def test_unknown_session_rejected(self):
        datagram = os.urandom(64)

        with self.assertRaises(MultiClientIPv4UDPError):
            self.engine.receive_ipv4(
                datagram, self.peer_a
            )


if __name__ == "__main__":
    unittest.main()
