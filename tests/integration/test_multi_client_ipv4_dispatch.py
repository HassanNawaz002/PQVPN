
"""Real UDP socket + mock TUN integration tests for PQVPN."""

import ipaddress
import os
import struct
import unittest
from collections import deque

from gateway.multi_client_registry import MultiClientSessionManager
from gateway.multi_client_ipv4_udp import MultiClientIPv4UDPEngine
from gateway.multi_client_ipv4_dispatch import (
    process_inbound_ipv4,
    process_outbound_ipv4,
)
from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
    decode_ipv4_payload,
)


def make_ipv4(source, destination, payload=b"PQVPN-lab"):
    """Build an IPv4 packet for controlled routing tests."""
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", 20 + len(payload))
    header[8] = 64
    header[9] = 253
    header[12:16] = ipaddress.IPv4Address(source).packed
    header[16:20] = ipaddress.IPv4Address(destination).packed

    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    header[10:12] = struct.pack("!H", (~total) & 0xFFFF)

    return bytes(header) + payload


class MockTun:
    """In-memory TUN-like adapter with observable packet I/O."""

    def __init__(self):
        self.written = []
        self.replies = deque()

    def write_packet(self, packet):
        self.written.append(packet)
        return len(packet)

    def read_packet(self, timeout=0):
        if self.replies:
            return self.replies.popleft()
        return None


class TestMultiClientIPv4Dispatch(unittest.TestCase):

    def setUp(self):
        self.registry = MultiClientSessionManager()

        self.registry.register_client("client-a", "10.77.0.2")
        self.registry.register_client("client-b", "10.77.0.3")

        self.sid_a = os.urandom(16)
        self.sid_b = os.urandom(16)

        self.registry.register_session("client-a", self.sid_a)
        self.registry.register_session("client-b", self.sid_b)

        self.keys_a = self.make_keys()
        self.keys_b = self.make_keys()

        self.engine = MultiClientIPv4UDPEngine(self.registry)

        self.engine.register_authenticated(
            "client-a", self.sid_a, self.keys_a
        )
        self.engine.register_authenticated(
            "client-b", self.sid_b, self.keys_b
        )

        self.crypto_a = self.make_client(self.sid_a, self.keys_a)
        self.crypto_b = self.make_client(self.sid_b, self.keys_b)

        self.tun = MockTun()

        self.gateway = UDPTransport(timeout=0.5)
        self.udp_a = UDPTransport(timeout=0.5)
        self.udp_b = UDPTransport(timeout=0.5)

    def tearDown(self):
        self.gateway.close()
        self.udp_a.close()
        self.udp_b.close()

    @staticmethod
    def make_keys():
        return SessionKeys(
            os.urandom(32),
            os.urandom(32),
            os.urandom(4),
            os.urandom(4),
        )

    @staticmethod
    def make_client(sid, keys):
        return SecureSessionTransport(
            sid,
            keys.client_to_server_key,
            keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
            keys.server_to_client_key,
            keys.server_nonce_prefix,
            SERVER_TO_CLIENT,
        )

    def send_inbound(self, udp, crypto, source):
        packet = make_ipv4(source, "10.77.0.1")

        udp.send(
            self.gateway.address,
            TYPE_DATA,
            crypto.encrypt(encode_ipv4_payload(packet)),
        )

        return packet

    def test_client_a_to_mock_tun(self):
        packet = self.send_inbound(
            self.udp_a, self.crypto_a, "10.77.0.2"
        )

        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertEqual(self.tun.written, [packet])

    def test_client_b_to_mock_tun(self):
        packet = self.send_inbound(
            self.udp_b, self.crypto_b, "10.77.0.3"
        )

        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertEqual(self.tun.written, [packet])

    def test_spoofed_source_never_reaches_tun(self):
        self.send_inbound(
            self.udp_a, self.crypto_a, "10.77.0.3"
        )

        self.assertFalse(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertEqual(self.tun.written, [])

    def test_replay_never_reaches_tun_twice(self):
        packet = self.send_inbound(
            self.udp_a, self.crypto_a, "10.77.0.2"
        )

        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )

        # Reuse the exact authenticated datagram with a fresh socket send.
        replay_crypto = self.make_client(self.sid_a, self.keys_a)
        replay = replay_crypto.encrypt(encode_ipv4_payload(packet))

        self.udp_a.send(self.gateway.address, TYPE_DATA, replay)

        self.assertFalse(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertEqual(self.tun.written, [packet])

    def test_two_clients_independent_tun_forwarding(self):
        packet_a = self.send_inbound(
            self.udp_a, self.crypto_a, "10.77.0.2"
        )
        packet_b = self.send_inbound(
            self.udp_b, self.crypto_b, "10.77.0.3"
        )

        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )

        self.assertEqual(
            self.tun.written,
            [packet_a, packet_b],
        )

    def test_tun_reply_routes_to_client_a(self):
        self.send_inbound(self.udp_a, self.crypto_a, "10.77.0.2")
        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )

        reply = make_ipv4("10.77.0.1", "10.77.0.2")
        self.tun.replies.append(reply)

        self.assertTrue(
            process_outbound_ipv4(self.gateway, self.engine, self.tun)
        )

        kind, encrypted, _sender = self.udp_a.receive()

        self.assertEqual(kind, TYPE_DATA)
        self.assertEqual(
            decode_ipv4_payload(
                self.crypto_a.decrypt(encrypted)
            ).packet,
            reply,
        )

    def test_tun_reply_routes_to_client_b(self):
        self.send_inbound(self.udp_b, self.crypto_b, "10.77.0.3")
        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )

        reply = make_ipv4("10.77.0.1", "10.77.0.3")
        self.tun.replies.append(reply)

        self.assertTrue(
            process_outbound_ipv4(self.gateway, self.engine, self.tun)
        )

        kind, encrypted, _sender = self.udp_b.receive()

        self.assertEqual(kind, TYPE_DATA)
        self.assertEqual(
            decode_ipv4_payload(
                self.crypto_b.decrypt(encrypted)
            ).packet,
            reply,
        )

    def test_revoked_client_packet_not_forwarded(self):
        self.engine.revoke_client("client-a")

        self.send_inbound(self.udp_a, self.crypto_a, "10.77.0.2")

        self.assertFalse(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertEqual(self.tun.written, [])

    def test_revocation_does_not_break_client_b(self):
        self.engine.revoke_client("client-a")

        packet = self.send_inbound(
            self.udp_b, self.crypto_b, "10.77.0.3"
        )

        self.assertTrue(
            process_inbound_ipv4(self.gateway, self.engine, self.tun)
        )
        self.assertEqual(self.tun.written, [packet])

    def test_unknown_tun_destination_dropped(self):
        self.tun.replies.append(
            make_ipv4("10.77.0.1", "10.77.0.99")
        )

        self.assertFalse(
            process_outbound_ipv4(self.gateway, self.engine, self.tun)
        )


if __name__ == "__main__":
    unittest.main()
