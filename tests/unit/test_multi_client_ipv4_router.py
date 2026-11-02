
"""Unit tests for isolated multi-client IPv4 routing policy."""

import ipaddress
import struct
import unittest

from gateway.multi_client_registry import MultiClientSessionManager
from gateway.multi_client_ipv4_router import (
    MultiClientIPv4Router,
    MultiClientRoutingError,
)
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
)


def make_ipv4(source, destination, payload=b"test"):
    """Create a minimal IPv4 packet for policy tests."""
    total_length = 20 + len(payload)

    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", total_length)
    header[8] = 64
    header[9] = 253

    header[12:16] = ipaddress.IPv4Address(
        source
    ).packed

    header[16:20] = ipaddress.IPv4Address(
        destination
    ).packed

    # Standard IPv4 header checksum.
    words = struct.unpack("!10H", header)
    checksum = (~sum(words)) & 0xFFFF

    header[10:12] = struct.pack("!H", checksum)

    return bytes(header) + payload


class TestMultiClientIPv4Router(unittest.TestCase):

    def setUp(self):
        self.registry = MultiClientSessionManager()

        self.sid_a = b"A" * 16
        self.sid_b = b"B" * 16

        self.registry.register_client(
            "client-a",
            "10.77.0.2",
        )
        self.registry.register_client(
            "client-b",
            "10.77.0.3",
        )

        self.registry.register_session(
            "client-a",
            self.sid_a,
        )
        self.registry.register_session(
            "client-b",
            self.sid_b,
        )

        self.router = MultiClientIPv4Router(
            self.registry
        )

    def inbound(self, sid, source, destination="10.77.0.1"):
        packet = make_ipv4(source, destination)

        return self.router.accept_inbound(
            sid,
            encode_ipv4_payload(packet),
        )

    def test_client_a_source_accepted(self):
        route = self.inbound(
            self.sid_a,
            "10.77.0.2",
        )
        self.assertEqual(route.client_id, "client-a")

    def test_client_b_source_accepted(self):
        route = self.inbound(
            self.sid_b,
            "10.77.0.3",
        )
        self.assertEqual(route.client_id, "client-b")

    def test_client_a_cannot_spoof_b(self):
        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                self.sid_a,
                "10.77.0.3",
            )

    def test_client_b_cannot_spoof_a(self):
        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                self.sid_b,
                "10.77.0.2",
            )

    def test_internet_destination_rejected(self):
        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                self.sid_a,
                "10.77.0.2",
                "8.8.8.8",
            )

    def test_client_to_client_rejected(self):
        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                self.sid_a,
                "10.77.0.2",
                "10.77.0.3",
            )

    def test_unknown_session_rejected(self):
        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                b"X" * 16,
                "10.77.0.2",
            )

    def test_staged_session_rejected(self):
        staged = b"S" * 16

        self.registry.register_session(
            "client-a",
            staged,
        )

        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                staged,
                "10.77.0.2",
            )

    def test_revoked_session_rejected(self):
        self.registry.revoke_client_sessions(
            "client-a"
        )

        with self.assertRaises(MultiClientRoutingError):
            self.inbound(
                self.sid_a,
                "10.77.0.2",
            )

    def test_outbound_routes_to_client_a(self):
        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.2",
        )

        route = self.router.select_outbound(packet)

        self.assertEqual(route.client_id, "client-a")
        self.assertEqual(route.session_id, self.sid_a)

    def test_outbound_routes_to_client_b(self):
        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.3",
        )

        route = self.router.select_outbound(packet)

        self.assertEqual(route.client_id, "client-b")
        self.assertEqual(route.session_id, self.sid_b)

    def test_outbound_unknown_destination_rejected(self):
        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.99",
        )

        with self.assertRaises(MultiClientRoutingError):
            self.router.select_outbound(packet)

    def test_outbound_internet_destination_rejected(self):
        packet = make_ipv4(
            "10.77.0.1",
            "8.8.8.8",
        )

        with self.assertRaises(MultiClientRoutingError):
            self.router.select_outbound(packet)

    def test_outbound_spoofed_gateway_source_rejected(self):
        packet = make_ipv4(
            "10.77.0.99",
            "10.77.0.2",
        )

        with self.assertRaises(MultiClientRoutingError):
            self.router.select_outbound(packet)

    def test_outbound_revoked_client_rejected(self):
        self.registry.revoke_client_sessions(
            "client-a"
        )

        packet = make_ipv4(
            "10.77.0.1",
            "10.77.0.2",
        )

        with self.assertRaises(MultiClientRoutingError):
            self.router.select_outbound(packet)


if __name__ == "__main__":
    unittest.main()
