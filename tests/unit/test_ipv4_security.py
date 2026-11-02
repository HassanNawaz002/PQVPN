
"""Security regression tests for strict IPv4 validation."""

import ipaddress
import struct
import unittest

from modules.networking.host.ipv4_security import (
    validate_secure_ipv4,
    IPv4SecurityError,
)


def make_packet(
    source="10.77.0.2",
    destination="10.77.0.1",
    payload=b"test",
    flags_offset=0,
    ihl=5,
):
    header_length = ihl * 4

    header = bytearray(header_length)
    header[0] = (4 << 4) | ihl

    struct.pack_into(
        "!H", header, 2, header_length + len(payload)
    )
    struct.pack_into("!H", header, 6, flags_offset)

    header[8] = 64
    header[9] = 253

    header[12:16] = ipaddress.IPv4Address(source).packed
    header[16:20] = ipaddress.IPv4Address(destination).packed

    words = struct.unpack(
        f"!{len(header) // 2}H",
        header,
    )

    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    struct.pack_into(
        "!H", header, 10, (~total) & 0xFFFF
    )

    return bytes(header) + payload


class TestIPv4Security(unittest.TestCase):

    def assert_rejected(self, packet):
        with self.assertRaises(IPv4SecurityError):
            validate_secure_ipv4(packet)

    def test_valid_packet(self):
        info = validate_secure_ipv4(make_packet())
        self.assertEqual(info.source, "10.77.0.2")

    def test_valid_df_packet(self):
        packet = make_packet(flags_offset=0x4000)
        validate_secure_ipv4(packet)

    def test_bad_checksum(self):
        packet = bytearray(make_packet())
        packet[10] ^= 0x01
        self.assert_rejected(bytes(packet))

    def test_modified_source_without_checksum_update(self):
        packet = bytearray(make_packet())
        packet[15] = 3
        self.assert_rejected(bytes(packet))

    def test_more_fragments_flag(self):
        self.assert_rejected(
            make_packet(flags_offset=0x2000)
        )

    def test_nonzero_fragment_offset(self):
        self.assert_rejected(
            make_packet(flags_offset=0x0001)
        )

    def test_reserved_flag(self):
        self.assert_rejected(
            make_packet(flags_offset=0x8000)
        )

    def test_ipv4_options_rejected(self):
        self.assert_rejected(make_packet(ihl=6))

    def test_multicast_destination(self):
        self.assert_rejected(
            make_packet(destination="224.0.0.1")
        )

    def test_unspecified_source(self):
        self.assert_rejected(
            make_packet(source="0.0.0.0")
        )

    def test_broadcast_destination(self):
        self.assert_rejected(
            make_packet(destination="255.255.255.255")
        )

    def test_oversized_packet(self):
        self.assert_rejected(
            make_packet(payload=b"A" * 1181)
        )

    def test_truncated_packet(self):
        self.assert_rejected(make_packet()[:15])

    def test_total_length_mismatch(self):
        self.assert_rejected(
            make_packet() + b"extra"
        )

    def test_ipv6_rejected(self):
        packet = bytearray(make_packet())
        packet[0] = 0x65
        self.assert_rejected(bytes(packet))


if __name__ == "__main__":
    unittest.main()
