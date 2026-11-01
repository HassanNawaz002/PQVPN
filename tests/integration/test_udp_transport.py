
"""PQVPN UDP transport integration tests."""

import socket
import unittest

from modules.networking.transport.packet_framing import (
    TYPE_PING,
    TYPE_PONG,
    FrameError,
    encode_frame,
    decode_frame,
)

from modules.networking.transport.udp_transport import (
    UDPTransport,
)


class TestUDPTransport(unittest.TestCase):

    def test_frame_roundtrip(self):
        datagram = encode_frame(TYPE_PING, b"PQVPN")

        self.assertEqual(
            decode_frame(datagram),
            (TYPE_PING, b"PQVPN"),
        )

    def test_invalid_magic_rejected(self):
        datagram = bytearray(
            encode_frame(TYPE_PING, b"test")
        )

        datagram[0] ^= 1

        with self.assertRaises(FrameError):
            decode_frame(bytes(datagram))

    def test_invalid_length_rejected(self):
        datagram = encode_frame(TYPE_PING, b"test")

        with self.assertRaises(FrameError):
            decode_frame(datagram[:-1])

    def test_invalid_message_type_rejected(self):
        with self.assertRaises(FrameError):
            encode_frame(99, b"test")

    def test_real_udp_exchange(self):
        with UDPTransport(port=0) as server:
            with UDPTransport(port=0) as client:

                client.send(
                    server.address,
                    TYPE_PING,
                    b"Hello",
                )

                kind, payload, source = server.receive()

                self.assertEqual(kind, TYPE_PING)
                self.assertEqual(payload, b"Hello")

                server.send(
                    source,
                    TYPE_PONG,
                    b"World",
                )

                kind, payload, source = client.receive()

                self.assertEqual(kind, TYPE_PONG)
                self.assertEqual(payload, b"World")
                self.assertEqual(source, server.address)

    def test_udp_timeout(self):
        with UDPTransport(timeout=0.1) as transport:
            with self.assertRaises(socket.timeout):
                transport.receive()


if __name__ == "__main__":
    unittest.main()
