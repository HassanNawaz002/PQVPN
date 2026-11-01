
"""Tests for PQVPN handshake wire format."""

import socket
import struct
import unittest

from modules.encryption.hybrid_handshake import (
    ClientHello,
    ServerHello,
)

from modules.networking.transport.handshake_framing import (
    HandshakeFrameError,
    encode_client_hello,
    decode_client_hello,
    encode_server_hello,
    decode_server_hello,
    encode_client_finished,
    decode_client_finished,
    receive_tcp_message,
    send_tcp_message,
    HEADER,
    MAGIC,
    VERSION,
    TYPE_CLIENT_HELLO,
    MAX_MESSAGE,
)


class TestHandshakeFraming(unittest.TestCase):

    def test_client_hello_roundtrip(self):
        original = ClientHello(
            b"A" * 32,
            b"B" * 1568,
            b"C" * 32,
        )

        frame = encode_client_hello(original)
        decoded = decode_client_hello(frame)

        self.assertEqual(decoded, original)

    def test_server_hello_roundtrip(self):
        original = ServerHello(
            b"A" * 32,
            b"B" * 1568,
            b"C" * 32,
            b"D" * 1952,
            b"E" * 3309,
            b"F" * 48,
        )

        frame = encode_server_hello(original)
        decoded = decode_server_hello(frame)

        self.assertEqual(decoded, original)

    def test_client_finished_roundtrip(self):
        proof = b"X" * 48

        frame = encode_client_finished(proof)

        self.assertEqual(
            decode_client_finished(frame),
            proof,
        )

    def test_wrong_client_public_length(self):
        hello = ClientHello(
            b"A" * 31,
            b"B" * 1568,
            b"C" * 32,
        )

        frame = encode_client_hello(hello)

        with self.assertRaises(HandshakeFrameError):
            decode_client_hello(frame)

    def test_truncated_frame_rejected(self):
        hello = ClientHello(
            b"A" * 32,
            b"B" * 1568,
            b"C" * 32,
        )

        frame = encode_client_hello(hello)

        with self.assertRaises(HandshakeFrameError):
            decode_client_hello(frame[:-1])

    def test_invalid_magic_rejected(self):
        hello = ClientHello(
            b"A" * 32,
            b"B" * 1568,
            b"C" * 32,
        )

        frame = bytearray(
            encode_client_hello(hello)
        )

        frame[0] ^= 1

        with self.assertRaises(HandshakeFrameError):
            decode_client_hello(bytes(frame))

    def test_oversized_message_rejected(self):
        header = HEADER.pack(
            MAGIC,
            VERSION,
            TYPE_CLIENT_HELLO,
            MAX_MESSAGE + 1,
        )

        with self.assertRaises(HandshakeFrameError):
            decode_client_hello(header)

    def test_tcp_socket_roundtrip(self):
        left, right = socket.socketpair()

        try:
            left.settimeout(2)
            right.settimeout(2)

            hello = ClientHello(
                b"A" * 32,
                b"B" * 1568,
                b"C" * 32,
            )

            frame = encode_client_hello(hello)

            send_tcp_message(left, frame)

            received = receive_tcp_message(right)

            self.assertEqual(
                decode_client_hello(received),
                hello,
            )

        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
