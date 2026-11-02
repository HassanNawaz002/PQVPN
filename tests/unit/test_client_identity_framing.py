
"""Tests for PQVPN multi-client identity preface."""

import socket
import unittest

from modules.networking.transport.client_identity_framing import (
    ClientIdentityFrameError,
    encode_identity_preface,
    decode_identity_preface,
    send_identity_preface,
    receive_identity_preface,
)


class TestClientIdentityFraming(unittest.TestCase):

    def test_roundtrip(self):
        frame = encode_identity_preface("client-a")
        self.assertEqual(
            decode_identity_preface(frame),
            "client-a",
        )

    def test_distinct_clients(self):
        a = encode_identity_preface("client-a")
        b = encode_identity_preface("client-b")
        self.assertNotEqual(a, b)

    def test_max_length_identity(self):
        client_id = "a" * 64
        frame = encode_identity_preface(client_id)
        self.assertEqual(
            decode_identity_preface(frame),
            client_id,
        )

    def test_empty_identity_rejected(self):
        with self.assertRaises(ClientIdentityFrameError):
            encode_identity_preface("")

    def test_invalid_characters_rejected(self):
        with self.assertRaises(ClientIdentityFrameError):
            encode_identity_preface("../client-a")

    def test_oversized_identity_rejected(self):
        with self.assertRaises(ClientIdentityFrameError):
            encode_identity_preface("a" * 65)

    def test_invalid_magic_rejected(self):
        frame = bytearray(
            encode_identity_preface("client-a")
        )
        frame[0] ^= 1

        with self.assertRaises(ClientIdentityFrameError):
            decode_identity_preface(bytes(frame))

    def test_invalid_version_rejected(self):
        frame = bytearray(
            encode_identity_preface("client-a")
        )
        frame[4] = 99

        with self.assertRaises(ClientIdentityFrameError):
            decode_identity_preface(bytes(frame))

    def test_truncated_frame_rejected(self):
        frame = encode_identity_preface("client-a")

        with self.assertRaises(ClientIdentityFrameError):
            decode_identity_preface(frame[:-1])

    def test_trailing_bytes_rejected(self):
        frame = encode_identity_preface("client-a")

        with self.assertRaises(ClientIdentityFrameError):
            decode_identity_preface(frame + b"x")

    def test_invalid_utf8_rejected(self):
        frame = b"PQID" + bytes([1, 1, 255])

        with self.assertRaises(ClientIdentityFrameError):
            decode_identity_preface(frame)

    def test_socket_roundtrip(self):
        sender, receiver = socket.socketpair()

        try:
            sender.settimeout(2)
            receiver.settimeout(2)

            send_identity_preface(sender, "client-a")

            self.assertEqual(
                receive_identity_preface(receiver),
                "client-a",
            )
        finally:
            sender.close()
            receiver.close()

    def test_socket_rejects_invalid_header(self):
        sender, receiver = socket.socketpair()

        try:
            sender.settimeout(2)
            receiver.settimeout(2)

            sender.sendall(b"BAD!" + bytes([1, 3]))

            with self.assertRaises(ClientIdentityFrameError):
                receive_identity_preface(receiver)
        finally:
            sender.close()
            receiver.close()

    def test_socket_rejects_early_close(self):
        sender, receiver = socket.socketpair()

        try:
            receiver.settimeout(2)
            sender.sendall(b"PQID")
            sender.close()

            with self.assertRaises(ClientIdentityFrameError):
                receive_identity_preface(receiver)
        finally:
            receiver.close()


if __name__ == "__main__":
    unittest.main()
