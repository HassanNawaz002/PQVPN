
"""Cross-platform UDP transport for PQVPN prototypes."""

import socket

from modules.networking.transport.packet_framing import (
    encode_frame,
    decode_frame,
)

MAX_DATAGRAM = 65535


class UDPTransport:
    def __init__(self, host="127.0.0.1", port=0, timeout=2.0):
        if not isinstance(host, str) or not host:
            raise ValueError("Invalid bind host")

        if not isinstance(port, int) or not (0 <= port <= 65535):
            raise ValueError("Invalid UDP port")

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("Invalid timeout")

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        try:
            self.socket.settimeout(timeout)
            self.socket.bind((host, port))
        except Exception:
            self.socket.close()
            raise

        self.closed = False

    @property
    def address(self):
        return self.socket.getsockname()

    def send(self, destination, message_type, payload=b""):
        if self.closed:
            raise RuntimeError("UDP transport is closed")

        datagram = encode_frame(message_type, payload)

        sent = self.socket.sendto(datagram, destination)

        if sent != len(datagram):
            raise OSError("Incomplete UDP datagram send")

        return sent

    def receive(self):
        if self.closed:
            raise RuntimeError("UDP transport is closed")

        datagram, address = self.socket.recvfrom(
            MAX_DATAGRAM
        )

        message_type, payload = decode_frame(datagram)

        return message_type, payload, address

    def close(self):
        if not self.closed:
            self.closed = True
            self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
