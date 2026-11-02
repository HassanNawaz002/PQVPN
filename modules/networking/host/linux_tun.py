"""PQVPN Linux TUN adapter.

Layer-3 packet I/O only. Does not modify routes, DNS, NAT or firewall.
"""

from __future__ import annotations

import fcntl
import os
import select
import struct
from typing import Optional

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
MAX_PACKET_SIZE = 65535


class LinuxTunAdapter:
    def __init__(self, name: str = "pqvpn0") -> None:
        try:
            encoded = name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("TUN name must be ASCII") from exc

        if not encoded or len(encoded) > 15:
            raise ValueError("TUN name must be 1-15 ASCII bytes")

        if b"\x00" in encoded or b"/" in encoded:
            raise ValueError("Invalid TUN interface name")

        self.name = name
        self._fd: Optional[int] = None

    @property
    def is_open(self) -> bool:
        return self._fd is not None

    def open(self) -> None:
        if self.is_open:
            raise RuntimeError("TUN adapter already open")

        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)

        try:
            request = struct.pack(
                "16sH",
                self.name.encode("ascii"),
                IFF_TUN | IFF_NO_PI,
            )

            result = fcntl.ioctl(fd, TUNSETIFF, request)

            self.name = result[:16].split(b"\x00", 1)[0].decode("ascii")
            self._fd = fd

        except BaseException:
            os.close(fd)
            raise

    def read_packet(
        self,
        timeout: Optional[float] = None,
    ) -> Optional[bytes]:
        if self._fd is None:
            raise RuntimeError("TUN adapter is closed")

        if timeout is not None and timeout < 0:
            raise ValueError("Timeout must not be negative")

        ready, _, _ = select.select([self._fd], [], [], timeout)

        if not ready:
            return None

        packet = os.read(self._fd, MAX_PACKET_SIZE)

        return packet or None

    def write_packet(self, packet: bytes) -> int:
        if self._fd is None:
            raise RuntimeError("TUN adapter is closed")

        if not isinstance(packet, bytes):
            raise TypeError("Packet must be bytes")

        if not packet or len(packet) > MAX_PACKET_SIZE:
            raise ValueError("Invalid packet size")

        return os.write(self._fd, packet)

    def close(self) -> None:
        if self._fd is not None:
            fd = self._fd
            self._fd = None
            os.close(fd)

    def __enter__(self) -> "LinuxTunAdapter":
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
