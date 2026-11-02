
"""PQVPN Windows Wintun adapter.

Provides Layer-3 packet I/O using the official Wintun DLL.

Does not change system routes, DNS, firewall or default gateway.
Requires Windows, a compatible Wintun DLL and appropriate privileges.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Optional

ERROR_NO_MORE_ITEMS = 259
ERROR_HANDLE_EOF = 38
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
WAIT_FAILED = 0xFFFFFFFF

MAX_PACKET_SIZE = 65535
RING_CAPACITY = 0x400000


class WintunAdapter:
    def __init__(
        self,
        name: str = "PQVPN",
        dll_path: Optional[str] = None,
    ) -> None:
        if not name or len(name) > 127:
            raise ValueError("Invalid Wintun adapter name")

        self.name = name
        self.dll_path = dll_path
        self._dll = None
        self._adapter = None
        self._session = None

    @property
    def is_open(self) -> bool:
        return self._session is not None

    def _load_library(self) -> None:
        if sys.platform != "win32":
            raise OSError("Wintun is supported only on Windows")

        if self.dll_path:
            path = Path(self.dll_path).resolve()
        else:
            path = (
                Path(__file__).resolve().parents[3]
                / "vendor"
                / "wintun"
                / "wintun.dll"
            )

        if not path.is_file():
            raise FileNotFoundError(f"Wintun DLL not found: {path}")

        self._dll = ctypes.WinDLL(str(path), use_last_error=True)

        void_p = ctypes.c_void_p
        dword = ctypes.c_uint32

        def configure(name, restype, argtypes):
            fn = getattr(self._dll, name)
            fn.restype = restype
            fn.argtypes = argtypes
            return fn

        configure(
            "WintunCreateAdapter",
            void_p,
            [ctypes.c_wchar_p, ctypes.c_wchar_p, void_p],
        )
        configure("WintunCloseAdapter", None, [void_p])
        configure(
            "WintunStartSession",
            void_p,
            [void_p, dword],
        )
        configure("WintunEndSession", None, [void_p])
        configure(
            "WintunGetReadWaitEvent",
            void_p,
            [void_p],
        )
        configure(
            "WintunReceivePacket",
            void_p,
            [void_p, ctypes.POINTER(dword)],
        )
        configure(
            "WintunReleaseReceivePacket",
            None,
            [void_p, void_p],
        )
        configure(
            "WintunAllocateSendPacket",
            void_p,
            [void_p, dword],
        )
        configure(
            "WintunSendPacket",
            None,
            [void_p, void_p],
        )

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        error = ctypes.get_last_error()
        raise OSError(error, f"{operation} failed: {ctypes.FormatError(error)}")

    def open(self) -> None:
        if self.is_open or self._adapter is not None:
            raise RuntimeError("Wintun adapter already open")

        self._load_library()

        try:
            self._adapter = self._dll.WintunCreateAdapter(
                self.name,
                "PQVPN",
                None,
            )

            if not self._adapter:
                self._raise_last_error("WintunCreateAdapter")

            self._session = self._dll.WintunStartSession(
                self._adapter,
                RING_CAPACITY,
            )

            if not self._session:
                self._raise_last_error("WintunStartSession")

        except BaseException:
            self.close()
            raise

    def read_packet(
        self,
        timeout: Optional[float] = None,
    ) -> Optional[bytes]:
        if not self.is_open:
            raise RuntimeError("Wintun session is closed")

        if timeout is not None and timeout < 0:
            raise ValueError("Timeout cannot be negative")

        import time

        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            size = ctypes.c_uint32(0)
            ptr = self._dll.WintunReceivePacket(
                self._session,
                ctypes.byref(size),
            )

            if ptr:
                try:
                    if not 0 < size.value <= MAX_PACKET_SIZE:
                        raise ValueError("Invalid received packet size")
                    return ctypes.string_at(ptr, size.value)
                finally:
                    self._dll.WintunReleaseReceivePacket(
                        self._session,
                        ptr,
                    )

            error = ctypes.get_last_error()

            if error == ERROR_HANDLE_EOF:
                raise OSError(error, "Wintun session terminated")

            if error != ERROR_NO_MORE_ITEMS:
                self._raise_last_error("WintunReceivePacket")

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                milliseconds = max(1, min(1000, int(remaining * 1000)))
            else:
                milliseconds = 1000

            event = self._dll.WintunGetReadWaitEvent(self._session)

            if not event:
                self._raise_last_error("WintunGetReadWaitEvent")

            result = ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_void_p(event),
                ctypes.c_uint32(milliseconds),
            )

            if result == WAIT_FAILED:
                self._raise_last_error("WaitForSingleObject")

            if result not in (WAIT_OBJECT_0, WAIT_TIMEOUT):
                raise OSError(f"Unexpected wait result: {result}")

    def write_packet(self, packet: bytes) -> int:
        if not self.is_open:
            raise RuntimeError("Wintun session is closed")

        if not isinstance(packet, bytes):
            raise TypeError("Packet must be bytes")

        if not 0 < len(packet) <= MAX_PACKET_SIZE:
            raise ValueError("Invalid packet size")

        ptr = self._dll.WintunAllocateSendPacket(
            self._session,
            len(packet),
        )

        if not ptr:
            self._raise_last_error("WintunAllocateSendPacket")

        ctypes.memmove(ptr, packet, len(packet))
        self._dll.WintunSendPacket(self._session, ptr)

        return len(packet)

    def close(self) -> None:
        if self._dll is None:
            return

        if self._session is not None:
            self._dll.WintunEndSession(self._session)
            self._session = None

        if self._adapter is not None:
            self._dll.WintunCloseAdapter(self._adapter)
            self._adapter = None

    def __enter__(self) -> "WintunAdapter":
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


