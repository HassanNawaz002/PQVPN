"""Session registry for experimental PQVPN.

Supports authenticated sessions, replay protection, peer binding,
legacy PING/PONG, IPv4 validation and isolated ICMP tunnel replies.
"""

import secrets
import ipaddress
import threading
import time
from dataclasses import dataclass

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.ip_payload import (
    decode_ipv4_payload,
    encode_ipv4_payload,
    validate_tunnel_source,
    MAX_IPV4_PACKET,
)
from modules.networking.host.packet_reader import inspect_ipv4


SESSION_LIFETIME = 300
MAX_SESSIONS = 128
TEST_TUNNEL_CLIENT_IP = "10.77.0.2"
TEST_TUNNEL_GATEWAY_IP = "10.77.0.1"


class SessionError(Exception):
    """Session authorization, lifecycle or endpoint failure."""


def _validate_ipv4_wire(packet):
    """Reject truncated, padded, fragmented or malformed IPv4 datagrams."""
    if not isinstance(packet, bytes) or len(packet) < 20:
        raise SessionError("Invalid IPv4 packet")
    if packet[0] >> 4 != 4:
        raise SessionError("Not IPv4")
    header_length = (packet[0] & 15) * 4
    if header_length < 20 or header_length > len(packet):
        raise SessionError("Invalid IPv4 header length")
    if int.from_bytes(packet[2:4], "big") != len(packet):
        raise SessionError("Invalid IPv4 total length")
    if int.from_bytes(packet[6:8], "big") & 0x3FFF:
        raise SessionError("Fragmented IPv4 unsupported")
    if packet[8] == 0:
        raise SessionError("Expired IPv4 TTL")
    if packet[9] not in (1, 6, 17):
        raise SessionError("Only ICMP, TCP and UDP allowed")


def _validate_internet_outbound(decoded):
    _validate_ipv4_wire(decoded.packet)
    if decoded.protocol not in (1, 6, 17):
        raise SessionError("Unsupported outbound protocol")
    target = ipaddress.IPv4Address(decoded.destination)
    if not target.is_global:
        raise SessionError("Destination must be public IPv4")


def _validate_internet_return(packet, info):
    _validate_ipv4_wire(packet)
    if info.destination != TEST_TUNNEL_CLIENT_IP:
        raise SessionError("Return packet not addressed to VPN client")
    if info.protocol not in (1, 6, 17):
        raise SessionError("Unsupported return protocol")
    source = ipaddress.IPv4Address(info.source)
    if not source.is_global:
        raise SessionError("Return packet must originate from public IPv4")


@dataclass
class SessionEntry:
    transport: SecureSessionTransport
    expires_at: float
    peer: tuple | None = None


class SessionManager:
    """Thread-safe registry of authorized encrypted sessions."""

    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()
        self._active_session_id = None

    def _prune(self):
        """Remove expired sessions. Caller must hold the lock."""
        now = time.monotonic()
        for sid in list(self._sessions):
            if self._sessions[sid].expires_at <= now:
                del self._sessions[sid]

        if self._active_session_id not in self._sessions:
            self._active_session_id = None

    def register(
        self,
        session_id,
        keys,
        role,
        *,
        authorized=False,
    ):
        if not authorized:
            raise SessionError(
                "Session activation requires authorization"
            )

        if not isinstance(session_id, bytes) or len(session_id) != 16:
            raise SessionError("Invalid session ID")

        if not isinstance(keys, SessionKeys):
            raise SessionError("Invalid session keys")

        if role not in ("client", "server"):
            raise SessionError("Invalid role")

        if role == "server":
            transport = SecureSessionTransport(
                session_id,
                keys.server_to_client_key,
                keys.server_nonce_prefix,
                SERVER_TO_CLIENT,
                keys.client_to_server_key,
                keys.client_nonce_prefix,
                CLIENT_TO_SERVER,
            )
        else:
            transport = SecureSessionTransport(
                session_id,
                keys.client_to_server_key,
                keys.client_nonce_prefix,
                CLIENT_TO_SERVER,
                keys.server_to_client_key,
                keys.server_nonce_prefix,
                SERVER_TO_CLIENT,
            )

        with self._lock:
            self._prune()

            if session_id in self._sessions:
                raise SessionError("Duplicate session ID")

            if len(self._sessions) >= MAX_SESSIONS:
                raise SessionError("Session capacity reached")

            self._sessions[session_id] = SessionEntry(
                transport=transport,
                expires_at=time.monotonic() + SESSION_LIFETIME,
            )

            if self._active_session_id is None:
                self._active_session_id = session_id

    def create(self, keys, role, *, authorized=False):
        if not authorized:
            raise SessionError(
                "Session activation requires authorization"
            )

        with self._lock:
            self._prune()

            if len(self._sessions) >= MAX_SESSIONS:
                raise SessionError("Session capacity reached")

            session_id = secrets.token_bytes(16)
            while session_id in self._sessions:
                session_id = secrets.token_bytes(16)

            self.register(
                session_id,
                keys,
                role,
                authorized=True,
            )
            return session_id

    def active_session_id(self):
        """Return the active, unexpired session ID."""
        with self._lock:
            self._prune()
            return self._active_session_id

    def activate(self, session_id):
        """Atomically select a staged session and retire others."""
        with self._lock:
            self._prune()

            if session_id not in self._sessions:
                raise SessionError("Unknown or expired session")

            selected = self._sessions[session_id]
            self._sessions = {session_id: selected}
            self._active_session_id = session_id

    def get(self, session_id):
        with self._lock:
            self._prune()
            entry = self._sessions.get(session_id)

            if entry is None:
                raise SessionError("Unknown or expired session")

            return entry

    def _check_peer(self, entry, address):
        if entry.peer is not None and entry.peer != address:
            raise SessionError("Session endpoint mismatch")

    def process_ping(self, session_id, datagram, address):
        """Authenticate encrypted PING and return encrypted PONG."""
        with self._lock:
            entry = self.get(session_id)
            self._check_peer(entry, address)

            plaintext = entry.transport.decrypt(datagram)
            if plaintext != b"PING":
                raise SessionError("Unsupported payload")

            if entry.peer is None:
                entry.peer = address

            return entry.transport.encrypt(b"PONG")

    def process_ipv4(
        self,
        session_id,
        datagram,
        address,
        *,
        assigned_ip=TEST_TUNNEL_CLIENT_IP,
    ):
        """Authenticate one IPv4 packet without forwarding."""
        with self._lock:
            entry = self.get(session_id)

            if len(self._sessions) != 1:
                raise SessionError(
                    "IPv4 test mode requires exactly one active session"
                )

            self._check_peer(entry, address)

            plaintext = entry.transport.decrypt(datagram)
            decoded = decode_ipv4_payload(plaintext)
            validate_tunnel_source(decoded, assigned_ip)

            if entry.peer is None:
                entry.peer = address

            return decoded

    def process_tunnel_datagram(
        self,
        session_id,
        datagram,
        address,
        *,
        enable_internet=False,
    ):
        """Decrypt once and validate a tunnel packet."""
        with self._lock:
            entry = self.get(session_id)

            if session_id != self._active_session_id:
                raise SessionError(
                    "Tunnel packet from inactive session"
                )

            self._check_peer(entry, address)
            plaintext = entry.transport.decrypt(datagram)

            if plaintext == b"PING":
                if entry.peer is None:
                    entry.peer = address
                return "ping", None

            decoded = decode_ipv4_payload(plaintext)
            validate_tunnel_source(
                decoded,
                TEST_TUNNEL_CLIENT_IP,
            )

            if enable_internet:
                _validate_internet_outbound(decoded)
            elif (
                decoded.destination != TEST_TUNNEL_GATEWAY_IP
                or decoded.protocol != 1
            ):
                raise SessionError(
                    "Only gateway ICMP is allowed in lab mode"
                )

            if entry.peer is None:
                entry.peer = address

            return "ipv4", decoded

    def encrypt_tunnel_reply(self, packet, *, enable_internet=False):
        """Encrypt a real kernel reply for the active client."""
        if len(packet) > MAX_IPV4_PACKET:
            raise SessionError("Reply exceeds tunnel MTU")

        info = inspect_ipv4(packet)

        if enable_internet:
            _validate_internet_return(packet, info)
        elif (
            info.source,
            info.destination,
            info.protocol,
        ) != (
            TEST_TUNNEL_GATEWAY_IP,
            TEST_TUNNEL_CLIENT_IP,
            1,
        ):
            raise SessionError("Unexpected kernel return packet")

        with self._lock:
            self._prune()

            if self._active_session_id is None:
                raise SessionError(
                    "No active tunnel session"
                )

            entry = self._sessions[self._active_session_id]

            if entry.peer is None:
                raise SessionError("No bound client endpoint")

            encrypted = entry.transport.encrypt(
                encode_ipv4_payload(packet)
            )
            return entry.peer, encrypted

    def close(self, session_id):
        with self._lock:
            self._sessions.pop(session_id, None)

            if self._active_session_id == session_id:
                self._active_session_id = None

    def count(self):
        with self._lock:
            self._prune()
            return len(self._sessions)