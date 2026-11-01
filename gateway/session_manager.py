
"""Bounded, thread-safe in-memory session registry for experimental PQVPN.

Features:
- Authorized session registration
- Directional authenticated AES-256-GCM transport
- Replay protection through SecureSessionTransport
- UDP peer binding
- Session expiry and capacity limits
- Legacy encrypted PING/PONG
- Controlled single-client encrypted IPv4 packet delivery

IPv4 delivery does NOT perform TUN injection, routing or NAT.
"""

import secrets
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
    validate_tunnel_source,
)


SESSION_LIFETIME = 300
MAX_SESSIONS = 128

# Sprint 12C.2: isolated single-client test configuration.
TEST_TUNNEL_CLIENT_IP = "10.77.0.2"


class SessionError(Exception):
    """Session authorization, lifecycle or endpoint failure."""


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

    def _prune(self):
        """Remove expired sessions. Caller must hold the lock."""

        now = time.monotonic()

        for sid in list(self._sessions):
            if self._sessions[sid].expires_at <= now:
                del self._sessions[sid]

    def register(
        self,
        session_id,
        keys,
        role,
        *,
        authorized=False,
    ):
        """Register an explicitly authorized session."""

        if not authorized:
            raise SessionError(
                "Session activation requires authorization"
            )

        if (
            not isinstance(session_id, bytes)
            or len(session_id) != 16
        ):
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
                raise SessionError(
                    "Session capacity reached"
                )

            self._sessions[session_id] = SessionEntry(
                transport=transport,
                expires_at=(
                    time.monotonic() + SESSION_LIFETIME
                ),
            )

    def create(self, keys, role, *, authorized=False):
        """Create a cryptographically random session identifier."""

        if not authorized:
            raise SessionError(
                "Session activation requires authorization"
            )

        with self._lock:
            self._prune()

            if len(self._sessions) >= MAX_SESSIONS:
                raise SessionError(
                    "Session capacity reached"
                )

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

    def get(self, session_id):
        """Retrieve a live authorized session."""

        with self._lock:
            self._prune()

            entry = self._sessions.get(session_id)

            if entry is None:
                raise SessionError(
                    "Unknown or expired session"
                )

            return entry

    def _check_peer(self, entry, address):
        """Reject packets from a different bound UDP endpoint."""

        if (
            entry.peer is not None
            and entry.peer != address
        ):
            raise SessionError(
                "Session endpoint mismatch"
            )

    def process_ping(
        self,
        session_id,
        datagram,
        address,
    ):
        """Authenticate encrypted PING and return encrypted PONG."""

        with self._lock:
            entry = self.get(session_id)

            self._check_peer(entry, address)

            plaintext = entry.transport.decrypt(datagram)

            if plaintext != b"PING":
                raise SessionError(
                    "Unsupported payload"
                )

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
        """Authenticate and validate one IPv4 packet.

        Restricted to exactly one active session for this
        controlled prototype.

        Returns the decoded IPv4 payload.

        Does not forward or inject the packet.
        """

        with self._lock:
            entry = self.get(session_id)

            # Fixed tunnel IP cannot safely be shared by
            # multiple simultaneous sessions.
            if len(self._sessions) != 1:
                raise SessionError(
                    "IPv4 test mode requires exactly "
                    "one active session"
                )

            self._check_peer(entry, address)

            # Authenticated decryption also enforces replay
            # protection via the existing packet decryptor.
            plaintext = entry.transport.decrypt(datagram)

            decoded = decode_ipv4_payload(plaintext)

            # Prevent spoofing another tunnel source address.
            validate_tunnel_source(
                decoded,
                assigned_ip,
            )

            # Bind the peer only after successful validation.
            if entry.peer is None:
                entry.peer = address

            return decoded

    def close(self, session_id):
        """Explicitly remove a session."""

        with self._lock:
            self._sessions.pop(session_id, None)

    def count(self):
        """Return the number of currently active sessions."""

        with self._lock:
            self._prune()
            return len(self._sessions)
