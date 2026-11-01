
"""Bounded, thread-safe in-memory session registry for experimental PQVPN."""

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


SESSION_LIFETIME = 300
MAX_SESSIONS = 128


class SessionError(Exception):
    pass


@dataclass
class SessionEntry:
    transport: SecureSessionTransport
    expires_at: float
    peer: tuple | None = None


class SessionManager:

    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def _prune(self):
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
        """Only trusted code may call after verifying authorization."""

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
        with self._lock:
            self._prune()

            entry = self._sessions.get(session_id)

            if entry is None:
                raise SessionError(
                    "Unknown or expired session"
                )

            return entry

    def process_ping(
        self,
        session_id,
        datagram,
        address,
    ):
        """Atomically validate, decrypt and respond."""

        with self._lock:
            entry = self.get(session_id)

            if (
                entry.peer is not None
                and entry.peer != address
            ):
                raise SessionError(
                    "Session endpoint mismatch"
                )

            plaintext = entry.transport.decrypt(datagram)

            if plaintext != b"PING":
                raise SessionError(
                    "Unsupported payload"
                )

            if entry.peer is None:
                entry.peer = address

            return entry.transport.encrypt(b"PONG")

    def close(self, session_id):
        with self._lock:
            self._sessions.pop(session_id, None)

    def count(self):
        with self._lock:
            self._prune()
            return len(self._sessions)
