
"""Bounded in-memory registry for authenticated PQVPN sessions."""

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
        self._lock = threading.Lock()

    def _prune(self):
        now = time.monotonic()
        expired = [
            sid for sid, entry in self._sessions.items()
            if entry.expires_at <= now
        ]
        for sid in expired:
            del self._sessions[sid]

    def create(self, keys, role, *, authorized=False):
        if not authorized:
            raise SessionError(
                "Session activation requires authorization"
            )

        if not isinstance(keys, SessionKeys):
            raise SessionError("Invalid session keys")

        if role not in ("client", "server"):
            raise SessionError("Invalid session role")

        if role == "client":
            transport = lambda sid: SecureSessionTransport(
                sid,
                keys.client_to_server_key,
                keys.client_nonce_prefix,
                CLIENT_TO_SERVER,
                keys.server_to_client_key,
                keys.server_nonce_prefix,
                SERVER_TO_CLIENT,
            )
        else:
            transport = lambda sid: SecureSessionTransport(
                sid,
                keys.server_to_client_key,
                keys.server_nonce_prefix,
                SERVER_TO_CLIENT,
                keys.client_to_server_key,
                keys.client_nonce_prefix,
                CLIENT_TO_SERVER,
            )

        with self._lock:
            self._prune()

            if len(self._sessions) >= MAX_SESSIONS:
                raise SessionError("Session capacity reached")

            sid = secrets.token_bytes(16)
            while sid in self._sessions:
                sid = secrets.token_bytes(16)

            self._sessions[sid] = SessionEntry(
                transport=transport(sid),
                expires_at=time.monotonic() + SESSION_LIFETIME,
            )

            return sid

    def register(self, session_id, keys, role, *, authorized=False):
        """Register a peer-agreed session ID after authorization.

        Caller must establish session_id using an authenticated
        control protocol. Never accept arbitrary IDs from UDP.
        """
        if not authorized:
            raise SessionError("Unauthorized session")

        if not isinstance(session_id, bytes) or len(session_id) != 16:
            raise SessionError("Invalid session ID")

        if not isinstance(keys, SessionKeys):
            raise SessionError("Invalid session keys")

        if role not in ("client", "server"):
            raise SessionError("Invalid role")

        with self._lock:
            self._prune()

            if session_id in self._sessions:
                raise SessionError("Duplicate session ID")

            if len(self._sessions) >= MAX_SESSIONS:
                raise SessionError("Session capacity reached")

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

            self._sessions[session_id] = SessionEntry(
                transport=transport,
                expires_at=time.monotonic() + SESSION_LIFETIME,
            )

    def get(self, session_id):
        with self._lock:
            self._prune()
            entry = self._sessions.get(session_id)

            if entry is None:
                raise SessionError(
                    "Unknown or expired session"
                )

            return entry

    def close(self, session_id):
        with self._lock:
            self._sessions.pop(session_id, None)

    def count(self):
        with self._lock:
            self._prune()
            return len(self._sessions)
