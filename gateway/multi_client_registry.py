
"""PQVPN multi-client session registry.

Experimental control-plane registry. This module does not
perform cryptographic authentication or network forwarding.

Callers must supply authenticated client identities.
"""

import ipaddress
import threading
import time
from dataclasses import dataclass, field


SESSION_LIFETIME = 300


class MultiClientError(Exception):
    """Invalid multi-client session operation."""


@dataclass
class ClientRecord:
    client_id: str
    tunnel_ip: str
    active_session_id: bytes | None = None
    staged_session_ids: set = field(default_factory=set)


@dataclass
class SessionRecord:
    session_id: bytes
    client_id: str
    expires_at: float


class MultiClientSessionManager:
    """Thread-safe multi-client session ownership registry."""

    def __init__(self):
        self._lock = threading.RLock()
        self._clients = {}
        self._sessions = {}
        self._ip_to_client = {}

    def register_client(self, client_id, tunnel_ip):
        if not isinstance(client_id, str) or not client_id:
            raise MultiClientError("Invalid client identity")

        try:
            address = ipaddress.IPv4Address(tunnel_ip)
        except (ValueError, TypeError) as exc:
            raise MultiClientError(
                "Invalid tunnel IPv4 address"
            ) from exc

        ip = str(address)

        if address not in ipaddress.IPv4Network(
            "10.77.0.0/24"
        ) or ip in ("10.77.0.0", "10.77.0.1", "10.77.0.255"):
            raise MultiClientError(
                "Tunnel IP outside client address pool"
            )

        with self._lock:
            if client_id in self._clients:
                raise MultiClientError(
                    "Client identity already registered"
                )

            if ip in self._ip_to_client:
                raise MultiClientError(
                    "Tunnel IP already assigned"
                )

            self._clients[client_id] = ClientRecord(
                client_id=client_id,
                tunnel_ip=ip,
            )

            self._ip_to_client[ip] = client_id

    def _prune(self):
        now = time.monotonic()

        for sid, record in list(self._sessions.items()):
            if record.expires_at <= now:
                self._remove_session(sid)

    def _remove_session(self, session_id):
        record = self._sessions.pop(session_id, None)

        if record is None:
            return

        client = self._clients[record.client_id]

        client.staged_session_ids.discard(session_id)

        if client.active_session_id == session_id:
            client.active_session_id = None

    def register_session(self, client_id, session_id):
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            raise MultiClientError("Invalid session ID")

        with self._lock:
            self._prune()

            client = self._clients.get(client_id)

            if client is None:
                raise MultiClientError("Unknown client")

            if session_id in self._sessions:
                raise MultiClientError(
                    "Duplicate session ID"
                )

            self._sessions[session_id] = SessionRecord(
                session_id=session_id,
                client_id=client_id,
                expires_at=time.monotonic() + SESSION_LIFETIME,
            )

            if client.active_session_id is None:
                client.active_session_id = session_id
            else:
                client.staged_session_ids.add(session_id)

    def activate(self, client_id, session_id):
        """Commit a staged session for its owning client only."""
        with self._lock:
            self._prune()

            client = self._clients.get(client_id)
            record = self._sessions.get(session_id)

            if client is None or record is None:
                raise MultiClientError(
                    "Unknown client or session"
                )

            if record.client_id != client_id:
                raise MultiClientError(
                    "Cross-client activation forbidden"
                )

            if (
                session_id != client.active_session_id
                and session_id not in client.staged_session_ids
            ):
                raise MultiClientError(
                    "Session not staged for client"
                )

            owned_sessions = [
                sid
                for sid, item in self._sessions.items()
                if item.client_id == client_id
                and sid != session_id
            ]

            for old_sid in owned_sessions:
                self._remove_session(old_sid)

            client.staged_session_ids.discard(session_id)
            client.active_session_id = session_id

    def active_session(self, client_id):
        with self._lock:
            self._prune()

            client = self._clients.get(client_id)

            if client is None:
                raise MultiClientError("Unknown client")

            return client.active_session_id

    def client_for_ip(self, tunnel_ip):
        with self._lock:
            return self._ip_to_client.get(tunnel_ip)

    def owner_of_session(self, session_id):
        with self._lock:
            self._prune()

            record = self._sessions.get(session_id)

            if record is None:
                raise MultiClientError(
                    "Unknown or expired session"
                )

            return record.client_id

    def session_count(self):
        with self._lock:
            self._prune()
            return len(self._sessions)

    def client_count(self):
        with self._lock:
            return len(self._clients)
