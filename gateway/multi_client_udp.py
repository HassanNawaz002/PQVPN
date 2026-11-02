
"""PQVPN experimental multi-client encrypted UDP session engine.

Isolated from the legacy single-client gateway.

Sessions must be registered using keys obtained from an
authenticated TCP handshake. Staged rekey sessions cannot
exchange ordinary data.

No TUN forwarding or rekey activation is implemented here.
"""

import threading
import time
from modules.encryption.cipher_suites import (
    PacketError,
    ReplayError,
)
from dataclasses import dataclass

from gateway.multi_client_registry import (
    MultiClientSessionManager,
    MultiClientError,
)
from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)

MAX_DATAGRAM = 4096


class MultiClientUDPError(Exception):
    """Rejected multi-client UDP operation."""


@dataclass
class UDPEntry:
    client_id: str
    transport: SecureSessionTransport
    peer: tuple | None = None


class MultiClientUDPEngine:
    """Encrypted UDP session state, scoped to individual clients."""

    def __init__(self, registry=None):
        self.registry = (
            registry
            if registry is not None
            else MultiClientSessionManager()
        )

        if not isinstance(self.registry, MultiClientSessionManager):
            raise TypeError("Invalid ownership registry")

        self._lock = threading.RLock()
        self._entries = {}

    def register_authenticated(self, client_id, session_id, keys):
        """Attach keys to an already authenticated TCP session.

        The caller MUST have obtained these keys from successful
        TCP authentication, not from an untrusted UDP packet.
        """
        if not isinstance(keys, SessionKeys):
            raise MultiClientUDPError("Invalid session keys")

        with self._lock:
            try:
                owner = self.registry.owner_of_session(session_id)
            except MultiClientError as exc:
                raise MultiClientUDPError(
                    "Unknown authenticated session"
                ) from exc

            if owner != client_id:
                raise MultiClientUDPError("Session ownership mismatch")

            if session_id in self._entries:
                raise MultiClientUDPError("Duplicate transport")

            transport = SecureSessionTransport(
                session_id,
                keys.server_to_client_key,
                keys.server_nonce_prefix,
                SERVER_TO_CLIENT,
                keys.client_to_server_key,
                keys.client_nonce_prefix,
                CLIENT_TO_SERVER,
            )

            self._entries[session_id] = UDPEntry(
                client_id=client_id,
                transport=transport,
            )

    def process(self, datagram, address):
        """Process authenticated PING and return encrypted PONG.

        A session's first successfully authenticated PING binds
        its UDP endpoint. Subsequent packets must use that endpoint.
        """
        if (
            not isinstance(datagram, bytes)
            or not 16 < len(datagram) <= MAX_DATAGRAM
        ):
            raise MultiClientUDPError("Invalid UDP datagram")

        if (
            not isinstance(address, tuple)
            or len(address) != 2
            or not isinstance(address[0], str)
            or not isinstance(address[1], int)
            or not 1 <= address[1] <= 65535
        ):
            raise MultiClientUDPError("Invalid UDP peer")

        session_id = datagram[:16]

        with self._lock:
            entry = self._entries.get(session_id)

            if entry is None:
                raise MultiClientUDPError("Unknown session")

            try:
                owner = self.registry.owner_of_session(session_id)
                active = self.registry.active_session(entry.client_id)
            except MultiClientError as exc:
                self._entries.pop(session_id, None)
                raise MultiClientUDPError(
                    "Expired or revoked session"
                ) from exc

            if owner != entry.client_id:
                raise MultiClientUDPError("Session ownership mismatch")

            if active != session_id:
                raise MultiClientUDPError("Staged session cannot send data")

            if entry.peer is not None and entry.peer != address:
                raise MultiClientUDPError("UDP endpoint mismatch")

            try:
                 plaintext = entry.transport.decrypt(datagram)
            except (PacketError, ReplayError, ValueError, TypeError) as exc:
                 raise MultiClientUDPError(
                     "UDP authentication failed"
                ) from exc

            if plaintext != b"PING":
                raise MultiClientUDPError("Unsupported UDP payload")

            if entry.peer is None:
                entry.peer = address

            return entry.transport.encrypt(b"PONG")

    def revoke_client(self, client_id):
        """Retire all control-plane and UDP state for one client."""
        with self._lock:
            try:
                removed = self.registry.revoke_client_sessions(client_id)
            except MultiClientError as exc:
                raise MultiClientUDPError("Unknown client") from exc

            for sid, entry in list(self._entries.items()):
                if entry.client_id == client_id:
                    del self._entries[sid]

            return removed

    def bound_peer(self, session_id):
        with self._lock:
            entry = self._entries.get(session_id)

            if entry is None:
                raise MultiClientUDPError("Unknown session")

            try:
                owner = self.registry.owner_of_session(session_id)
                active = self.registry.active_session(entry.client_id)
            except MultiClientError as exc:
                self._entries.pop(session_id, None)
                raise MultiClientUDPError("Inactive session") from exc

            if owner != entry.client_id or active != session_id:
                raise MultiClientUDPError("Inactive session")

            return entry.peer
