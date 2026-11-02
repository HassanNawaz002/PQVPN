
"""PQVPN multi-client credential registry.

Stores independent client PSKs and authorization state.
Experimental in-memory registry; network authentication
must use challenge-response, never transmit raw PSKs.
"""

import hmac
import threading
from dataclasses import dataclass


PSK_SIZE = 32
MAX_CLIENTS = 253


class CredentialError(Exception):
    """Invalid client credential operation."""


@dataclass
class ClientCredential:
    client_id: str
    psk: bytes
    enabled: bool = True


class ClientCredentialRegistry:
    """Thread-safe in-memory client credential registry."""

    def __init__(self):
        self._lock = threading.RLock()
        self._clients = {}

    def add_client(self, client_id, psk):
        if (
            not isinstance(client_id, str)
            or not client_id
            or len(client_id) > 64
        ):
            raise CredentialError("Invalid client ID")

        if not isinstance(psk, bytes) or len(psk) != PSK_SIZE:
            raise CredentialError(
                "Client PSK must be exactly 32 bytes"
            )

        with self._lock:
            if client_id in self._clients:
                raise CredentialError(
                    "Client already registered"
                )

            if len(self._clients) >= MAX_CLIENTS:
                raise CredentialError(
                    "Client capacity reached"
                )

            self._clients[client_id] = ClientCredential(
                client_id=client_id,
                psk=psk,
            )

    def verify(self, client_id, candidate_psk):
        """Verify a locally supplied credential."""
        if (
            not isinstance(client_id, str)
            or not isinstance(candidate_psk, bytes)
            or len(candidate_psk) != PSK_SIZE
        ):
            return False

        with self._lock:
            record = self._clients.get(client_id)

            if record is None or not record.enabled:
                return False

            return hmac.compare_digest(
                record.psk,
                candidate_psk,
            )

    def revoke(self, client_id):
        with self._lock:
            record = self._clients.get(client_id)

            if record is None:
                raise CredentialError("Unknown client")

            record.enabled = False

    def is_enabled(self, client_id):
        with self._lock:
            record = self._clients.get(client_id)
            return record is not None and record.enabled

    def client_count(self):
        with self._lock:
            return len(self._clients)
