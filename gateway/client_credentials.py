
"""PQVPN multi-client credential registry.

Independent in-memory PSKs with revocation support.

Raw PSKs are never sent over the network. Network authorization
uses an identity-bound HMAC-SHA384 challenge-response proof.

Experimental implementation; not a production credential store.
"""

import hmac
import threading
from dataclasses import dataclass

from modules.networking.transport.client_identity_auth import (
    validate_client_id,
    verify_identity_proof,
    ClientIdentityAuthError,
)


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
    """Thread-safe in-memory credential registry."""

    def __init__(self):
        self._lock = threading.RLock()
        self._clients = {}

    def add_client(self, client_id, psk):
        try:
            validate_client_id(client_id)
        except ClientIdentityAuthError as exc:
            raise CredentialError(
                "Invalid client ID"
            ) from exc

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
        """Verify a locally supplied credential.

        Not intended as a network protocol operation.
        """
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

    def verify_proof(
        self,
        client_id,
        challenge,
        keys,
        received_proof,
    ):
        """Authorize an identity-bound network proof.

        The stored PSK remains internal to this registry.
        Unknown and revoked identities fail closed.
        """
        if not isinstance(client_id, str):
            return False

        with self._lock:
            record = self._clients.get(client_id)

            if record is None or not record.enabled:
                return False

            return verify_identity_proof(
                client_id,
                record.psk,
                challenge,
                keys,
                received_proof,
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
