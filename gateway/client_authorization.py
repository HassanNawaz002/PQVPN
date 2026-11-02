
"""PQVPN gateway multi-client authorization service.

Validates identity-bound PSK proofs before permitting
the caller to create an authenticated session.

This module does not create UDP sessions or forward traffic.
"""

from dataclasses import dataclass

from gateway.client_credentials import (
    ClientCredentialRegistry,
)

from modules.networking.transport.client_identity_auth import (
    validate_client_id,
    ClientIdentityAuthError,
)


class ClientAuthorizationError(PermissionError):
    """Client authorization failed."""


@dataclass(frozen=True)
class AuthorizedClient:
    client_id: str


class ClientAuthorizationService:
    """Gateway-side identity authorization boundary."""

    def __init__(self, credentials):
        if not isinstance(
            credentials,
            ClientCredentialRegistry,
        ):
            raise TypeError(
                "Expected ClientCredentialRegistry"
            )

        self._credentials = credentials

    def authorize(
        self,
        client_id,
        challenge,
        keys,
        received_proof,
    ):
        """Authorize a client using its identity-bound proof.

        Returns an immutable authorized identity on success.
        Never returns the client's PSK.
        """

        try:
            validate_client_id(client_id)
        except ClientIdentityAuthError as exc:
            raise ClientAuthorizationError(
                "Client authorization failed"
            ) from exc

        if not self._credentials.verify_proof(
            client_id,
            challenge,
            keys,
            received_proof,
        ):
            raise ClientAuthorizationError(
                "Client authorization failed"
            )

        return AuthorizedClient(client_id=client_id)
