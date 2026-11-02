
"""PQVPN v1 multi-client identity-bound PSK authentication.

Experimental authentication primitive.

Client identity is bound to the challenge and independently
derived hybrid session keys using HMAC-SHA384.

The PSK must never be transmitted over the network.
"""

import hashlib
import hmac
import re


AUTH_LABEL = b"PQVPN-v1-client-identity-auth\x00"

CHALLENGE_SIZE = 32
PSK_SIZE = 32
PROOF_SIZE = 48

CLIENT_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
)


class ClientIdentityAuthError(ValueError):
    """Invalid identity authentication inputs."""


def validate_client_id(client_id):
    if (
        not isinstance(client_id, str)
        or CLIENT_ID_PATTERN.fullmatch(client_id) is None
    ):
        raise ClientIdentityAuthError(
            "Invalid client identity"
        )

    return client_id


def _validate_inputs(client_id, psk, challenge, keys):
    validate_client_id(client_id)

    if not isinstance(psk, bytes) or len(psk) != PSK_SIZE:
        raise ClientIdentityAuthError(
            "Client PSK must be 32 bytes"
        )

    if (
        not isinstance(challenge, bytes)
        or len(challenge) != CHALLENGE_SIZE
    ):
        raise ClientIdentityAuthError(
            "Invalid authentication challenge"
        )

    for name in (
        "client_to_server_key",
        "server_to_client_key",
    ):
        value = getattr(keys, name, None)

        if not isinstance(value, bytes) or len(value) != 32:
            raise ClientIdentityAuthError(
                f"Invalid {name}"
            )


def make_identity_proof(
    client_id,
    psk,
    challenge,
    keys,
):
    """Create identity-bound HMAC-SHA384 proof."""
    _validate_inputs(
        client_id,
        psk,
        challenge,
        keys,
    )

    identity = client_id.encode("ascii")

    message = (
        AUTH_LABEL
        + len(identity).to_bytes(2, "big")
        + identity
        + challenge
        + keys.client_to_server_key
        + keys.server_to_client_key
    )

    return hmac.new(
        psk,
        message,
        hashlib.sha384,
    ).digest()


def verify_identity_proof(
    client_id,
    psk,
    challenge,
    keys,
    received,
):
    """Verify identity-bound proof in constant time."""
    if (
        not isinstance(received, bytes)
        or len(received) != PROOF_SIZE
    ):
        return False

    try:
        expected = make_identity_proof(
            client_id,
            psk,
            challenge,
            keys,
        )
    except (ClientIdentityAuthError, TypeError):
        return False

    return hmac.compare_digest(
        received,
        expected,
    )
