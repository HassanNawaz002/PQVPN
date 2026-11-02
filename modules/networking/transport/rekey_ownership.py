
"""PQVPN experimental rekey predecessor ownership proof.

This module provides cryptographic proof construction and
verification. It does not enforce challenge freshness or
session activation policy; those belong to the gateway.
"""

import hashlib
import hmac


REKEY_PROOF_LABEL = (
    b"PQVPN-v1-rekey-predecessor-ownership\x00"
)

SESSION_ID_SIZE = 16
CHALLENGE_SIZE = 32
KEY_SIZE = 32
PROOF_SIZE = hashlib.sha384().digest_size


class RekeyOwnershipError(ValueError):
    """Invalid rekey ownership proof inputs."""


def _validate_bytes(name, value, expected_length):
    if (
        not isinstance(value, bytes)
        or len(value) != expected_length
    ):
        raise RekeyOwnershipError(
            f"{name} must be {expected_length} bytes"
        )


def derive_ownership_key(
    old_client_to_server_key,
    old_server_to_client_key,
):
    """Derive a domain-separated proof key from session A."""
    _validate_bytes(
        "Old client-to-server key",
        old_client_to_server_key,
        KEY_SIZE,
    )
    _validate_bytes(
        "Old server-to-client key",
        old_server_to_client_key,
        KEY_SIZE,
    )

    return hmac.new(
        old_client_to_server_key,
        REKEY_PROOF_LABEL
        + b"ownership-key\x00"
        + old_server_to_client_key,
        hashlib.sha384,
    ).digest()


def _proof_message(
    old_session_id,
    new_session_id,
    challenge,
    new_client_to_server_key,
    new_server_to_client_key,
):
    _validate_bytes(
        "Old session ID",
        old_session_id,
        SESSION_ID_SIZE,
    )
    _validate_bytes(
        "New session ID",
        new_session_id,
        SESSION_ID_SIZE,
    )
    _validate_bytes(
        "Challenge",
        challenge,
        CHALLENGE_SIZE,
    )
    _validate_bytes(
        "New client-to-server key",
        new_client_to_server_key,
        KEY_SIZE,
    )
    _validate_bytes(
        "New server-to-client key",
        new_server_to_client_key,
        KEY_SIZE,
    )

    if old_session_id == new_session_id:
        raise RekeyOwnershipError(
            "Old and new sessions must differ"
        )

    new_key_binding = hashlib.sha384(
        REKEY_PROOF_LABEL
        + b"new-session-keys\x00"
        + new_client_to_server_key
        + new_server_to_client_key
    ).digest()

    return (
        REKEY_PROOF_LABEL
        + b"activate\x00"
        + old_session_id
        + new_session_id
        + challenge
        + new_key_binding
    )


def make_rekey_ownership_proof(
    old_session_id,
    new_session_id,
    challenge,
    old_client_to_server_key,
    old_server_to_client_key,
    new_client_to_server_key,
    new_server_to_client_key,
):
    """Create an HMAC-SHA384 predecessor ownership proof."""
    ownership_key = derive_ownership_key(
        old_client_to_server_key,
        old_server_to_client_key,
    )

    message = _proof_message(
        old_session_id,
        new_session_id,
        challenge,
        new_client_to_server_key,
        new_server_to_client_key,
    )

    return hmac.new(
        ownership_key,
        message,
        hashlib.sha384,
    ).digest()


def verify_rekey_ownership_proof(
    proof,
    old_session_id,
    new_session_id,
    challenge,
    old_client_to_server_key,
    old_server_to_client_key,
    new_client_to_server_key,
    new_server_to_client_key,
):
    """Verify proof with constant-time MAC comparison."""
    if not isinstance(proof, bytes) or len(proof) != PROOF_SIZE:
        return False

    expected = make_rekey_ownership_proof(
        old_session_id,
        new_session_id,
        challenge,
        old_client_to_server_key,
        old_server_to_client_key,
        new_client_to_server_key,
        new_server_to_client_key,
    )

    return hmac.compare_digest(proof, expected)
