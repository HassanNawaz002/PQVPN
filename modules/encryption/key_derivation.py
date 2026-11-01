
"""PQVPN hybrid key derivation.

Combines X25519 and ML-KEM-1024 shared secrets using
HKDF-SHA-384 with transcript-bound domain separation.

This module does not authenticate peer identities.
"""

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_LABEL = b"PQVPN-v1-hybrid-MLKEM1024-X25519"
KEY_LENGTH = 32
NONCE_PREFIX_LENGTH = 4


@dataclass(frozen=True)
class SessionKeys:
    client_to_server_key: bytes
    server_to_client_key: bytes
    client_nonce_prefix: bytes
    server_nonce_prefix: bytes


def _require_secret(value, name):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must be 32 bytes")


def derive_session_keys(
    x25519_secret: bytes,
    mlkem_secret: bytes,
    transcript: bytes,
) -> SessionKeys:
    """Derive directional keys for a single handshake.

    Both peers must use the identical, canonical handshake
    transcript, in the same byte order.
    """
    _require_secret(x25519_secret, "x25519_secret")
    _require_secret(mlkem_secret, "mlkem_secret")

    if not isinstance(transcript, bytes) or not transcript:
        raise ValueError("transcript must be non-empty bytes")

    if len(transcript) > 1024 * 1024:
        raise ValueError("transcript exceeds maximum size")

    transcript_hash = hashlib.sha384(transcript).digest()

    # Length-prefix each input to avoid ambiguous encoding.
    ikm = (
        len(x25519_secret).to_bytes(2, "big")
        + x25519_secret
        + len(mlkem_secret).to_bytes(2, "big")
        + mlkem_secret
    )

    salt = hashlib.sha384(
        PROTOCOL_LABEL + b"|salt|" + transcript_hash
    ).digest()

    info = (
        PROTOCOL_LABEL
        + b"|session-keys|"
        + transcript_hash
    )

    # 2 directional keys + 2 nonce prefixes.
    output = HKDF(
        algorithm=hashes.SHA384(),
        length=(2 * KEY_LENGTH) + (2 * NONCE_PREFIX_LENGTH),
        salt=salt,
        info=info,
    ).derive(ikm)

    return SessionKeys(
        client_to_server_key=output[0:32],
        server_to_client_key=output[32:64],
        client_nonce_prefix=output[64:68],
        server_nonce_prefix=output[68:72],
    )


def keys_match(a: SessionKeys, b: SessionKeys) -> bool:
    """Constant-time comparison for testing key schedules."""
    return all(
        hmac.compare_digest(x, y)
        for x, y in (
            (a.client_to_server_key, b.client_to_server_key),
            (a.server_to_client_key, b.server_to_client_key),
            (a.client_nonce_prefix, b.client_nonce_prefix),
            (a.server_nonce_prefix, b.server_nonce_prefix),
        )
    )
