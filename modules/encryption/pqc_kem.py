
"""PQVPN Module 1: ML-KEM-1024 key encapsulation.

Uses liboqs-python / liboqs.
Experimental integration; not a certification claim.
"""

import oqs

ALGORITHM = "ML-KEM-1024"

PUBLIC_KEY_BYTES = 1568
SECRET_KEY_BYTES = 3168
CIPHERTEXT_BYTES = 1568
SHARED_SECRET_BYTES = 32


class KEMError(Exception):
    """Invalid input or unavailable KEM implementation."""


def _require_bytes(value, expected_length, name):
    if not isinstance(value, bytes):
        raise KEMError(f"{name} must be bytes")
    if len(value) != expected_length:
        raise KEMError(
            f"{name} must be {expected_length} bytes"
        )


def _check_algorithm():
    if ALGORITHM not in oqs.get_enabled_kem_mechanisms():
        raise KEMError(f"{ALGORITHM} is not available")


def generate_keypair():
    """Return (public_key, secret_key) for one KEM exchange."""
    _check_algorithm()

    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    _require_bytes(
        public_key, PUBLIC_KEY_BYTES, "public_key"
    )
    _require_bytes(
        secret_key, SECRET_KEY_BYTES, "secret_key"
    )

    return public_key, secret_key


def encapsulate(public_key):
    """Return (ciphertext, shared_secret)."""
    _check_algorithm()
    _require_bytes(
        public_key, PUBLIC_KEY_BYTES, "public_key"
    )

    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(
            public_key
        )

    _require_bytes(
        ciphertext, CIPHERTEXT_BYTES, "ciphertext"
    )
    _require_bytes(
        shared_secret,
        SHARED_SECRET_BYTES,
        "shared_secret",
    )

    return ciphertext, shared_secret


def decapsulate(secret_key, ciphertext):
    """Recover the shared secret using the KEM secret key."""
    _check_algorithm()
    _require_bytes(
        secret_key, SECRET_KEY_BYTES, "secret_key"
    )
    _require_bytes(
        ciphertext, CIPHERTEXT_BYTES, "ciphertext"
    )

    with oqs.KeyEncapsulation(
        ALGORITHM, secret_key
    ) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    _require_bytes(
        shared_secret,
        SHARED_SECRET_BYTES,
        "shared_secret",
    )

    return shared_secret
