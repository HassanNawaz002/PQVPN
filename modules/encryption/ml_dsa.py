
"""PQVPN: ML-DSA-65 digital signature implementation."""

import hashlib
import hmac
import oqs

ALGORITHM = "ML-DSA-65"

PUBLIC_KEY_BYTES = 1952
SECRET_KEY_BYTES = 4032
SIGNATURE_MAX_BYTES = 3309

DOMAIN = b"PQVPN-v1-gateway-auth\x00"


class SignatureError(Exception):
    """ML-DSA signature operation failed."""


def generate_keypair():
    """Generate an ML-DSA-65 public/private keypair."""

    if ALGORITHM not in oqs.get_enabled_sig_mechanisms():
        raise SignatureError("ML-DSA-65 is unavailable")

    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    if len(public_key) != PUBLIC_KEY_BYTES:
        raise SignatureError("Unexpected public key length")

    if len(secret_key) != SECRET_KEY_BYTES:
        raise SignatureError("Unexpected secret key length")

    return public_key, secret_key


def sign_message(secret_key, message):
    """Sign a domain-separated handshake message."""

    if not isinstance(secret_key, bytes):
        raise SignatureError("Secret key must be bytes")

    if len(secret_key) != SECRET_KEY_BYTES:
        raise SignatureError("Invalid secret key length")

    if not isinstance(message, bytes):
        raise SignatureError("Message must be bytes")

    if not message or len(message) > 1024 * 1024:
        raise SignatureError("Invalid message length")

    with oqs.Signature(ALGORITHM, secret_key) as signer:
        signature = signer.sign(DOMAIN + message)

    if not 1 <= len(signature) <= SIGNATURE_MAX_BYTES:
        raise SignatureError("Invalid signature length")

    return signature


def verify_signature(public_key, message, signature):
    """Verify an ML-DSA-65 signature."""

    if not all(
        isinstance(value, bytes)
        for value in (public_key, message, signature)
    ):
        return False

    if len(public_key) != PUBLIC_KEY_BYTES:
        return False

    if not message or len(message) > 1024 * 1024:
        return False

    if not 1 <= len(signature) <= SIGNATURE_MAX_BYTES:
        return False

    try:
        with oqs.Signature(ALGORITHM) as verifier:
            return bool(
                verifier.verify(
                    DOMAIN + message,
                    signature,
                    public_key,
                )
            )
    except (ValueError, RuntimeError):
        return False


def public_key_fingerprint(public_key):
    """Generate SHA-256 fingerprint for gateway key pinning."""

    if not isinstance(public_key, bytes):
        raise SignatureError("Public key must be bytes")

    if len(public_key) != PUBLIC_KEY_BYTES:
        raise SignatureError("Invalid public key length")

    return hashlib.sha256(public_key).hexdigest()


def verify_pinned_identity(
    public_key,
    expected_fingerprint,
    message,
    signature,
):
    """Verify both trusted fingerprint and signature."""

    if not isinstance(expected_fingerprint, str):
        return False

    fingerprint = public_key_fingerprint(public_key)

    if not hmac.compare_digest(
        fingerprint,
        expected_fingerprint.lower(),
    ):
        return False

    return verify_signature(
        public_key,
        message,
        signature,
    )
