
"""PQVPN classical X25519 key agreement module."""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def generate_keypair():
    """Generate an ephemeral X25519 keypair."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_bytes):
    """Derive the X25519 shared secret with a remote peer."""
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise TypeError("Expected X25519 private key")

    if not isinstance(peer_public_bytes, bytes):
        raise TypeError("Peer public key must be bytes")

    if len(peer_public_bytes) != 32:
        raise ValueError("Invalid X25519 public key length")

    peer_public_key = x25519.X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    secret = private_key.exchange(peer_public_key)

    if len(secret) != 32:
        raise ValueError("Unexpected shared secret length")

    return secret
