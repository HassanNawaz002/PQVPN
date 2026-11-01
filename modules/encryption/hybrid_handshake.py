
"""PQVPN v1 authenticated hybrid handshake prototype.

Client authenticates gateway using a pinned ML-DSA-65 key.
Both peers confirm possession of directional session keys.

Local in-memory protocol; network serialization and client
authentication are not implemented yet.
"""

from dataclasses import dataclass
import hashlib
import hmac
import os

from modules.encryption.ecdh import (
    generate_keypair as x25519_keypair,
    derive_shared_secret,
)
from modules.encryption.pqc_kem import (
    generate_keypair as kem_keypair,
    encapsulate,
    decapsulate,
)
from modules.encryption.ml_dsa import (
    sign_message,
    verify_pinned_identity,
)
from modules.encryption.key_derivation import derive_session_keys

PROTOCOL = b"PQVPN-v1-MLKEM1024-X25519-MLDSA65"
MAX_HANDSHAKE_AGE_SECONDS = 30


class HandshakeError(Exception):
    pass


@dataclass(frozen=True)
class ClientHello:
    client_x25519_public: bytes
    kem_public: bytes
    client_nonce: bytes


@dataclass(frozen=True)
class ServerHello:
    server_x25519_public: bytes
    kem_ciphertext: bytes
    server_nonce: bytes
    identity_public: bytes
    signature: bytes
    server_confirmation: bytes


@dataclass
class ClientState:
    x25519_private: object
    kem_secret: bytes
    hello: ClientHello
    consumed: bool = False


@dataclass
class ServerState:
    keys: object
    transcript_hash: bytes
    consumed: bool = False


def _encode_fields(*fields):
    """Unambiguous length-prefixed transcript encoding."""
    output = bytearray(PROTOCOL)

    for field in fields:
        if not isinstance(field, bytes):
            raise HandshakeError("Handshake field must be bytes")
        if len(field) > 65535:
            raise HandshakeError("Handshake field too large")
        output.extend(len(field).to_bytes(2, "big"))
        output.extend(field)

    return bytes(output)


def _transcript(hello, server_public, ciphertext,
                server_nonce, identity_public):
    if len(hello.client_nonce) != 32:
        raise HandshakeError("Invalid client nonce")
    if len(server_nonce) != 32:
        raise HandshakeError("Invalid server nonce")

    return _encode_fields(
        hello.client_x25519_public,
        hello.kem_public,
        hello.client_nonce,
        server_public,
        ciphertext,
        server_nonce,
        identity_public,
    )


def _confirmation(key, label, transcript_hash):
    return hmac.new(
        key,
        PROTOCOL + b"|" + label + b"|" + transcript_hash,
        hashlib.sha384,
    ).digest()


def client_start():
    """Create a fresh client hello and ephemeral state."""
    private, public = x25519_keypair()
    kem_public, kem_secret = kem_keypair()

    hello = ClientHello(
        client_x25519_public=public,
        kem_public=kem_public,
        client_nonce=os.urandom(32),
    )

    return ClientState(private, kem_secret, hello), hello


def server_respond(hello, identity_public, identity_secret):
    """Produce authenticated server response and pending state."""
    if not isinstance(hello, ClientHello):
        raise HandshakeError("Invalid client hello")

    if len(hello.client_nonce) != 32:
        raise HandshakeError("Invalid client nonce")

    server_private, server_public = x25519_keypair()
    server_nonce = os.urandom(32)

    try:
        x_secret = derive_shared_secret(
            server_private,
            hello.client_x25519_public,
        )
        ciphertext, pq_secret = encapsulate(hello.kem_public)

        transcript = _transcript(
            hello,
            server_public,
            ciphertext,
            server_nonce,
            identity_public,
        )

        signature = sign_message(identity_secret, transcript)
        keys = derive_session_keys(
            x_secret, pq_secret, transcript
        )
    except (ValueError, TypeError, RuntimeError) as exc:
        raise HandshakeError("Invalid handshake input") from exc

    transcript_hash = hashlib.sha384(transcript).digest()

    proof = _confirmation(
        keys.server_to_client_key,
        b"server-finished",
        transcript_hash,
    )

    response = ServerHello(
        server_x25519_public=server_public,
        kem_ciphertext=ciphertext,
        server_nonce=server_nonce,
        identity_public=identity_public,
        signature=signature,
        server_confirmation=proof,
    )

    return ServerState(keys, transcript_hash), response


def client_finish(state, response, trusted_fingerprint):
    """Authenticate gateway, confirm keys, return client proof."""
    if not isinstance(state, ClientState) or state.consumed:
        raise HandshakeError("Invalid or consumed client state")

    state.consumed = True

    if not isinstance(response, ServerHello):
        raise HandshakeError("Invalid server response")

    transcript = _transcript(
        state.hello,
        response.server_x25519_public,
        response.kem_ciphertext,
        response.server_nonce,
        response.identity_public,
    )

    try:
        trusted = verify_pinned_identity(
            response.identity_public,
            trusted_fingerprint,
            transcript,
            response.signature,
        )
    except (ValueError, TypeError):
        trusted = False

    if not trusted:
        raise HandshakeError("Gateway authentication failed")

    try:
        x_secret = derive_shared_secret(
            state.x25519_private,
            response.server_x25519_public,
        )
        pq_secret = decapsulate(
            state.kem_secret,
            response.kem_ciphertext,
        )
        keys = derive_session_keys(
            x_secret, pq_secret, transcript
        )
    except (ValueError, TypeError, RuntimeError) as exc:
        raise HandshakeError("Key agreement failed") from exc

    transcript_hash = hashlib.sha384(transcript).digest()
    expected = _confirmation(
        keys.server_to_client_key,
        b"server-finished",
        transcript_hash,
    )

    if not hmac.compare_digest(
        expected, response.server_confirmation
    ):
        raise HandshakeError("Server key confirmation failed")

    client_proof = _confirmation(
        keys.client_to_server_key,
        b"client-finished",
        transcript_hash,
    )

    return keys, client_proof


def server_finish(state, client_proof):
    """Validate client possession of the derived session key."""
    if not isinstance(state, ServerState) or state.consumed:
        raise HandshakeError("Invalid or consumed server state")

    state.consumed = True

    if not isinstance(client_proof, bytes):
        raise HandshakeError("Invalid client confirmation")

    expected = _confirmation(
        state.keys.client_to_server_key,
        b"client-finished",
        state.transcript_hash,
    )

    if not hmac.compare_digest(expected, client_proof):
        raise HandshakeError("Client key confirmation failed")

    return state.keys


def establish_session():
    """Legacy entry point: reject unauthenticated session creation.

    Actual session establishment must use the authenticated
    client_start/server_respond/client_finish/server_finish flow.
    """
    from shared.errors import TunnelNotReady

    raise TunnelNotReady(
        "Direct session establishment is disabled. "
        "Authenticated hybrid handshake is required."
    )
