
"""PQVPN experimental PSK authorization over an authenticated hybrid handshake.

PSK must be a uniformly random 32-byte secret, represented as 64 hex chars.
Never send PSK over the network or commit it to source control.
"""

import hashlib
import hmac
import os
import secrets

LABEL = b"PQVPN-v1-PSK-session-authorization\x00"

CHALLENGE_SIZE = 32
PROOF_SIZE = 48
SESSION_ID_SIZE = 16
ACCEPT_SIZE = SESSION_ID_SIZE + PROOF_SIZE


def load_psk():
    raw = os.environ.get("PQVPN_CLIENT_PSK", "")

    if len(raw) != 64:
        raise ValueError(
            "PQVPN_CLIENT_PSK must contain exactly 64 hex characters"
        )

    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(
            "PQVPN_CLIENT_PSK must be hexadecimal"
        ) from exc

    if len(key) != 32:
        raise ValueError("Invalid PSK length")

    return key


def read_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        part = sock.recv(length - len(data))

        if not part:
            raise ConnectionError(
                "Connection closed during authorization"
            )

        data.extend(part)

    return bytes(data)


def make_challenge():
    return secrets.token_bytes(CHALLENGE_SIZE)


def make_proof(psk, challenge, keys):
    if len(psk) != 32 or len(challenge) != CHALLENGE_SIZE:
        raise ValueError("Invalid authorization inputs")

    return hmac.new(
        psk,
        LABEL
        + b"client"
        + challenge
        + keys.client_to_server_key
        + keys.server_to_client_key,
        hashlib.sha384,
    ).digest()


def check_proof(psk, challenge, keys, received):
    return (
        len(received) == PROOF_SIZE
        and hmac.compare_digest(
            make_proof(psk, challenge, keys),
            received,
        )
    )


def make_accept(keys, session_id, challenge, proof):
    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError("Invalid session ID")

    mac = hmac.new(
        keys.server_to_client_key,
        LABEL
        + b"accept"
        + session_id
        + challenge
        + proof,
        hashlib.sha384,
    ).digest()

    return session_id + mac


def check_accept(keys, payload, challenge, proof):
    if len(payload) != ACCEPT_SIZE:
        raise ValueError(
            "Invalid server acceptance length"
        )

    session_id = payload[:SESSION_ID_SIZE]

    expected = make_accept(
        keys,
        session_id,
        challenge,
        proof,
    )

    if not hmac.compare_digest(payload, expected):
        raise ValueError(
            "Server acceptance authentication failed"
        )

    return session_id
