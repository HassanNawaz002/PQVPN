
"""PQVPN client-side authenticated session rekey.

Experimental single-client implementation.
"""

import time
from dataclasses import dataclass

from modules.networking.transport.handshake_client import (
    connect_gateway,
)
from modules.networking.transport.session_control import (
    encode_rekey_activate,
    is_rekey_ack,
)
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.packet_framing import TYPE_DATA


REKEY_INTERVAL = 240
REKEY_ACK_TIMEOUT = 2.0
REKEY_MAX_ATTEMPTS = 3


class RekeyError(Exception):
    """Authenticated session renewal failed."""


@dataclass
class ClientSession:
    crypto: SecureSessionTransport
    session_id: bytes
    created_at: float


def make_client_session(keys, session_id):
    """Construct client-direction transport from handshake keys."""
    crypto = SecureSessionTransport(
        session_id,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
    )

    return ClientSession(
        crypto=crypto,
        session_id=session_id,
        created_at=time.monotonic(),
    )


def establish_session(host, port, fingerprint):
    keys, session_id = connect_gateway(
        host,
        port,
        fingerprint,
    )

    return make_client_session(keys, session_id)


def rekey_session(
    current,
    udp,
    destination,
    host,
    port,
    fingerprint,
    *,
    ack_timeout=REKEY_ACK_TIMEOUT,
    max_attempts=REKEY_MAX_ATTEMPTS,
):
    """Perform handshake, activate new session, verify ACK.

    Never replace the current crypto before authenticated ACK.
    """
    if max_attempts < 1 or ack_timeout <= 0:
        raise ValueError("Invalid rekey retry settings")

    try:
        staged = establish_session(
            host,
            port,
            fingerprint,
        )
    except Exception as exc:
        raise RekeyError(
            "Fresh authenticated handshake failed"
        ) from exc

    for attempt in range(1, max_attempts + 1):
        request = staged.crypto.encrypt(
            encode_rekey_activate()
        )

        try:
            udp.send(
                destination,
                TYPE_DATA,
                request,
            )

            deadline = time.monotonic() + ack_timeout

            while time.monotonic() < deadline:
                try:
                    kind, packet, peer = udp.receive()
                except TimeoutError:
                    continue

                if kind != TYPE_DATA or peer != destination:
                    continue

                # Ignore packets from old session.
                if packet[:16] != staged.session_id:
                    continue

                try:
                    plaintext = staged.crypto.decrypt(packet)
                except (ValueError, TypeError):
                    continue

                if is_rekey_ack(plaintext):
                    staged.created_at = time.monotonic()
                    return staged

        except (OSError, ValueError, TypeError) as exc:
            raise RekeyError(
                "UDP rekey transport failure"
            ) from exc

    raise RekeyError(
        "Authenticated REKEY_ACK not received"
    )
