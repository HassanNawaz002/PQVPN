
"""PQVPN lab client: pinned hybrid handshake and PSK authorization.

Supports:
- Legacy single-client PSK handshake (existing lab mode).
- Experimental identity-bound multi-client handshake.

Multi-client mode requires a matching gateway implementation.
Do not use this experimental protocol as a production VPN.
"""

import argparse
import socket

from modules.encryption.hybrid_handshake import (
    client_start,
    client_finish,
)

from modules.networking.transport.handshake_framing import (
    encode_client_hello,
    decode_server_hello,
    encode_client_finished,
    receive_tcp_message,
    send_tcp_message,
)

from modules.networking.transport.session_authorization import (
    load_psk,
    read_exact,
    make_proof,
    check_accept,
    CHALLENGE_SIZE,
    ACCEPT_SIZE,
)

from modules.networking.transport.client_identity_auth import (
    make_identity_proof,
    validate_client_id,
)

from modules.networking.transport.client_identity_framing import (
    send_identity_preface,
)


DEFAULT_PORT = 51821
CONNECTION_TIMEOUT = 10


def validate_fingerprint(fingerprint):
    """Validate the pinned gateway public-key fingerprint."""
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in fingerprint
        )
    ):
        raise ValueError("Invalid gateway fingerprint")

    return fingerprint


def connect_gateway(
    host,
    port,
    fingerprint,
    *,
    client_id=None,
):
    """Establish an authenticated PQVPN session.

    When client_id is None, use the existing legacy protocol.

    When client_id is supplied:
      1. Send identity preface.
      2. Perform the existing authenticated hybrid handshake.
      3. Create an identity-bound PSK authorization proof.
      4. Verify the gateway's authenticated acceptance.

    The gateway must implement the matching multi-client mode.
    """

    validate_fingerprint(fingerprint)

    if client_id is not None:
        validate_client_id(client_id)

    # Never transmit the raw PSK.
    psk = load_psk()

    state, hello = client_start()

    with socket.create_connection(
        (host, port),
        timeout=CONNECTION_TIMEOUT,
    ) as connection:

        connection.settimeout(CONNECTION_TIMEOUT)

        # Explicit protocol selection before the hybrid handshake.
        # Legacy clients omit this preface.
        if client_id is not None:
            send_identity_preface(
                connection,
                client_id,
            )

        send_tcp_message(
            connection,
            encode_client_hello(hello),
        )

        server_frame = receive_tcp_message(
            connection
        )

        response = decode_server_hello(
            server_frame
        )

        keys, handshake_proof = client_finish(
            state,
            response,
            fingerprint,
        )

        send_tcp_message(
            connection,
            encode_client_finished(handshake_proof),
        )

        challenge = read_exact(
            connection,
            CHALLENGE_SIZE,
        )

        if client_id is None:
            authorization_proof = make_proof(
                psk,
                challenge,
                keys,
            )
        else:
            authorization_proof = make_identity_proof(
                client_id,
                psk,
                challenge,
                keys,
            )

        connection.sendall(
            authorization_proof
        )

        acceptance = read_exact(
            connection,
            ACCEPT_SIZE,
        )

        session_id = check_accept(
            keys,
            acceptance,
            challenge,
            authorization_proof,
        )

        return keys, session_id


def main():
    parser = argparse.ArgumentParser(
        description="PQVPN authenticated handshake client"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
    )

    parser.add_argument(
        "--fingerprint",
        required=True,
    )

    parser.add_argument(
        "--client-id",
        default=None,
        help=(
            "Enable experimental identity-bound "
            "multi-client authentication"
        ),
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Invalid TCP port")

    _keys, session_id = connect_gateway(
        args.host,
        args.port,
        args.fingerprint,
        client_id=args.client_id,
    )

    print(
        "Gateway authenticated; "
        "client PSK accepted; "
        "session confirmed."
    )

    if args.client_id is not None:
        print(
            "Authenticated client identity:",
            args.client_id,
        )

    print(
        "Session ID:",
        session_id.hex(),
    )


if __name__ == "__main__":
    main()
