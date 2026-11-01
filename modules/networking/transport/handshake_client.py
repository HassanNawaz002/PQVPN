
"""PQVPN lab client: gateway-pinned hybrid handshake + PSK authorization."""

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


def connect_gateway(host, port, fingerprint):
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(
            c not in "0123456789abcdefABCDEF"
            for c in fingerprint
        )
    ):
        raise ValueError(
            "Invalid gateway fingerprint"
        )

    psk = load_psk()

    state, hello = client_start()

    with socket.create_connection(
        (host, port),
        timeout=10,
    ) as connection:

        connection.settimeout(10)

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

        keys, proof = client_finish(
            state,
            response,
            fingerprint,
        )

        send_tcp_message(
            connection,
            encode_client_finished(proof),
        )

        challenge = read_exact(
            connection,
            CHALLENGE_SIZE,
        )

        authorization_proof = make_proof(
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
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=51821,
    )

    parser.add_argument(
        "--fingerprint",
        required=True,
    )

    args = parser.parse_args()

    _keys, session_id = connect_gateway(
        args.host,
        args.port,
        args.fingerprint,
    )

    print(
        "Gateway authenticated; "
        "client PSK accepted; "
        "session confirmed."
    )

    print(
        "Session ID:",
        session_id.hex(),
    )


if __name__ == "__main__":
    main()
