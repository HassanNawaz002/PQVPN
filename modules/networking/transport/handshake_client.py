
"""PQVPN experimental authenticated handshake client."""

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


def connect_gateway(host, port, fingerprint):
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(c not in "0123456789abcdefABCDEF"
               for c in fingerprint)
    ):
        raise ValueError("Invalid gateway fingerprint")

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

        server_frame = receive_tcp_message(connection)

        response = decode_server_hello(server_frame)

        keys, proof = client_finish(
            state,
            response,
            fingerprint,
        )

        send_tcp_message(
            connection,
            encode_client_finished(proof),
        )

        # The client has authenticated the gateway and
        # derived matching keys. No server acceptance ACK
        # or persistent session is implemented yet.
        return keys


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

    connect_gateway(
        args.host,
        args.port,
        args.fingerprint,
    )

    print(
        "Gateway signature and server key "
        "confirmation verified."
    )
    print(
        "ClientFinished sent. Server acceptance "
        "must be verified in gateway logs."
    )


if __name__ == "__main__":
    main()
