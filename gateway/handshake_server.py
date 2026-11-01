
"""PQVPN experimental authenticated handshake server.

Localhost-only listener. No VPN tunnel or client authorization.
"""

import argparse
import os
import socket
from pathlib import Path

from modules.encryption.hybrid_handshake import (
    server_respond,
    server_finish,
)
from modules.encryption.ml_dsa import (
    public_key_fingerprint,
)
from modules.networking.transport.handshake_framing import (
    decode_client_hello,
    decode_client_finished,
    encode_server_hello,
    receive_tcp_message,
    send_tcp_message,
)

HOST = "127.0.0.1"
DEFAULT_PORT = 51821
TIMEOUT = 10


def load_identity():
    directory = Path.home() / ".config" / "pqvpn"

    private_path = directory / "gateway-identity.key"
    public_path = directory / "gateway-identity.pub"

    if not private_path.is_file():
        raise RuntimeError("Gateway private key missing")

    if not public_path.is_file():
        raise RuntimeError("Gateway public key missing")

    if os.name != "nt":
        mode = private_path.stat().st_mode & 0o777
        if mode & 0o077:
            raise RuntimeError(
                "Private key permissions are too broad"
            )

    public = public_path.read_bytes()
    private = private_path.read_bytes()

    if len(public) != 1952 or len(private) != 4032:
        raise RuntimeError("Invalid identity key lengths")

    return public, private


def handle_connection(connection, identity):
    public, private = identity

    connection.settimeout(TIMEOUT)

    client_frame = receive_tcp_message(connection)
    client_hello = decode_client_hello(client_frame)

    state, server_hello = server_respond(
        client_hello,
        public,
        private,
    )

    send_tcp_message(
        connection,
        encode_server_hello(server_hello),
    )

    finished_frame = receive_tcp_message(connection)
    client_proof = decode_client_finished(finished_frame)

    server_finish(state, client_proof)

    print(
        "Authenticated hybrid handshake completed",
        flush=True,
    )

    # Deliberately do not create a persistent VPN session.
    # Client authorization and session lifecycle are pending.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")

    identity = load_identity()

    print(
        "Gateway fingerprint:",
        public_key_fingerprint(identity[0]),
    )

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server.bind((HOST, args.port))
        server.listen(5)

        print(
            f"PQVPN handshake listening on "
            f"{HOST}:{args.port}",
            flush=True,
        )

        while True:
            connection, address = server.accept()

            with connection:
                try:
                    handle_connection(connection, identity)
                except (
                    Exception
                ) as exc:
                    print(
                        "Handshake rejected:",
                        type(exc).__name__,
                        flush=True,
                    )


if __name__ == "__main__":
    main()
