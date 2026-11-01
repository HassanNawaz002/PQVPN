"""PQVPN authenticated gateway handshake server.

Hybrid PQC handshake, ML-DSA authentication, PSK authorization,
encrypted UDP sessions and optional bidirectional TUN lab.

Experimental software. Not a production VPN.
"""

import argparse
import os
import socket
import threading
from pathlib import Path

from gateway.session_manager import SessionManager
from gateway.udp_gateway import serve_forever

from modules.encryption.hybrid_handshake import (
    server_respond,
    server_finish,
)
from modules.encryption.ml_dsa import public_key_fingerprint
from modules.networking.transport.handshake_framing import (
    decode_client_hello,
    decode_client_finished,
    encode_server_hello,
    receive_tcp_message,
    send_tcp_message,
)
from modules.networking.transport.session_authorization import (
    load_psk,
    read_exact,
    make_challenge,
    check_proof,
    make_accept,
    PROOF_SIZE,
)


HOST = "0.0.0.0"
DEFAULT_PORT = 51821
DEFAULT_UDP_PORT = 51820
TIMEOUT = 10


def load_identity():
    """Load persistent ML-DSA gateway identity keys."""
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


def handle_connection(
    connection,
    identity,
    sessions,
    psk,
):
    """Perform authenticated handshake and authorize a session."""
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

    keys = server_finish(
        state,
        client_proof,
    )

    challenge = make_challenge()
    connection.sendall(challenge)

    authorization_proof = read_exact(
        connection,
        PROOF_SIZE,
    )

    if not check_proof(
        psk,
        challenge,
        keys,
        authorization_proof,
    ):
        raise PermissionError(
            "Client PSK authorization failed"
        )

    session_id = sessions.create(
        keys,
        "server",
        authorized=True,
    )

    acceptance = make_accept(
        keys,
        session_id,
        challenge,
        authorization_proof,
    )

    try:
        connection.sendall(acceptance)
    except OSError:
        sessions.close(session_id)
        raise

    print(
        f"Authorized UDP session: {session_id.hex()}",
        flush=True,
    )


def main():
    """Start TCP handshake and encrypted UDP gateway services."""
    parser = argparse.ArgumentParser(
        description="PQVPN authenticated gateway server"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="TCP handshake listening port",
    )

    parser.add_argument(
        "--udp-host",
        default="127.0.0.1",
        help="UDP bind address",
    )

    parser.add_argument(
        "--udp-port",
        type=int,
        default=DEFAULT_UDP_PORT,
        help="Encrypted UDP listening port",
    )

    parser.add_argument(
        "--enable-ipv4-test",
        action="store_true",
        help="Enable controlled IPv4 delivery test",
    )

    parser.add_argument(
        "--enable-tun",
        action="store_true",
        help="Enable bidirectional TUN lab mode",
    )

    parser.add_argument(
        "--enable-internet",
        action="store_true",
        help="Enable controlled public IPv4 forwarding through TUN",
    )

    args = parser.parse_args()

    if args.enable_tun and not args.enable_ipv4_test:
        parser.error(
            "--enable-tun requires --enable-ipv4-test"
        )

    if args.enable_internet and not (
        args.enable_tun and args.enable_ipv4_test
    ):
        parser.error(
            "--enable-internet requires "
            "--enable-tun and --enable-ipv4-test"
        )

    if not 1 <= args.port <= 65535:
        parser.error("Invalid TCP port")

    if not 1 <= args.udp_port <= 65535:
        parser.error("Invalid UDP port")

    psk = load_psk()
    identity = load_identity()

    sessions = SessionManager()

    worker = threading.Thread(
        target=serve_forever,
        args=(
            sessions,
            args.udp_host,
            args.udp_port,
        ),
        kwargs={
            "enable_ipv4_test": args.enable_ipv4_test,
            "enable_tun": args.enable_tun,
            "enable_internet": args.enable_internet,
        },
        daemon=True,
        name="pqvpn-udp-gateway",
    )

    worker.start()

    print(
        "Gateway fingerprint:",
        public_key_fingerprint(identity[0]),
        flush=True,
    )

    print(
        "IPv4 delivery test:",
        "ENABLED" if args.enable_ipv4_test else "DISABLED",
        flush=True,
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
            f"PQVPN handshake listening on {HOST}:{args.port}",
            flush=True,
        )

        while True:
            connection, address = server.accept()

            with connection:
                try:
                    handle_connection(
                        connection,
                        identity,
                        sessions,
                        psk,
                    )
                except Exception as exc:
                    print(
                        "Handshake rejected:",
                        type(exc).__name__,
                        flush=True,
                    )


if __name__ == "__main__":
    main()