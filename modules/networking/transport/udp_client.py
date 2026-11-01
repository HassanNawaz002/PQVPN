
"""PQVPN encrypted UDP PING/PONG client for controlled testing."""

import argparse
import socket

from modules.networking.transport.handshake_client import (
    connect_gateway,
)

from modules.networking.transport.packet_framing import (
    TYPE_DATA,
)

from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)

from modules.networking.transport.udp_transport import (
    UDPTransport,
)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="TCP handshake host",
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

    parser.add_argument(
        "--udp-host",
        default="127.0.0.1",
    )

    parser.add_argument(
        "--udp-port",
        type=int,
        default=51820,
    )

    args = parser.parse_args()

    keys, session_id = connect_gateway(
        args.host,
        args.port,
        args.fingerprint,
    )

    crypto = SecureSessionTransport(
        session_id,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
    )

    destination_ip = socket.gethostbyname(
        args.udp_host
    )

    destination = (
        destination_ip,
        args.udp_port,
    )

    with UDPTransport(
        host="0.0.0.0",
        port=0,
        timeout=5,
    ) as udp:

        encrypted_ping = crypto.encrypt(
            b"PING"
        )

        udp.send(
            destination,
            TYPE_DATA,
            encrypted_ping,
        )

        kind, response, address = udp.receive()

        if kind != TYPE_DATA:
            raise RuntimeError(
                "Unexpected UDP packet type"
            )

        if address != destination:
            raise RuntimeError(
                "Unexpected UDP reply source"
            )

        plaintext = crypto.decrypt(
            response
        )

        if plaintext != b"PONG":
            raise RuntimeError(
                "Invalid encrypted UDP response"
            )

    print(
        "SUCCESS: authenticated encrypted UDP PING/PONG"
    )

    print(
        "Session ID:",
        session_id.hex(),
    )


if __name__ == "__main__":
    main()
