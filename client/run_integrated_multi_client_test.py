
"""PQVPN experimental integrated multi-client test.

Performs:
1. Fresh authenticated hybrid PQC TCP handshake.
2. Identity-bound client PSK authorization.
3. Encrypted IPv4/ICMP traffic over UDP.
4. Validation of decrypted gateway ICMP replies.

Run inside the corresponding isolated network namespace.

Experimental FYP software; not a production VPN.
"""

import argparse
import os
import socket
import time
from pathlib import Path

from client.run_multi_client_test import (
    build_request,
    checksum,
)
from modules.networking.transport.handshake_client import (
    connect_gateway,
)
from modules.networking.transport.client_rekey import (
    make_client_session,
)
from modules.networking.transport.udp_transport import (
    UDPTransport,
)
from modules.networking.transport.packet_framing import (
    TYPE_DATA,
)
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
    decode_ipv4_payload,
)
from modules.networking.host.ipv4_security import (
    validate_secure_ipv4,
)


GATEWAY_IP = "172.30.77.1"
GATEWAY_TCP_PORT = 51831
GATEWAY_UDP_PORT = 51821

CLIENTS = {
    "a": {
        "id": "client-a",
        "tunnel": "10.77.0.2",
        "underlay": "172.30.77.2",
    },
    "b": {
        "id": "client-b",
        "tunnel": "10.77.0.3",
        "underlay": "172.30.77.6",
    },
}


def read_fingerprint(path):
    """Load the pinned gateway public-key fingerprint."""

    fingerprint = Path(path).read_text(
        encoding="ascii"
    ).strip()

    if (
        len(fingerprint) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in fingerprint
        )
    ):
        raise ValueError(
            "Invalid pinned gateway fingerprint"
        )

    return fingerprint


def verify_reply(reply, request, tunnel_ip):
    """Validate an authenticated IPv4 ICMP Echo Reply."""

    info = validate_secure_ipv4(reply)

    if (
        info.source != "10.77.0.1"
        or info.destination != tunnel_ip
        or info.protocol != 1
    ):
        raise RuntimeError(
            "Incorrect ICMP reply addressing or protocol"
        )

    icmp = reply[info.header_length:]

    if (
        len(icmp) < 8
        or icmp[0:2] != b"\x00\x00"
        or checksum(icmp) != 0
        or icmp[4:] != request[24:]
    ):
        raise RuntimeError(
            "Invalid ICMP Echo Reply"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PQVPN live authenticated multi-client test"
        )
    )

    parser.add_argument(
        "--client",
        choices=("a", "b"),
        required=True,
    )

    parser.add_argument(
        "--count",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--fingerprint-file",
        required=True,
    )

    args = parser.parse_args()

    if not 1 <= args.count <= 20:
        parser.error(
            "count must be between 1 and 20"
        )

    config = CLIENTS[args.client]

    client_id = config["id"]
    tunnel_ip = config["tunnel"]
    underlay_ip = config["underlay"]

    if not os.environ.get("PQVPN_CLIENT_PSK"):
        raise RuntimeError(
            "PQVPN_CLIENT_PSK is not configured"
        )

    fingerprint = read_fingerprint(
        args.fingerprint_file
    )

    print(
        f"[HANDSHAKE] {client_id}: connecting...",
        flush=True,
    )

    # Fresh authenticated, identity-bound PQC handshake.
    keys, session_id = connect_gateway(
        GATEWAY_IP,
        GATEWAY_TCP_PORT,
        fingerprint,
        client_id=client_id,
    )

    # IMPORTANT:
    # make_client_session() returns ClientSession.
    # The SecureSessionTransport is stored in .crypto.
    session = make_client_session(
        keys,
        session_id,
    )

    crypto = session.crypto

    print(
        f"[AUTHENTICATED] {client_id}: "
        "session established",
        flush=True,
    )

    gateway = (
        GATEWAY_IP,
        GATEWAY_UDP_PORT,
    )

    with UDPTransport(
        host=underlay_ip,
        port=0,
        timeout=5.0,
    ) as udp:

        print(
            f"[UDP] {client_id}: "
            f"{udp.address} -> {gateway}",
            flush=True,
        )

        for sequence in range(
            1,
            args.count + 1,
        ):
            request = build_request(
                tunnel_ip,
                sequence,
            )

            plaintext = encode_ipv4_payload(
                request
            )

            encrypted = crypto.encrypt(
                plaintext
            )

            udp.send(
                gateway,
                TYPE_DATA,
                encrypted,
            )

            try:
                kind, response, sender = (
                    udp.receive()
                )

            except socket.timeout as exc:
                raise RuntimeError(
                    f"{client_id}: UDP timeout "
                    f"on request {sequence}"
                ) from exc

            if (
                kind != TYPE_DATA
                or sender != gateway
            ):
                raise RuntimeError(
                    "Unexpected UDP response "
                    "type or sender"
                )

            decrypted = crypto.decrypt(
                response
            )

            reply = decode_ipv4_payload(
                decrypted
            ).packet

            verify_reply(
                reply,
                request,
                tunnel_ip,
            )

            print(
                f"[PASS] {client_id}: "
                f"encrypted round-trip "
                f"{sequence}/{args.count}",
                flush=True,
            )

            time.sleep(0.1)

    print(
        f"SUCCESS: {client_id} completed "
        f"{args.count} live encrypted "
        "round-trips",
        flush=True,
    )


if __name__ == "__main__":
    main()
