
"""PQVPN bidirectional Linux TUN client.

Controlled single-client ICMP tunnel:
10.77.0.2 <-> 10.77.0.1

No default-route, DNS or firewall modifications.
"""

import argparse
import socket

from modules.networking.host.linux_tun import LinuxTunAdapter
from modules.networking.host.packet_reader import inspect_ipv4
from modules.networking.transport.handshake_client import (
    connect_gateway,
)
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
    decode_ipv4_payload,
    MAX_IPV4_PACKET,
)
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.udp_transport import UDPTransport


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=51821)
    parser.add_argument("--udp-host", required=True)
    parser.add_argument("--udp-port", type=int, default=51820)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--interface", default="pqvpn0")

    args = parser.parse_args()

    # Existing authenticated hybrid handshake.
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

    destination = (
        socket.gethostbyname(args.udp_host),
        args.udp_port,
    )

    print(
        "PQVPN authenticated session established",
        flush=True,
    )
    print("Opening Linux TUN:", args.interface, flush=True)

    with LinuxTunAdapter(args.interface) as tun:
        with UDPTransport(
            host="0.0.0.0",
            port=0,
            timeout=0.05,
        ) as udp:

            print("TUN capture active", flush=True)
            print(
                "Waiting for real IPv4 packets...",
                flush=True,
            )

            while True:
                # Read real kernel-generated outbound packets.
                packet = tun.read_packet(timeout=0.05)

                # Receive encrypted server-to-client packets
                # on the same UDP socket used for sending.
                try:
                    kind, datagram, peer = udp.receive()

                    if kind == TYPE_DATA and peer == destination:
                        plaintext = crypto.decrypt(datagram)
                        decoded = decode_ipv4_payload(plaintext)

                        if (
                            decoded.source,
                            decoded.destination,
                            decoded.protocol,
                        ) == (
                            "10.77.0.1",
                            "10.77.0.2",
                            1,
                        ):
                            tun.write_packet(decoded.packet)
                            print(
                                "[RECEIVED] authenticated kernel reply",
                                flush=True,
                            )

                except TimeoutError:
                    pass

                except (ValueError, TypeError, OSError):
                    # Reject malformed or unauthenticated traffic.
                    pass

                if packet is None:
                    continue

                if len(packet) > MAX_IPV4_PACKET:
                    continue

                try:
                    info = inspect_ipv4(packet)

                    # Restrict to isolated lab source.
                    if info.source != "10.77.0.2":
                        continue

                    # Restrict to AWS gateway destination.
                    if info.destination != "10.77.0.1":
                        continue

                    # ICMP-only lab mode.
                    if info.protocol != 1:
                        continue

                    payload = encode_ipv4_payload(packet)
                    encrypted = crypto.encrypt(payload)

                    udp.send(
                        destination,
                        TYPE_DATA,
                        encrypted,
                    )

                    print(
                        "[SENT] "
                        f"{info.source} -> {info.destination} "
                        f"protocol={info.protocol} "
                        f"bytes={len(packet)}",
                        flush=True,
                    )

                except (ValueError, TypeError):
                    continue


if __name__ == "__main__":
    main()
