
"""PQVPN bidirectional Linux TUN client.

Opt-in public IPv4 forwarding with authenticated session rekey.

Does not modify default route, DNS or firewall.
"""

import argparse
import socket
import ipaddress
import subprocess
import time

from modules.networking.host.linux_tun import LinuxTunAdapter
from modules.networking.host.packet_reader import inspect_ipv4
from modules.networking.transport.client_rekey import (
    establish_session,
    rekey_session,
    RekeyError,
    REKEY_INTERVAL,
)
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
    decode_ipv4_payload,
    MAX_IPV4_PACKET,
)
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.udp_transport import UDPTransport


def configure_tun(name):
    """Bring up Linux TUN without modifying default routes."""
    for command in (
        ["ip", "addr", "replace", "10.77.0.2/24", "dev", name],
        ["ip", "link", "set", "dev", name, "mtu", "1200", "up"],
    ):
        subprocess.run(command, check=True)


def valid_ipv4(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return False

    ihl = (packet[0] & 15) * 4

    return (
        ihl >= 20
        and ihl <= len(packet)
        and int.from_bytes(packet[2:4], "big") == len(packet)
        and not (int.from_bytes(packet[6:8], "big") & 0x3FFF)
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=51821)
    parser.add_argument("--udp-host", required=True)
    parser.add_argument("--udp-port", type=int, default=51820)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--interface", default="pqvpn0")

    parser.add_argument(
        "--enable-internet",
        action="store_true",
        help="Permit public IPv4 traffic",
    )

    args = parser.parse_args()

    destination = (
        socket.gethostbyname(args.udp_host),
        args.udp_port,
    )

    session = establish_session(
        args.host,
        args.port,
        args.fingerprint,
    )

    print(
        "PQVPN authenticated session established",
        flush=True,
    )
    print("Opening Linux TUN:", args.interface, flush=True)

    with LinuxTunAdapter(args.interface) as tun:
        configure_tun(tun.name)

        print(
            "TUN configured: 10.77.0.2/24 MTU 1200 UP",
            flush=True,
        )

        with UDPTransport(
            host="0.0.0.0",
            port=0,
            timeout=0.05,
        ) as udp:

            print("TUN capture active", flush=True)
            print(
                f"Automatic rekey interval: {REKEY_INTERVAL}s",
                flush=True,
            )

            while True:
                # Rekey before gateway session expiry.
                if (
                    time.monotonic() - session.created_at
                    >= REKEY_INTERVAL
                ):
                    print(
                        "[REKEY] Starting authenticated renewal",
                        flush=True,
                    )

                    try:
                        session = rekey_session(
                            session,
                            udp,
                            destination,
                            args.host,
                            args.port,
                            args.fingerprint,
                        )

                    except RekeyError as exc:
                        print(
                            f"[REKEY FAILED] {exc}",
                            flush=True,
                        )
                        raise SystemExit(
                            "PQVPN stopped: session renewal failed"
                        )

                    print(
                        "[REKEY] New session activated",
                        flush=True,
                    )

                packet = tun.read_packet(timeout=0.05)

                # Receive encrypted server-to-client packets.
                try:
                    kind, datagram, peer = udp.receive()

                    if kind == TYPE_DATA and peer == destination:
                        plaintext = session.crypto.decrypt(
                            datagram
                        )

                        decoded = decode_ipv4_payload(plaintext)

                        permitted = (
                            valid_ipv4(decoded.packet)
                            and decoded.destination == "10.77.0.2"
                            and decoded.protocol in (1, 6, 17)
                            and (
                                (
                                    args.enable_internet
                                    and ipaddress.IPv4Address(
                                        decoded.source
                                    ).is_global
                                )
                                or (
                                    not args.enable_internet
                                    and decoded.source == "10.77.0.1"
                                    and decoded.protocol == 1
                                )
                            )
                        )

                        if permitted:
                            tun.write_packet(decoded.packet)

                            print(
                                "[RECEIVED] authenticated kernel reply",
                                flush=True,
                            )

                except TimeoutError:
                    pass

                except (ValueError, TypeError, OSError):
                    pass

                if packet is None:
                    continue

                if len(packet) > MAX_IPV4_PACKET:
                    continue

                try:
                    info = inspect_ipv4(packet)

                    if (
                        info.source != "10.77.0.2"
                        or not valid_ipv4(packet)
                    ):
                        continue

                    if args.enable_internet:
                        if (
                            not ipaddress.IPv4Address(
                                info.destination
                            ).is_global
                            or info.protocol not in (1, 6, 17)
                        ):
                            continue

                    elif (
                        info.destination != "10.77.0.1"
                        or info.protocol != 1
                    ):
                        continue

                    payload = encode_ipv4_payload(packet)

                    encrypted = session.crypto.encrypt(
                        payload
                    )

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
