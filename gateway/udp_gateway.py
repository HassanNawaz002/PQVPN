
"""PQVPN authenticated UDP gateway.

Opt-in isolated bidirectional ICMP TUN lab.
No internet routing, NAT or DNS forwarding.
"""

import contextlib

from gateway.session_manager import SessionError
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.ip_payload import (
    HEADER_SIZE,
    MAX_IPV4_PACKET,
)


MAX_TEST_PAYLOAD = 1200
MAX_IP_DATAGRAM = MAX_IPV4_PACKET + HEADER_SIZE + 256


def process_one(
    udp,
    sessions,
    *,
    enable_ipv4_test=False,
    tun=None,
):
    """Process one authenticated UDP datagram."""
    kind, datagram, address = udp.receive()

    if kind != TYPE_DATA:
        return False

    limit = (
        MAX_IP_DATAGRAM
        if enable_ipv4_test
        else MAX_TEST_PAYLOAD
    )

    if not 16 < len(datagram) <= limit:
        return False

    session_id = datagram[:16]

    try:
        if not enable_ipv4_test:
            response = sessions.process_ping(
                session_id,
                datagram,
                address,
            )
            udp.send(address, TYPE_DATA, response)
            return True

        if tun is None:
            # Preserve accept-only IPv4 test behavior.
            decoded = sessions.process_ipv4(
                session_id,
                datagram,
                address,
            )
        else:
            category, decoded = sessions.process_tunnel_datagram(
                session_id,
                datagram,
                address,
            )

            if category == "ping":
                # Legacy PING receives no PONG in TUN lab mode.
                return True

            # Only authenticated and validated IPv4 is injected.
            tun.write_packet(decoded.packet)

        print(
            f"[IPv4 ACCEPTED] "
            f"{decoded.source} -> {decoded.destination} "
            f"protocol={decoded.protocol} "
            f"bytes={len(decoded.packet)}",
            flush=True,
        )
        return True

    except (SessionError, ValueError, TypeError, OSError):
        return False

    except Exception:
        # Fail closed for unexpected invalid traffic.
        return False


def serve_forever(
    sessions,
    host="127.0.0.1",
    port=51820,
    *,
    enable_ipv4_test=False,
    enable_tun=False,
):
    """Run the encrypted UDP gateway and optional TUN loop."""
    if enable_tun and not enable_ipv4_test:
        raise ValueError("TUN requires IPv4 test mode")

    if enable_tun:
        from modules.networking.host.linux_tun import LinuxTunAdapter
        tun_context = LinuxTunAdapter("pqvpn0")
    else:
        tun_context = contextlib.nullcontext(None)

    with tun_context as tun:
        with UDPTransport(
            host=host,
            port=port,
            timeout=0.1 if enable_tun else 2.0,
        ) as udp:

            print(
                f"Encrypted UDP listening on {udp.address}",
                flush=True,
            )

            if enable_tun:
                print(
                    "TUN LAB MODE ENABLED — "
                    "ICMP to 10.77.0.1 only",
                    flush=True,
                )
            elif enable_ipv4_test:
                print(
                    "IPv4 TEST MODE ENABLED — no forwarding",
                    flush=True,
                )

            while True:
                # Read real packets produced by AWS Linux kernel.
                if tun is not None:
                    packet = tun.read_packet(timeout=0)

                    if packet:
                        try:
                            peer, encrypted = (
                                sessions.encrypt_tunnel_reply(packet)
                            )
                            udp.send(
                                peer,
                                TYPE_DATA,
                                encrypted,
                            )
                            print(
                                "[TUN REPLY SENT]",
                                flush=True,
                            )
                        except (
                            SessionError,
                            ValueError,
                            TypeError,
                            OSError,
                        ):
                            pass

                # Receive authenticated client packets.
                try:
                    process_one(
                        udp,
                        sessions,
                        enable_ipv4_test=enable_ipv4_test,
                        tun=tun,
                    )
                except TimeoutError:
                    continue
                except OSError:
                    continue
