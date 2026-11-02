
"""PQVPN authenticated UDP gateway.

Supports encrypted UDP, authenticated session handover,
and optional bidirectional TUN forwarding.

Internet mode requires explicit enablement.
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
    enable_internet=False,
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
        # A staged session may send only an authenticated
        # activation request, never ordinary tunnel traffic.
        if sessions.is_staged_session(session_id):
            response = sessions.process_rekey_activation(
                session_id,
                datagram,
                address,
            )

            udp.send(address, TYPE_DATA, response)
            return True

        if not enable_ipv4_test:
            # Preserve legacy encrypted PING/PONG behavior.
            response = sessions.process_ping(
                session_id,
                datagram,
                address,
            )

            udp.send(address, TYPE_DATA, response)
            return True

        if tun is None:
            # IPv4 validation mode without TUN forwarding.
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
                enable_internet=enable_internet,
            )

            if category == "rekey_ack":
                # Already encrypted using active session keys.
                udp.send(address, TYPE_DATA, decoded)
                return True

            if category == "ping":
                # The manager validated the active session.
                # UDP processing is single-threaded here.
                response = sessions.get(
                    session_id
                ).transport.encrypt(b"PONG")

                udp.send(address, TYPE_DATA, response)
                return True

            if category != "ipv4":
                return False

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
        # Preserve existing fail-closed gateway behavior.
        return False


def serve_forever(
    sessions,
    host="127.0.0.1",
    port=51820,
    *,
    enable_ipv4_test=False,
    enable_tun=False,
    enable_internet=False,
):
    """Run encrypted UDP gateway with optional TUN forwarding."""
    if enable_tun and not enable_ipv4_test:
        raise ValueError("TUN requires IPv4 test mode")

    if enable_internet and not enable_tun:
        raise ValueError("Internet mode requires TUN")

    if enable_tun:
        from modules.networking.host.linux_tun import (
            LinuxTunAdapter,
        )

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
                    "TUN INTERNET MODE ENABLED"
                    if enable_internet
                    else
                    "TUN LAB MODE ENABLED - "
                    "ICMP to 10.77.0.1 only",
                    flush=True,
                )

            elif enable_ipv4_test:
                print(
                    "IPv4 TEST MODE ENABLED - no forwarding",
                    flush=True,
                )

            while True:
                if tun is not None:
                    packet = tun.read_packet(timeout=0)

                    if packet:
                        try:
                            peer, encrypted = (
                                sessions.encrypt_tunnel_reply(
                                    packet,
                                    enable_internet=enable_internet,
                                )
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

                try:
                    process_one(
                        udp,
                        sessions,
                        enable_ipv4_test=enable_ipv4_test,
                        tun=tun,
                        enable_internet=enable_internet,
                    )

                except TimeoutError:
                    continue

                except OSError:
                    continue
