
"""PQVPN authenticated UDP gateway.

Supports:
- Legacy encrypted PING/PONG
- Opt-in authenticated IPv4 packet delivery test
- Session validation and replay protection
- Single-client tunnel source validation

Does NOT implement TUN injection, NAT or forwarding.
"""

from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.ip_payload import (
    HEADER_SIZE as IP_HEADER_SIZE,
    MAX_IPV4_PACKET,
)


MAX_TEST_PAYLOAD = 1200

# Includes session ID, encryption overhead and IPv4 framing.
MAX_IP_DATAGRAM = MAX_IPV4_PACKET + IP_HEADER_SIZE + 256


def process_one(udp, sessions, *, enable_ipv4_test=False):
    """Process one encrypted UDP datagram."""

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

    if not enable_ipv4_test:
        try:
            response = sessions.process_ping(
                session_id,
                datagram,
                address,
            )

            udp.send(address, TYPE_DATA, response)
            return True

        except Exception:
            return False

    # Test mode: one authenticated decrypt per datagram.
    # Avoid decrypting the same datagram twice, because
    # replay protection would reject the second attempt.
    try:
        with sessions._lock:
            entry = sessions.get(session_id)

            if len(sessions._sessions) != 1:
                return False

            if (
                entry.peer is not None
                and entry.peer != address
            ):
                return False

            plaintext = entry.transport.decrypt(datagram)

            if plaintext == b"PING":
                if entry.peer is None:
                    entry.peer = address

                response = entry.transport.encrypt(b"PONG")
                udp.send(address, TYPE_DATA, response)
                return True

            from modules.networking.transport.ip_payload import (
                decode_ipv4_payload,
                validate_tunnel_source,
            )

            decoded = decode_ipv4_payload(plaintext)
            validate_tunnel_source(decoded, "10.77.0.2")

            if entry.peer is None:
                entry.peer = address

        print(
            "[IPv4 ACCEPTED] "
            f"{decoded.source} -> {decoded.destination} "
            f"protocol={decoded.protocol} "
            f"bytes={len(decoded.packet)}",
            flush=True,
        )

        return True

    except Exception:
        # Fail closed for invalid/unauthenticated traffic.
        return False


def serve_forever(
    sessions,
    host="127.0.0.1",
    port=51820,
    *,
    enable_ipv4_test=False,
):
    """Run the encrypted UDP gateway."""

    with UDPTransport(
        host=host,
        port=port,
        timeout=2.0,
    ) as udp:

        print(
            f"Encrypted UDP listening on {udp.address}",
            flush=True,
        )

        if enable_ipv4_test:
            print(
                "IPv4 TEST MODE ENABLED — no forwarding",
                flush=True,
            )

        while True:
            try:
                process_one(
                    udp,
                    sessions,
                    enable_ipv4_test=enable_ipv4_test,
                )

            except TimeoutError:
                continue

            except OSError:
                continue
