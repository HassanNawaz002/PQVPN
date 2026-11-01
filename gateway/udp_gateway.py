
"""Encrypted UDP PING/PONG gateway.

Not a TUN VPN or public production service.
"""

from modules.networking.transport.packet_framing import (
    TYPE_DATA,
)

from modules.networking.transport.udp_transport import (
    UDPTransport,
)


MAX_TEST_PAYLOAD = 1200


def process_one(udp, sessions):
    kind, datagram, address = udp.receive()

    if kind != TYPE_DATA:
        return False

    if not 16 <= len(datagram) <= MAX_TEST_PAYLOAD:
        return False

    try:
        response = sessions.process_ping(
            datagram[:16],
            datagram,
            address,
        )

        udp.send(
            address,
            TYPE_DATA,
            response,
        )

        return True

    except Exception:
        # Invalid or unauthenticated packets are dropped.
        return False


def serve_forever(
    sessions,
    host="127.0.0.1",
    port=51820,
):
    with UDPTransport(
        host=host,
        port=port,
        timeout=2.0,
    ) as udp:

        print(
            f"Encrypted UDP listening on {udp.address}",
            flush=True,
        )

        while True:
            try:
                process_one(udp, sessions)

            except TimeoutError:
                continue

            except OSError:
                continue
