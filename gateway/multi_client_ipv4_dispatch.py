
"""PQVPN experimental multi-client IPv4 UDP dispatcher.

Authenticated encrypted UDP to injected TUN-like adapter.
Strict IPv4 validation before forwarding in both directions.

No internet routing, NAT or interface configuration.
"""

from gateway.multi_client_ipv4_udp import (
    MultiClientIPv4UDPEngine,
    MultiClientIPv4UDPError,
)
from gateway.multi_client_ipv4_router import (
    MultiClientRoutingError,
)
from modules.networking.host.ipv4_security import (
    validate_secure_ipv4,
    IPv4SecurityError,
)
from modules.networking.transport.packet_framing import TYPE_DATA


def process_inbound_ipv4(udp, engine, tun):
    """Receive, authenticate, validate and write one packet."""
    if not isinstance(engine, MultiClientIPv4UDPEngine):
        raise TypeError("Invalid IPv4 UDP engine")

    if tun is None or not callable(
        getattr(tun, "write_packet", None)
    ):
        raise TypeError("Invalid TUN adapter")

    try:
        message_type, datagram, address = udp.receive()

        if message_type != TYPE_DATA:
            return False

        route = engine.receive_ipv4(datagram, address)

        validate_secure_ipv4(route.packet)

        written = tun.write_packet(route.packet)

        return written == len(route.packet)

    except (
        MultiClientIPv4UDPError,
        MultiClientRoutingError,
        IPv4SecurityError,
        ValueError,
        TypeError,
        OSError,
    ):
        return False


def process_outbound_ipv4(udp, engine, tun):
    """Validate a TUN packet and encrypt for its owner."""
    if not isinstance(engine, MultiClientIPv4UDPEngine):
        raise TypeError("Invalid IPv4 UDP engine")

    if tun is None or not callable(
        getattr(tun, "read_packet", None)
    ):
        raise TypeError("Invalid TUN adapter")

    try:
        packet = tun.read_packet(timeout=0)

        if packet is None:
            return False

        validate_secure_ipv4(packet)

        peer, encrypted = engine.encrypt_ipv4_reply(packet)

        udp.send(peer, TYPE_DATA, encrypted)

        return True

    except (
        MultiClientIPv4UDPError,
        MultiClientRoutingError,
        IPv4SecurityError,
        ValueError,
        TypeError,
        OSError,
    ):
        return False
