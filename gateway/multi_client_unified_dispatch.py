
"""PQVPN authenticated multi-client UDP dispatcher.

Processes encrypted PING/PONG and IPv4 traffic.

Optional diagnostic logging is enabled with:
    PQVPN_DEBUG=1

Security:
- Rejected packets remain rejected.
- No plaintext packet contents or secret keys are logged.
- Existing authentication and routing logic is unchanged.
"""

import logging
import os

from gateway.multi_client_ipv4_udp import (
    MultiClientIPv4UDPEngine,
    MultiClientIPv4UDPError,
)
from gateway.multi_client_ipv4_router import (
    MultiClientRoutingError,
)
from modules.networking.host.ipv4_security import (
    IPv4SecurityError,
)
from modules.networking.transport.packet_framing import (
    TYPE_DATA,
)


logger = logging.getLogger("pqvpn.gateway.dispatch")


def _debug_enabled():
    return os.environ.get("PQVPN_DEBUG", "0") == "1"


def _diagnostic(message):
    if _debug_enabled():
        print(
            f"[PQVPN DEBUG] {message}",
            flush=True,
        )


def process_one(udp, engine, tun):
    """Process one authenticated UDP frame.

    Returns:
        "ping" on authenticated PONG
        "ipv4" on successful IPv4 TUN injection
        None on rejected/unsupported packets

    Network receive timeouts propagate to the caller.
    """

    if not isinstance(engine, MultiClientIPv4UDPEngine):
        raise TypeError("Invalid multi-client IPv4 engine")

    if tun is None or not callable(
        getattr(tun, "write_packet", None)
    ):
        raise TypeError("Invalid TUN adapter")

    try:
        kind, datagram, address = udp.receive()

        if kind != TYPE_DATA:
            _diagnostic("Unsupported UDP frame type")
            return None

        _diagnostic(
            f"Received DATA frame ({len(datagram)} bytes)"
        )

        result_type, result = engine.process_authenticated(
            datagram,
            address,
        )

        _diagnostic(
            f"Authenticated result: {result_type}"
        )

        if result_type == "ping":
            udp.send(address, TYPE_DATA, result)
            return "ping"

        if result_type == "ipv4":
            written = tun.write_packet(result.packet)

            if written != len(result.packet):
                _diagnostic(
                    "TUN write returned incomplete length"
                )
                return None

            _diagnostic(
                f"IPv4 packet injected into TUN "
                f"({written} bytes)"
            )

            return "ipv4"

        _diagnostic("Unsupported authenticated result")
        return None

    except (
        MultiClientIPv4UDPError,
        MultiClientRoutingError,
        IPv4SecurityError,
        ValueError,
        TypeError,
        OSError,
    ) as exc:
        _diagnostic(
            f"Packet rejected: {type(exc).__name__}"
        )
        logger.debug(
            "Rejected UDP packet",
            exc_info=True,
        )
        return None
