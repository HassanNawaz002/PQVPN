
"""PQVPN isolated multi-client encrypted UDP dispatcher.

Uses existing UDPTransport framing. No TUN forwarding.
"""

from gateway.multi_client_udp import (
    MultiClientUDPEngine,
    MultiClientUDPError,
)
from modules.networking.transport.packet_framing import TYPE_DATA


def process_one(udp, engine):
    """Process one framed UDP packet.

    Returns True only when an authenticated response was sent.
    Invalid frames and unauthorized packets fail closed.
    """
    if not isinstance(engine, MultiClientUDPEngine):
        raise TypeError("Invalid UDP engine")

    try:
        message_type, payload, address = udp.receive()

        if message_type != TYPE_DATA:
            return False

        response = engine.process(payload, address)
        udp.send(address, TYPE_DATA, response)

        return True

    except (
        MultiClientUDPError,
        ValueError,
        TypeError,
        OSError,
    ):
        return False
