
"""Local-only encrypted UDP test gateway."""

from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.packet_framing import TYPE_DATA
from gateway.session_manager import SessionError

MAX_TEST_PAYLOAD = 1200


def process_one(udp, sessions):
    kind, datagram, address = udp.receive()

    if kind != TYPE_DATA:
        return False

    if len(datagram) < 16 or len(datagram) > MAX_TEST_PAYLOAD:
        return False

    session_id = datagram[:16]

    try:
        entry = sessions.get(session_id)

        # Bind first valid sender endpoint. This is only
        # suitable for a controlled local test, not NAT roaming.
        if entry.peer is not None and entry.peer != address:
            return False

        plaintext = entry.transport.decrypt(datagram)

        if entry.peer is None:
            entry.peer = address

        if plaintext != b"PING":
            return False

        response = entry.transport.encrypt(b"PONG")

        udp.send(address, TYPE_DATA, response)
        return True

    except (SessionError, ValueError, TypeError):
        return False
    except Exception:
        # Malformed or unauthenticated packets are dropped.
        # Production implementation needs structured,
        # rate-limited error reporting.
        return False
