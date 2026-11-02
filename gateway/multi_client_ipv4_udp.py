
"""Experimental authenticated multi-client IPv4 UDP engine.

Extends the tested PING/PONG engine without changing its behavior.
No TUN writes or internet forwarding are performed here.
"""

from gateway.multi_client_udp import (
    MultiClientUDPEngine,
    MultiClientUDPError,
    MAX_DATAGRAM,
)
from gateway.multi_client_ipv4_router import (
    MultiClientIPv4Router,
    MultiClientRoutingError,
)
from gateway.multi_client_registry import MultiClientError
from modules.encryption.cipher_suites import PacketError, ReplayError
from modules.networking.transport.ip_payload import (
    encode_ipv4_payload,
    IPPayloadError,
)


class MultiClientIPv4UDPError(MultiClientUDPError):
    """Authenticated IPv4 transport operation rejected."""


class MultiClientIPv4UDPEngine(MultiClientUDPEngine):

    def __init__(self, registry=None):
        super().__init__(registry)
        self.router = MultiClientIPv4Router(self.registry)

    def receive_ipv4(self, datagram, address):
        """Decrypt and validate an inbound IPv4 tunnel packet.

        Returns an InboundRoute; caller may subsequently write
        route.packet to an explicitly configured lab TUN.
        """
        if (
            not isinstance(datagram, bytes)
            or not 16 < len(datagram) <= MAX_DATAGRAM
        ):
            raise MultiClientIPv4UDPError("Invalid datagram")

        if (
            not isinstance(address, tuple)
            or len(address) != 2
            or not isinstance(address[0], str)
            or not isinstance(address[1], int)
            or not 1 <= address[1] <= 65535
        ):
            raise MultiClientIPv4UDPError("Invalid peer")

        sid = datagram[:16]

        with self._lock:
            entry = self._entries.get(sid)

            if entry is None:
                raise MultiClientIPv4UDPError("Unknown session")

            try:
                owner = self.registry.owner_of_session(sid)
                active = self.registry.active_session(entry.client_id)
            except MultiClientError as exc:
                self._entries.pop(sid, None)
                raise MultiClientIPv4UDPError(
                    "Expired or revoked session"
                ) from exc

            if owner != entry.client_id or active != sid:
                raise MultiClientIPv4UDPError("Inactive session")

            if entry.peer is not None and entry.peer != address:
                raise MultiClientIPv4UDPError("Endpoint mismatch")

            try:
                plaintext = entry.transport.decrypt(datagram)
            except (PacketError, ReplayError, ValueError, TypeError) as exc:
                raise MultiClientIPv4UDPError(
                    "Packet authentication failed"
                ) from exc

            try:
                route = self.router.accept_inbound(sid, plaintext)
            except MultiClientRoutingError as exc:
                raise MultiClientIPv4UDPError(
                    "IPv4 policy rejected packet"
                ) from exc

            # Bind only after AEAD and IPv4 policy succeed.
            if entry.peer is None:
                entry.peer = address

            return route

    def encrypt_ipv4_reply(self, packet):
        """Select recipient and encrypt a gateway-origin IPv4 reply.

        Returns (peer_address, encrypted_datagram).
        Does not send a packet.
        """
        with self._lock:
            try:
                route = self.router.select_outbound(packet)
            except MultiClientRoutingError as exc:
                raise MultiClientIPv4UDPError(
                    "Outbound IPv4 policy rejected packet"
                ) from exc

            entry = self._entries.get(route.session_id)

            if entry is None or entry.client_id != route.client_id:
                raise MultiClientIPv4UDPError(
                    "Recipient transport unavailable"
                )

            if entry.peer is None:
                raise MultiClientIPv4UDPError(
                    "Recipient endpoint not authenticated"
                )

            try:
                # Recheck ownership before encryption.
                owner = self.registry.owner_of_session(route.session_id)
                active = self.registry.active_session(route.client_id)

                if owner != route.client_id or active != route.session_id:
                    raise MultiClientIPv4UDPError(
                        "Recipient session inactive"
                    )

                framed = encode_ipv4_payload(packet)
            except (MultiClientError, IPPayloadError) as exc:
                raise MultiClientIPv4UDPError(
                    "Recipient unavailable"
                ) from exc

            return entry.peer, entry.transport.encrypt(framed)
