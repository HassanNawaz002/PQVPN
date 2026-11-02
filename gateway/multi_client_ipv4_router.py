
"""PQVPN experimental multi-client IPv4 routing policy.

Pure policy layer: no UDP socket, cryptography, TUN I/O,
routing table changes, NAT or internet forwarding.

Session ownership is resolved through the shared registry.
"""

import ipaddress
from dataclasses import dataclass

from gateway.multi_client_registry import (
    MultiClientSessionManager,
    MultiClientError,
)
from modules.networking.transport.ip_payload import (
    DecodedIPPayload,
    decode_ipv4_payload,
    encode_ipv4_payload,
    validate_tunnel_source,
    IPPayloadError,
)
from modules.networking.host.packet_reader import inspect_ipv4


GATEWAY_IP = "10.77.0.1"
TUNNEL_NETWORK = ipaddress.IPv4Network("10.77.0.0/24")


class MultiClientRoutingError(ValueError):
    """IPv4 routing policy rejected the packet."""


@dataclass(frozen=True)
class InboundRoute:
    client_id: str
    session_id: bytes
    packet: bytes
    source: str
    destination: str
    protocol: int


@dataclass(frozen=True)
class OutboundRoute:
    client_id: str
    session_id: bytes
    packet: bytes
    encrypted_payload: bytes
    source: str
    destination: str
    protocol: int


class MultiClientIPv4Router:
    """Validate inbound ownership and select outbound sessions."""

    def __init__(self, registry):
        if not isinstance(registry, MultiClientSessionManager):
            raise TypeError("Invalid multi-client registry")

        self.registry = registry

    def _active_owner(self, session_id):
        if not isinstance(session_id, bytes) or len(session_id) != 16:
            raise MultiClientRoutingError("Invalid session ID")

        try:
            client_id = self.registry.owner_of_session(session_id)
            active = self.registry.active_session(client_id)
        except MultiClientError as exc:
            raise MultiClientRoutingError(
                "Unknown, revoked or expired session"
            ) from exc

        if active != session_id:
            raise MultiClientRoutingError(
                "Inactive or staged session"
            )

        return client_id

    def accept_inbound(self, session_id, plaintext):
        """Validate decrypted IPv4 payload from an active client.

        This method must be called only after successful AEAD
        authentication by the UDP session transport.
        """
        client_id = self._active_owner(session_id)

        try:
            decoded = decode_ipv4_payload(plaintext)
            assigned_ip = self.registry.tunnel_ip_for_client(
                client_id
            )
            validate_tunnel_source(decoded, assigned_ip)
        except (IPPayloadError, MultiClientError) as exc:
            raise MultiClientRoutingError(
                "Invalid or spoofed client IPv4 packet"
            ) from exc

        destination = ipaddress.IPv4Address(
            decoded.destination
        )

        # Initial lab policy: only gateway-directed packets.
        # No client-to-client or internet forwarding yet.
        if destination != ipaddress.IPv4Address(GATEWAY_IP):
            raise MultiClientRoutingError(
                "Destination not permitted in lab mode"
            )

        return InboundRoute(
            client_id=client_id,
            session_id=session_id,
            packet=decoded.packet,
            source=decoded.source,
            destination=decoded.destination,
            protocol=decoded.protocol,
        )

    def select_outbound(self, packet):
        """Select active recipient for a validated TUN IPv4 packet.

        This method does not encrypt or send the packet.
        """
        try:
            info = inspect_ipv4(packet)
        except (ValueError, TypeError) as exc:
            raise MultiClientRoutingError(
                "Invalid outbound IPv4 packet"
            ) from exc

        if len(packet) > 1200:
            raise MultiClientRoutingError(
                "Outbound IPv4 packet exceeds tunnel MTU"
            )

        # Lab-only: return traffic must originate from gateway.
        if info.source != GATEWAY_IP:
            raise MultiClientRoutingError(
                "Outbound source is not the lab gateway"
            )

        destination = ipaddress.IPv4Address(
            info.destination
        )

        if destination not in TUNNEL_NETWORK:
            raise MultiClientRoutingError(
                "Destination outside tunnel network"
            )

        client_id = self.registry.client_for_ip(
            info.destination
        )

        if client_id is None:
            raise MultiClientRoutingError(
                "No client assigned to destination"
            )

        try:
            session_id = self.registry.active_session(
                client_id
            )

            if session_id is None:
                raise MultiClientRoutingError(
                    "Destination client has no active session"
                )

            if self.registry.owner_of_session(
                session_id
            ) != client_id:
                raise MultiClientRoutingError(
                    "Outbound session ownership mismatch"
                )

            framed = encode_ipv4_payload(packet)

        except (MultiClientError, IPPayloadError) as exc:
            raise MultiClientRoutingError(
                "Destination session unavailable"
            ) from exc

        return OutboundRoute(
            client_id=client_id,
            session_id=session_id,
            packet=packet,
            encrypted_payload=framed,
            source=info.source,
            destination=info.destination,
            protocol=info.protocol,
        )
