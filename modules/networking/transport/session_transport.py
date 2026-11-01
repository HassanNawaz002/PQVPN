
"""PQVPN authenticated encrypted session transport.

This module handles encrypted application payloads after
a successful authenticated hybrid handshake.

It does not perform a handshake, authenticate a client,
or create an operating-system VPN tunnel.
"""

import hmac

from modules.encryption.packet_encryptor import PacketEncryptor
from modules.decryption.aead_decryptor import PacketDecryptor


CLIENT_TO_SERVER = 1
SERVER_TO_CLIENT = 2

SESSION_ID_BYTES = 16
SESSION_CONTEXT = b"PQVPN-v1-session-data\x00"


class SessionTransportError(Exception):
    """Invalid encrypted session operation."""


class SecureSessionTransport:
    def __init__(
        self,
        session_id,
        send_key,
        send_nonce_prefix,
        send_direction,
        receive_key,
        receive_nonce_prefix,
        receive_direction,
    ):
        if not isinstance(session_id, bytes):
            raise SessionTransportError(
                "Session ID must be bytes"
            )

        if len(session_id) != SESSION_ID_BYTES:
            raise SessionTransportError(
                "Session ID must be 16 bytes"
            )

        if send_direction == receive_direction:
            raise SessionTransportError(
                "Send and receive directions must differ"
            )

        if {
            send_direction,
            receive_direction,
        } != {CLIENT_TO_SERVER, SERVER_TO_CLIENT}:
            raise SessionTransportError(
                "Invalid session directions"
            )

        self.session_id = session_id

        self._encryptor = PacketEncryptor(
            send_key,
            send_nonce_prefix,
            send_direction,
        )

        self._decryptor = PacketDecryptor(
            receive_key,
            receive_nonce_prefix,
            receive_direction,
        )

    def encrypt(self, payload):
        if not isinstance(payload, bytes):
            raise SessionTransportError(
                "Payload must be bytes"
            )

        # Bind the session identifier to the authenticated
        # encrypted plaintext, not just the outer UDP frame.
        plaintext = (
            SESSION_CONTEXT
            + self.session_id
            + payload
        )

        encrypted = self._encryptor.encrypt(
            plaintext
        )

        # Outer session ID permits receiver-side lookup.
        return self.session_id + encrypted

    def decrypt(self, datagram):
        if not isinstance(datagram, bytes):
            raise SessionTransportError(
                "Datagram must be bytes"
            )

        if len(datagram) <= SESSION_ID_BYTES:
            raise SessionTransportError(
                "Encrypted datagram too short"
            )

        received_id = datagram[:SESSION_ID_BYTES]

        if not hmac.compare_digest(
            received_id,
            self.session_id,
        ):
            raise SessionTransportError(
                "Unknown session ID"
            )

        encrypted = datagram[SESSION_ID_BYTES:]

        plaintext = self._decryptor.decrypt(
            encrypted
        )

        expected_prefix = (
            SESSION_CONTEXT + self.session_id
        )

        if not plaintext.startswith(expected_prefix):
            raise SessionTransportError(
                "Session authentication context mismatch"
            )

        return plaintext[len(expected_prefix):]
