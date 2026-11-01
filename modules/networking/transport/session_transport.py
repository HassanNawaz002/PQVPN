
"""PQVPN authenticated encrypted session transport.

Provides session-bound AES-256-GCM packet encryption and
decryption using existing directional crypto modules.

Security properties:
- Authenticated session binding
- Directional encryption/decryption
- Replay protection through PacketDecryptor
- Session ID validation
"""

import hmac

from modules.encryption.packet_encryptor import (
    PacketEncryptor,
)

from modules.decryption.aead_decryptor import (
    PacketDecryptor,
)


CLIENT_TO_SERVER = 1
SERVER_TO_CLIENT = 2

SESSION_ID_BYTES = 16
SESSION_CONTEXT = b"PQVPN-v1-session-data\x00"


class SessionTransportError(ValueError):
    """Invalid session parameters or session-bound packet."""


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
        if (
            not isinstance(session_id, bytes)
            or len(session_id) != SESSION_ID_BYTES
        ):
            raise SessionTransportError(
                "Session ID must be exactly 16 bytes"
            )

        valid_directions = {
            CLIENT_TO_SERVER,
            SERVER_TO_CLIENT,
        }

        if (
            send_direction not in valid_directions
            or receive_direction not in valid_directions
            or send_direction == receive_direction
        ):
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
            raise TypeError(
                "Payload must be bytes"
            )

        plaintext = (
            SESSION_CONTEXT
            + self.session_id
            + payload
        )

        encrypted = self._encryptor.encrypt(
            plaintext
        )

        return self.session_id + encrypted

    def decrypt(self, datagram):
        if not isinstance(datagram, bytes):
            raise TypeError(
                "Datagram must be bytes"
            )

        if len(datagram) <= SESSION_ID_BYTES:
            raise SessionTransportError(
                "Truncated session packet"
            )

        received_id = datagram[:SESSION_ID_BYTES]

        if not hmac.compare_digest(
            received_id,
            self.session_id,
        ):
            raise SessionTransportError(
                "Session ID mismatch"
            )

        encrypted = datagram[SESSION_ID_BYTES:]

        plaintext = self._decryptor.decrypt(
            encrypted
        )

        expected_prefix = (
            SESSION_CONTEXT
            + self.session_id
        )

        if not plaintext.startswith(
            expected_prefix
        ):
            raise SessionTransportError(
                "Invalid authenticated session context"
            )

        return plaintext[len(expected_prefix):]
