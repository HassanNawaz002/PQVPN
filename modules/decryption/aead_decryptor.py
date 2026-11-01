
"""Authenticated AES-GCM decryption and replay protection."""

import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from modules.encryption.cipher_suites import (
    VERSION,
    HEADER,
    HEADER_SIZE,
    TAG_SIZE,
    MAX_PLAINTEXT,
    PacketError,
    ReplayError,
    validate_key_material,
    validate_direction,
    make_nonce,
)
from modules.decryption.replay_protection import ReplayWindow


class PacketDecryptor:
    def __init__(
        self,
        key,
        nonce_prefix,
        expected_direction,
        window_size=1024,
    ):
        validate_key_material(key, nonce_prefix)
        validate_direction(expected_direction)

        self._cipher = AESGCM(key)
        self._prefix = nonce_prefix
        self._direction = expected_direction
        self._replay = ReplayWindow(window_size)
        self._lock = threading.Lock()

    def decrypt(self, packet):
        if not isinstance(packet, bytes):
            raise PacketError("Packet must be bytes")

        if not (
            HEADER_SIZE + TAG_SIZE
            <= len(packet)
            <= HEADER_SIZE + MAX_PLAINTEXT + TAG_SIZE
        ):
            raise PacketError("Invalid packet length")

        header = packet[:HEADER_SIZE]
        ciphertext = packet[HEADER_SIZE:]

        version, direction, sequence = HEADER.unpack(header)

        if version != VERSION:
            raise PacketError("Unsupported packet version")

        if direction != self._direction:
            raise PacketError("Wrong packet direction")

        nonce = make_nonce(self._prefix, sequence)

        # Atomic replay check, authentication and commit.
        with self._lock:
            if not self._replay.can_accept(sequence):
                raise ReplayError("Duplicate or stale packet")

            try:
                plaintext = self._cipher.decrypt(
                    nonce,
                    ciphertext,
                    header,
                )
            except InvalidTag as exc:
                raise PacketError(
                    "Packet authentication failed"
                ) from exc

            if not self._replay.mark_authenticated(sequence):
                raise ReplayError("Replay detected")

            return plaintext
