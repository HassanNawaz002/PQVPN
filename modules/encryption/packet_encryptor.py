
"""AES-256-GCM packet encryption with unique sequence nonces."""

import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from modules.encryption.cipher_suites import (
    VERSION,
    HEADER,
    MAX_SEQUENCE,
    MAX_PLAINTEXT,
    PacketError,
    SequenceExhausted,
    validate_key_material,
    validate_direction,
    make_nonce,
)


class PacketEncryptor:
    def __init__(self, key, nonce_prefix, direction):
        validate_key_material(key, nonce_prefix)
        validate_direction(direction)

        self._cipher = AESGCM(key)
        self._prefix = nonce_prefix
        self._direction = direction
        self._next_sequence = 0
        self._lock = threading.Lock()

    def encrypt(self, plaintext):
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")

        if len(plaintext) > MAX_PLAINTEXT:
            raise PacketError("Plaintext exceeds packet limit")

        with self._lock:
            if self._next_sequence > MAX_SEQUENCE:
                raise SequenceExhausted(
                    "Nonce space exhausted; rekey required"
                )

            sequence = self._next_sequence

            # Reserve before encryption; never reuse after failure.
            self._next_sequence += 1

            header = HEADER.pack(
                VERSION,
                self._direction,
                sequence,
            )

            nonce = make_nonce(self._prefix, sequence)

            ciphertext = self._cipher.encrypt(
                nonce,
                plaintext,
                header,
            )

            return header + ciphertext
