
"""PQVPN v1 handshake serialization and TCP framing."""

import struct

from modules.encryption.hybrid_handshake import (
    ClientHello,
    ServerHello,
)

MAGIC = b"PQHS"
VERSION = 1

TYPE_CLIENT_HELLO = 1
TYPE_SERVER_HELLO = 2
TYPE_CLIENT_FINISHED = 3

MAX_MESSAGE = 16384
HEADER = struct.Struct("!4sBBI")
FIELD_LENGTH = struct.Struct("!H")


class HandshakeFrameError(Exception):
    pass


def _pack_fields(*fields):
    output = bytearray()

    for field in fields:
        if not isinstance(field, bytes):
            raise HandshakeFrameError(
                "Handshake field must be bytes"
            )

        if len(field) > 65535:
            raise HandshakeFrameError(
                "Handshake field too large"
            )

        output.extend(FIELD_LENGTH.pack(len(field)))
        output.extend(field)

    return bytes(output)


def _unpack_fields(data, expected_count):
    fields = []
    offset = 0

    for _ in range(expected_count):
        if offset + 2 > len(data):
            raise HandshakeFrameError(
                "Truncated field length"
            )

        size = FIELD_LENGTH.unpack_from(
            data, offset
        )[0]

        offset += 2

        if offset + size > len(data):
            raise HandshakeFrameError(
                "Truncated handshake field"
            )

        fields.append(data[offset:offset + size])
        offset += size

    if offset != len(data):
        raise HandshakeFrameError(
            "Unexpected trailing bytes"
        )

    return fields


def encode_message(message_type, payload):
    if message_type not in (
        TYPE_CLIENT_HELLO,
        TYPE_SERVER_HELLO,
        TYPE_CLIENT_FINISHED,
    ):
        raise HandshakeFrameError(
            "Invalid handshake message type"
        )

    if not isinstance(payload, bytes):
        raise HandshakeFrameError(
            "Payload must be bytes"
        )

    if len(payload) > MAX_MESSAGE:
        raise HandshakeFrameError(
            "Handshake message too large"
        )

    return (
        HEADER.pack(
            MAGIC,
            VERSION,
            message_type,
            len(payload),
        )
        + payload
    )


def decode_message(frame):
    if not isinstance(frame, bytes):
        raise HandshakeFrameError(
            "Frame must be bytes"
        )

    if len(frame) < HEADER.size:
        raise HandshakeFrameError(
            "Truncated frame"
        )

    magic, version, message_type, size = (
        HEADER.unpack_from(frame)
    )

    if magic != MAGIC:
        raise HandshakeFrameError(
            "Invalid handshake magic"
        )

    if version != VERSION:
        raise HandshakeFrameError(
            "Unsupported handshake version"
        )

    if message_type not in (
        TYPE_CLIENT_HELLO,
        TYPE_SERVER_HELLO,
        TYPE_CLIENT_FINISHED,
    ):
        raise HandshakeFrameError(
            "Invalid handshake message type"
        )

    if size > MAX_MESSAGE:
        raise HandshakeFrameError(
            "Handshake message exceeds limit"
        )

    if len(frame) != HEADER.size + size:
        raise HandshakeFrameError(
            "Handshake frame length mismatch"
        )

    return message_type, frame[HEADER.size:]


def encode_client_hello(hello):
    if not isinstance(hello, ClientHello):
        raise HandshakeFrameError(
            "Expected ClientHello"
        )

    return encode_message(
        TYPE_CLIENT_HELLO,
        _pack_fields(
            hello.client_x25519_public,
            hello.kem_public,
            hello.client_nonce,
        ),
    )


def decode_client_hello(frame):
    kind, payload = decode_message(frame)

    if kind != TYPE_CLIENT_HELLO:
        raise HandshakeFrameError(
            "Expected ClientHello frame"
        )

    public, kem_public, nonce = (
        _unpack_fields(payload, 3)
    )

    if (
        len(public) != 32
        or len(kem_public) != 1568
        or len(nonce) != 32
    ):
        raise HandshakeFrameError(
            "Invalid ClientHello field length"
        )

    return ClientHello(
        client_x25519_public=public,
        kem_public=kem_public,
        client_nonce=nonce,
    )


def encode_server_hello(hello):
    if not isinstance(hello, ServerHello):
        raise HandshakeFrameError(
            "Expected ServerHello"
        )

    return encode_message(
        TYPE_SERVER_HELLO,
        _pack_fields(
            hello.server_x25519_public,
            hello.kem_ciphertext,
            hello.server_nonce,
            hello.identity_public,
            hello.signature,
            hello.server_confirmation,
        ),
    )


def decode_server_hello(frame):
    kind, payload = decode_message(frame)

    if kind != TYPE_SERVER_HELLO:
        raise HandshakeFrameError(
            "Expected ServerHello frame"
        )

    fields = _unpack_fields(payload, 6)

    public, ciphertext, nonce, identity, signature, proof = (
        fields
    )

    if (
        len(public) != 32
        or len(ciphertext) != 1568
        or len(nonce) != 32
        or len(identity) != 1952
        or not 1 <= len(signature) <= 3309
        or len(proof) != 48
    ):
        raise HandshakeFrameError(
            "Invalid ServerHello field length"
        )

    return ServerHello(*fields)


def encode_client_finished(proof):
    if not isinstance(proof, bytes) or len(proof) != 48:
        raise HandshakeFrameError(
            "Invalid client confirmation"
        )

    return encode_message(
        TYPE_CLIENT_FINISHED,
        proof,
    )


def decode_client_finished(frame):
    kind, payload = decode_message(frame)

    if kind != TYPE_CLIENT_FINISHED or len(payload) != 48:
        raise HandshakeFrameError(
            "Invalid ClientFinished frame"
        )

    return payload


def recv_exact(sock, size):
    if not isinstance(size, int) or not 0 <= size <= MAX_MESSAGE + HEADER.size:
        raise HandshakeFrameError(
            "Invalid read size"
        )

    chunks = bytearray()

    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))

        if not chunk:
            raise HandshakeFrameError(
                "Connection closed during handshake"
            )

        chunks.extend(chunk)

    return bytes(chunks)


def receive_tcp_message(sock):
    header = recv_exact(sock, HEADER.size)

    magic, version, kind, size = HEADER.unpack(header)

    if (
        magic != MAGIC
        or version != VERSION
        or kind not in (
            TYPE_CLIENT_HELLO,
            TYPE_SERVER_HELLO,
            TYPE_CLIENT_FINISHED,
        )
        or size > MAX_MESSAGE
    ):
        raise HandshakeFrameError(
            "Invalid TCP handshake header"
        )

    payload = recv_exact(sock, size)

    return header + payload


def send_tcp_message(sock, frame):
    decode_message(frame)
    sock.sendall(frame)
