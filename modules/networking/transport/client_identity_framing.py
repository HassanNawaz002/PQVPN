
"""PQVPN experimental multi-client identity preface.

Wire format:
    magic:      4 bytes
    version:    1 byte
    length:     1 byte
    client_id:  length bytes

This preface identifies a credential candidate. It does not
authenticate the client.

The gateway must verify an identity-bound PSK proof before
creating or authorizing any session.
"""

import struct

from modules.networking.transport.client_identity_auth import (
    validate_client_id,
    ClientIdentityAuthError,
)


MAGIC = b"PQID"
VERSION = 1
HEADER = struct.Struct("!4sBB")
MAX_ID_LENGTH = 64


class ClientIdentityFrameError(ValueError):
    """Malformed client identity preface."""


def encode_identity_preface(client_id):
    try:
        validate_client_id(client_id)
    except ClientIdentityAuthError as exc:
        raise ClientIdentityFrameError(
            "Invalid client identity"
        ) from exc

    identity = client_id.encode("ascii")

    if len(identity) > MAX_ID_LENGTH:
        raise ClientIdentityFrameError(
            "Client identity exceeds limit"
        )

    return (
        HEADER.pack(MAGIC, VERSION, len(identity))
        + identity
    )


def decode_identity_preface(frame):
    if not isinstance(frame, bytes):
        raise ClientIdentityFrameError(
            "Identity preface must be bytes"
        )

    if len(frame) < HEADER.size:
        raise ClientIdentityFrameError(
            "Truncated identity preface"
        )

    magic, version, length = HEADER.unpack_from(frame)

    if magic != MAGIC:
        raise ClientIdentityFrameError(
            "Invalid identity preface magic"
        )

    if version != VERSION:
        raise ClientIdentityFrameError(
            "Unsupported identity preface version"
        )

    if not 1 <= length <= MAX_ID_LENGTH:
        raise ClientIdentityFrameError(
            "Invalid client identity length"
        )

    if len(frame) != HEADER.size + length:
        raise ClientIdentityFrameError(
            "Identity preface length mismatch"
        )

    try:
        client_id = frame[HEADER.size:].decode("ascii")
        validate_client_id(client_id)
    except (UnicodeDecodeError, ClientIdentityAuthError) as exc:
        raise ClientIdentityFrameError(
            "Invalid client identity encoding"
        ) from exc

    return client_id


def _read_exact(sock, length):
    output = bytearray()

    while len(output) < length:
        chunk = sock.recv(length - len(output))

        if not chunk:
            raise ClientIdentityFrameError(
                "Connection closed during identity preface"
            )

        output.extend(chunk)

    return bytes(output)


def send_identity_preface(sock, client_id):
    frame = encode_identity_preface(client_id)
    sock.sendall(frame)


def receive_identity_preface(sock):
    header = _read_exact(sock, HEADER.size)

    magic, version, length = HEADER.unpack(header)

    if magic != MAGIC:
        raise ClientIdentityFrameError(
            "Invalid identity preface magic"
        )

    if version != VERSION:
        raise ClientIdentityFrameError(
            "Unsupported identity preface version"
        )

    if not 1 <= length <= MAX_ID_LENGTH:
        raise ClientIdentityFrameError(
            "Invalid client identity length"
        )

    identity = _read_exact(sock, length)

    return decode_identity_preface(
        header + identity
    )
