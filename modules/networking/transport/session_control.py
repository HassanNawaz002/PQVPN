
"""Authenticated PQVPN session control payloads.

These messages must only be transported inside
SecureSessionTransport encrypted packets.
"""

import hmac

CONTROL_PREFIX = b"PQVPN-v1-control\x00"

REKEY_ACTIVATE = CONTROL_PREFIX + b"REKEY_ACTIVATE"
REKEY_ACK = CONTROL_PREFIX + b"REKEY_ACK"


class SessionControlError(ValueError):
    """Invalid authenticated session control payload."""


def encode_rekey_activate():
    return REKEY_ACTIVATE


def encode_rekey_ack():
    return REKEY_ACK


def is_rekey_activate(payload):
    return (
        isinstance(payload, bytes)
        and hmac.compare_digest(payload, REKEY_ACTIVATE)
    )


def is_rekey_ack(payload):
    return (
        isinstance(payload, bytes)
        and hmac.compare_digest(payload, REKEY_ACK)
    )
