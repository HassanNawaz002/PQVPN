"""TODO: authenticated decryption; reject invalid tags."""
from shared.errors import TunnelNotReady

def decrypt_packet(*args, **kwargs):
    raise TunnelNotReady("Packet decryption not implemented; fail closed")
