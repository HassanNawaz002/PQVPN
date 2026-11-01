class PQVPNError(Exception):
    """Base project error."""

class TunnelNotReady(PQVPNError):
    """Raised when a real, authenticated tunnel is not established."""
