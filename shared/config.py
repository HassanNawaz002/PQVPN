"""Validated configuration types. No embedded server IPs or secrets."""
from dataclasses import dataclass
import ipaddress

@dataclass(frozen=True)
class Gateway:
    id: str
    host: str
    region: str
    udp_port: int = 51820
    public_identity_key: str = ""

    def __post_init__(self):
        if not self.id.strip() or not self.host.strip() or not self.region.strip():
            raise ValueError("Gateway id, host and region are required")
        if not (1 <= self.udp_port <= 65535):
            raise ValueError("Invalid UDP port")

@dataclass(frozen=True)
class ClientPolicy:
    mode: str = "selected_apps"
    executable_paths: tuple[str, ...] = ()
    def __post_init__(self):
        if self.mode not in ("selected_apps", "all_apps", "bypass_selected"):
            raise ValueError("Unsupported routing mode")
