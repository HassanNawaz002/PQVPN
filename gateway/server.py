"""Gateway entrypoint placeholder. Legacy FastAPI server is preserved separately.
Do not expose legacy mock handshake as a production VPN service.
"""
from shared.errors import TunnelNotReady

def main():
    raise TunnelNotReady("Secure gateway not implemented; refusing to start")

if __name__ == "__main__":
    main()
