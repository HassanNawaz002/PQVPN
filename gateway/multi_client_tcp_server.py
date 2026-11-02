
"""PQVPN experimental multi-client TCP authentication server.

Integrates authenticated TCP sessions with the isolated
multi-client UDP engine.

No TUN forwarding or production deployment is enabled.
"""

import argparse
import secrets
import socket
import threading

from gateway.client_authorization import ClientAuthorizationService
from gateway.client_config import load_client_config
from gateway.handshake_server import load_identity
from gateway.multi_client_ipv4_udp import MultiClientIPv4UDPEngine
from gateway.multi_client_handshake import authenticate_connection
from gateway.multi_client_registry import (
    MultiClientSessionManager,
    MultiClientError,
)
from gateway.multi_client_udp import MultiClientUDPEngine

from modules.networking.transport.session_authorization import (
    make_accept,
)


class MultiClientTCPError(Exception):
    """TCP session establishment failed."""


class MultiClientTCPServer:

    def __init__(self, identity, credentials, assignments):
        self.identity = identity
        self.credentials = credentials
        self.authorization = ClientAuthorizationService(credentials)

        self.sessions = MultiClientSessionManager()
        self.udp_engine = MultiClientIPv4UDPEngine(self.sessions)

        self._lock = threading.RLock()

        if not isinstance(assignments, dict) or not assignments:
            raise MultiClientTCPError("Client assignments required")

        for client_id, tunnel_ip in assignments.items():
            if not credentials.is_enabled(client_id):
                raise MultiClientTCPError(
                    "Assignment references unknown or disabled client"
                )

            self.sessions.register_client(client_id, tunnel_ip)

    def _new_session_id(self):
        """Allocate an unused session ID under the server lock."""
        for _ in range(32):
            sid = secrets.token_bytes(16)

            try:
                self.sessions.owner_of_session(sid)
            except MultiClientError:
                return sid

        raise MultiClientTCPError("Unable to allocate session ID")

    def handle_connection(self, connection):
        """Authenticate TCP and register an encrypted UDP session."""
        authenticated = authenticate_connection(
            connection,
            self.identity,
            self.authorization,
        )

        client_id = authenticated.client_id
        keys = authenticated.keys

        with self._lock:
            if not self.credentials.is_enabled(client_id):
                raise MultiClientTCPError("Client disabled")

            session_id = self._new_session_id()

            acceptance = make_accept(
                keys,
                session_id,
                authenticated.challenge,
                authenticated.authorization_proof,
            )

            self.sessions.register_session(client_id, session_id)

            try:
                # Only authenticated TCP-derived keys are registered.
                self.udp_engine.register_authenticated(
                    client_id,
                    session_id,
                    keys,
                )

                if not self.credentials.is_enabled(client_id):
                    raise MultiClientTCPError("Client disabled")

                connection.sendall(acceptance)

            except BaseException:
                # Roll back both ownership and UDP transport state.
                self.sessions.remove_session(client_id, session_id)
                self.udp_engine.discard_session(session_id)
                raise

            return client_id, session_id

    def revoke_client(self, client_id):
        """Revoke credentials and all associated UDP sessions."""
        with self._lock:
            self.credentials.revoke(client_id)
            return self.udp_engine.revoke_client(client_id)


def serve(host, port, server):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        listener.bind((host, port))
        listener.listen(16)

        print(
            f"PQVPN multi-client TCP listening on {host}:{port}",
            flush=True,
        )

        while True:
            connection, _address = listener.accept()

            def worker(sock):
                with sock:
                    try:
                        client_id, sid = server.handle_connection(sock)
                        print(
                            f"Authenticated {client_id}: {sid.hex()}",
                            flush=True,
                        )
                    except Exception as exc:
                        print(
                            "Handshake rejected:",
                            type(exc).__name__,
                            flush=True,
                        )

            threading.Thread(
                target=worker,
                args=(connection,),
                daemon=True,
            ).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=51831)
    parser.add_argument("--credentials", required=True)
    parser.add_argument(
        "--assign",
        action="append",
        required=True,
        metavar="CLIENT_ID=IPv4",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Invalid TCP port")

    assignments = {}

    for item in args.assign:
        if "=" not in item:
            parser.error("Invalid client assignment")

        client_id, tunnel_ip = item.split("=", 1)

        if client_id in assignments:
            parser.error("Duplicate client assignment")

        assignments[client_id] = tunnel_ip

    server = MultiClientTCPServer(
        load_identity(),
        load_client_config(args.credentials),
        assignments,
    )

    serve(args.host, args.port, server)


if __name__ == "__main__":
    main()
