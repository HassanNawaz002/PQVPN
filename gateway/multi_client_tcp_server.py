
"""PQVPN isolated multi-client TCP handshake server.

Authenticates independent client identities and issues
authenticated session acceptances.

Control-plane testing only. No UDP/TUN forwarding.
"""

import argparse
import secrets
import socket
import threading

from gateway.client_authorization import ClientAuthorizationService
from gateway.client_config import load_client_config
from gateway.handshake_server import load_identity
from gateway.multi_client_handshake import authenticate_connection
from gateway.multi_client_registry import MultiClientSessionManager

from modules.networking.transport.session_authorization import (
    make_accept,
)


class MultiClientTCPError(Exception):
    """Multi-client TCP session establishment failed."""


class MultiClientTCPServer:
    def __init__(self, identity, credentials, assignments):
        self.identity = identity
        self.credentials = credentials
        self.authorization = ClientAuthorizationService(credentials)
        self.sessions = MultiClientSessionManager()
        self._lock = threading.RLock()
        self._pending = set()

        if not isinstance(assignments, dict) or not assignments:
            raise MultiClientTCPError("Client assignments required")

        for client_id, tunnel_ip in assignments.items():
            if not credentials.is_enabled(client_id):
                raise MultiClientTCPError(
                    "Assignment references unknown or disabled client"
                )
            self.sessions.register_client(client_id, tunnel_ip)

    def handle_connection(self, connection):
        """Authenticate and register one TCP session.

        Session acceptance is sent only after successful
        authorization and ownership registration.
        """

        authenticated = authenticate_connection(
            connection,
            self.identity,
            self.authorization,
        )

        client_id = authenticated.client_id
        keys = authenticated.keys

        # Recheck authorization before registration.
        with self._lock:
            if not self.credentials.is_enabled(client_id):
                raise MultiClientTCPError("Client disabled")

            session_id = secrets.token_bytes(16)

            while (
                session_id in self._pending
                or self._session_exists(session_id)
            ):
                session_id = secrets.token_bytes(16)

            self._pending.add(session_id)

        try:
            # The authorization challenge and proof must be
            # preserved from the handshake for make_accept().
            # They are returned by the updated handshake handler.
            acceptance = make_accept(
                keys,
                session_id,
                authenticated.challenge,
                authenticated.authorization_proof,
            )

            with self._lock:
                if not self.credentials.is_enabled(client_id):
                    raise MultiClientTCPError("Client disabled")

                self.sessions.register_session(
                    client_id,
                    session_id,
                )

            try:
                connection.sendall(acceptance)
            except OSError:
                # Do not claim the session was accepted.
                # The registry currently lacks removal API;
                # no UDP transport is attached in this sprint.
                raise

            return client_id, session_id

        finally:
            with self._lock:
                self._pending.discard(session_id)

    def _session_exists(self, session_id):
        try:
            self.sessions.owner_of_session(session_id)
            return True
        except Exception as exc:
            from gateway.multi_client_registry import MultiClientError
            if isinstance(exc, MultiClientError):
                return False
            raise


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
            f"Multi-client TCP handshake listening on {host}:{port}",
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

    for assignment in args.assign:
        if "=" not in assignment:
            parser.error("Invalid client assignment")

        client_id, tunnel_ip = assignment.split("=", 1)

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
