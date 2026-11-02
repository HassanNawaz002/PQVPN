
"""PQVPN experimental multi-client TCP authentication handler.

Authenticates client identity using a pinned hybrid handshake
and identity-bound PSK challenge-response.

Does not register or activate UDP sessions.
"""

from dataclasses import dataclass

from gateway.client_authorization import ClientAuthorizationService

from modules.encryption.hybrid_handshake import (
    server_respond,
    server_finish,
)

from modules.networking.transport.client_identity_framing import (
    receive_identity_preface,
)

from modules.networking.transport.handshake_framing import (
    decode_client_hello,
    decode_client_finished,
    encode_server_hello,
    receive_tcp_message,
    send_tcp_message,
)

from modules.networking.transport.session_authorization import (
    make_challenge,
    read_exact,
    PROOF_SIZE,
)


TIMEOUT = 10


@dataclass(frozen=True)
class AuthenticatedHandshake:
    client_id: str
    keys: object
    challenge: bytes = b""
    authorization_proof: bytes = b""


def authenticate_connection(
    connection,
    identity,
    authorization_service,
):
    """Authenticate one client without creating a UDP session."""

    if not isinstance(
        authorization_service,
        ClientAuthorizationService,
    ):
        raise TypeError("Expected ClientAuthorizationService")

    public, private = identity

    connection.settimeout(TIMEOUT)

    client_id = receive_identity_preface(connection)

    client_frame = receive_tcp_message(connection)
    client_hello = decode_client_hello(client_frame)

    state, server_hello = server_respond(
        client_hello,
        public,
        private,
    )

    send_tcp_message(
        connection,
        encode_server_hello(server_hello),
    )

    finished_frame = receive_tcp_message(connection)
    client_proof = decode_client_finished(finished_frame)

    keys = server_finish(state, client_proof)

    challenge = make_challenge()
    connection.sendall(challenge)

    authorization_proof = read_exact(
        connection,
        PROOF_SIZE,
    )

    authorized = authorization_service.authorize(
        client_id,
        challenge,
        keys,
        authorization_proof,
    )

    return AuthenticatedHandshake(
        client_id=authorized.client_id,
        keys=keys,
        challenge=challenge,
        authorization_proof=authorization_proof,
    )
