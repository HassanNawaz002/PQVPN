
"""Real TCP-to-UDP integration tests for experimental PQVPN.

Coverage:
- Real hybrid TCP handshake and client PSK authentication
- Independent client identities and sessions
- Wrong PSK rejection
- Cross-client PSK rejection
- Revoked client rejection
- Automatic TCP-to-UDP session registration
- Real encrypted UDP PING/PONG
- Two independent clients using one UDP gateway
- UDP revocation isolation

No production keys, TUN interface or AWS deployment required.
"""

import os
import socket
import threading
import unittest
from unittest.mock import patch

from gateway.client_credentials import ClientCredentialRegistry
from gateway.multi_client_tcp_server import MultiClientTCPServer
from gateway.multi_client_udp_dispatch import process_one

from modules.encryption.ml_dsa import (
    generate_keypair,
    public_key_fingerprint,
)
from modules.networking.transport.handshake_client import (
    connect_gateway,
)
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.packet_framing import TYPE_DATA


class TestMultiClientTCPE2E(unittest.TestCase):
    """Real localhost TCP and UDP integration tests."""

    @classmethod
    def setUpClass(cls):
        cls.identity = generate_keypair()
        cls.fingerprint = public_key_fingerprint(
            cls.identity[0]
        )

    def setUp(self):
        self.psk_a = os.urandom(32)
        self.psk_b = os.urandom(32)

        self.credentials = ClientCredentialRegistry()

        self.credentials.add_client(
            "client-a",
            self.psk_a,
        )

        self.credentials.add_client(
            "client-b",
            self.psk_b,
        )

        self.server = MultiClientTCPServer(
            self.identity,
            self.credentials,
            {
                "client-a": "10.77.0.2",
                "client-b": "10.77.0.3",
            },
        )

    def exchange(self, client_id, psk):
        """Perform a real authenticated localhost TCP handshake.

        Returns:
            client_result: (SessionKeys, session_id) or None
            server_result: (client_id, session_id) or None
            client_errors: list of client exceptions
            server_errors: list of server exceptions
        """
        client_result = None
        server_result = None
        client_errors = []
        server_errors = []

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as listener:

            listener.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )

            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10.0)

            host, port = listener.getsockname()

            def gateway_worker():
                nonlocal server_result

                try:
                    connection, _address = listener.accept()

                    with connection:
                        server_result = (
                            self.server.handle_connection(
                                connection
                            )
                        )

                except Exception as exc:
                    server_errors.append(exc)

            worker = threading.Thread(
                target=gateway_worker,
                daemon=True,
            )
            worker.start()

            try:
                with patch.dict(
                    os.environ,
                    {"PQVPN_CLIENT_PSK": psk.hex()},
                ):
                    client_result = connect_gateway(
                        host,
                        port,
                        self.fingerprint,
                        client_id=client_id,
                    )

            except Exception as exc:
                client_errors.append(exc)

            worker.join(timeout=12.0)

            if worker.is_alive():
                self.fail(
                    "Gateway handshake worker did not terminate"
                )

        return (
            client_result,
            server_result,
            client_errors,
            server_errors,
        )

    def successful_exchange(self, client_id, psk):
        """Require successful authentication on both endpoints."""
        (
            client_result,
            server_result,
            client_errors,
            server_errors,
        ) = self.exchange(client_id, psk)

        self.assertFalse(
            client_errors,
            f"Client errors: {client_errors}",
        )

        self.assertFalse(
            server_errors,
            f"Gateway errors: {server_errors}",
        )

        self.assertIsNotNone(client_result)
        self.assertIsNotNone(server_result)

        keys, session_id = client_result

        self.assertEqual(
            server_result,
            (client_id, session_id),
        )

        self.assertEqual(
            self.server.sessions.owner_of_session(
                session_id
            ),
            client_id,
        )

        # TCP authentication creates the UDP transport,
        # but the UDP endpoint must remain unbound.
        self.assertIsNone(
            self.server.udp_engine.bound_peer(
                session_id
            )
        )

        return keys, session_id

    @staticmethod
    def make_client_transport(keys, session_id):
        """Build the client side of an authenticated session."""
        return SecureSessionTransport(
            session_id,
            keys.client_to_server_key,
            keys.client_nonce_prefix,
            CLIENT_TO_SERVER,
            keys.server_to_client_key,
            keys.server_nonce_prefix,
            SERVER_TO_CLIENT,
        )

    def udp_exchange(self, gateway_udp, client_udp, crypto):
        """Send a real encrypted UDP PING and validate PONG."""
        client_udp.send(
            gateway_udp.address,
            TYPE_DATA,
            crypto.encrypt(b"PING"),
        )

        self.assertTrue(
            process_one(
                gateway_udp,
                self.server.udp_engine,
            )
        )

        message_type, encrypted, sender = (
            client_udp.receive()
        )

        self.assertEqual(
            message_type,
            TYPE_DATA,
        )

        self.assertEqual(
            sender,
            gateway_udp.address,
        )

        self.assertEqual(
            crypto.decrypt(encrypted),
            b"PONG",
        )

    # ---------------------------------------------------------
    # Existing real TCP authentication tests
    # ---------------------------------------------------------

    def test_real_client_a_handshake(self):
        keys, sid = self.successful_exchange(
            "client-a",
            self.psk_a,
        )

        self.assertIsNotNone(keys)
        self.assertEqual(len(sid), 16)

    def test_real_two_independent_clients(self):
        _keys_a, sid_a = self.successful_exchange(
            "client-a",
            self.psk_a,
        )

        _keys_b, sid_b = self.successful_exchange(
            "client-b",
            self.psk_b,
        )

        self.assertNotEqual(sid_a, sid_b)

        self.assertEqual(
            self.server.sessions.active_session(
                "client-a"
            ),
            sid_a,
        )

        self.assertEqual(
            self.server.sessions.active_session(
                "client-b"
            ),
            sid_b,
        )

    def test_real_wrong_psk_rejected(self):
        (
            client_result,
            server_result,
            client_errors,
            server_errors,
        ) = self.exchange(
            "client-a",
            os.urandom(32),
        )

        self.assertIsNone(client_result)
        self.assertIsNone(server_result)
        self.assertTrue(client_errors)
        self.assertTrue(server_errors)
        self.assertEqual(self.server.sessions.session_count(), 0)

    def test_real_cross_client_psk_rejected(self):
        (
            client_result,
            server_result,
            client_errors,
            server_errors,
        ) = self.exchange(
            "client-a",
            self.psk_b,
        )

        self.assertIsNone(client_result)
        self.assertIsNone(server_result)
        self.assertTrue(client_errors)
        self.assertTrue(server_errors)
        self.assertEqual(self.server.sessions.session_count(), 0)

    def test_real_revoked_client_rejected(self):
        self.server.revoke_client("client-a")

        (
            client_result,
            server_result,
            client_errors,
            server_errors,
        ) = self.exchange(
            "client-a",
            self.psk_a,
        )

        self.assertIsNone(client_result)
        self.assertIsNone(server_result)
        self.assertTrue(client_errors)
        self.assertTrue(server_errors)
        self.assertEqual(self.server.sessions.session_count(), 0)

    # ---------------------------------------------------------
    # New real TCP -> UDP integration tests
    # ---------------------------------------------------------

    def test_real_tcp_to_encrypted_udp(self):
        keys, sid = self.successful_exchange(
            "client-a",
            self.psk_a,
        )

        crypto = self.make_client_transport(
            keys,
            sid,
        )

        with UDPTransport(timeout=1.0) as gateway_udp:
            with UDPTransport(timeout=1.0) as client_udp:

                self.udp_exchange(
                    gateway_udp,
                    client_udp,
                    crypto,
                )

                self.assertEqual(
                    self.server.udp_engine.bound_peer(sid),
                    client_udp.address,
                )

    def test_real_two_clients_tcp_to_udp(self):
        keys_a, sid_a = self.successful_exchange(
            "client-a",
            self.psk_a,
        )

        keys_b, sid_b = self.successful_exchange(
            "client-b",
            self.psk_b,
        )

        crypto_a = self.make_client_transport(
            keys_a,
            sid_a,
        )

        crypto_b = self.make_client_transport(
            keys_b,
            sid_b,
        )

        with UDPTransport(timeout=1.0) as gateway_udp:
            with UDPTransport(timeout=1.0) as udp_a:
                with UDPTransport(timeout=1.0) as udp_b:

                    # Both clients use the same UDP gateway.
                    self.udp_exchange(
                        gateway_udp,
                        udp_a,
                        crypto_a,
                    )

                    self.udp_exchange(
                        gateway_udp,
                        udp_b,
                        crypto_b,
                    )

                    # Interleave further encrypted packets.
                    self.udp_exchange(
                        gateway_udp,
                        udp_b,
                        crypto_b,
                    )

                    self.udp_exchange(
                        gateway_udp,
                        udp_a,
                        crypto_a,
                    )

                    self.assertEqual(
                        self.server.udp_engine.bound_peer(
                            sid_a
                        ),
                        udp_a.address,
                    )

                    self.assertEqual(
                        self.server.udp_engine.bound_peer(
                            sid_b
                        ),
                        udp_b.address,
                    )

                    self.assertNotEqual(
                        sid_a,
                        sid_b,
                    )

    def test_real_udp_revocation_isolated(self):
        keys_a, sid_a = self.successful_exchange(
            "client-a",
            self.psk_a,
        )

        keys_b, sid_b = self.successful_exchange(
            "client-b",
            self.psk_b,
        )

        crypto_a = self.make_client_transport(
            keys_a,
            sid_a,
        )

        crypto_b = self.make_client_transport(
            keys_b,
            sid_b,
        )

        with UDPTransport(timeout=1.0) as gateway_udp:
            with UDPTransport(timeout=1.0) as udp_a:
                with UDPTransport(timeout=1.0) as udp_b:

                    self.udp_exchange(
                        gateway_udp,
                        udp_a,
                        crypto_a,
                    )

                    self.udp_exchange(
                        gateway_udp,
                        udp_b,
                        crypto_b,
                    )

                    self.server.revoke_client(
                        "client-a"
                    )

                    udp_a.send(
                        gateway_udp.address,
                        TYPE_DATA,
                        crypto_a.encrypt(b"PING"),
                    )

                    self.assertFalse(
                        process_one(
                            gateway_udp,
                            self.server.udp_engine,
                        )
                    )

                    # Client B must remain fully operational.
                    self.udp_exchange(
                        gateway_udp,
                        udp_b,
                        crypto_b,
                    )

                    self.assertEqual(
                        self.server.udp_engine.bound_peer(
                            sid_b
                        ),
                        udp_b.address,
                    )


if __name__ == "__main__":
    unittest.main()
