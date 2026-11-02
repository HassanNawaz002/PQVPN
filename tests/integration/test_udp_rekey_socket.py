
"""Real localhost UDP socket tests for PQVPN rekey handover.

No AWS, root privileges, or TUN device required.
"""

import os
import socket
import threading
import unittest

from gateway.session_manager import SessionManager
from gateway.udp_gateway import process_one
from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.session_control import (
    encode_rekey_activate,
    is_rekey_ack,
)
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.udp_transport import UDPTransport


def create_session(manager):
    keys = SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )

    sid = manager.create(keys, "server", authorized=True)

    client = SecureSessionTransport(
        sid,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
    )

    return sid, client


class FakeTun:
    def __init__(self):
        self.written = []

    def write_packet(self, packet):
        self.written.append(packet)


class TestUDPRekeySocket(unittest.TestCase):

    def setUp(self):
        self.manager = SessionManager()
        self.tun = FakeTun()

        self.old_id, self.old_client = create_session(
            self.manager
        )
        self.new_id, self.new_client = create_session(
            self.manager
        )

        self.gateway = UDPTransport(
            host="127.0.0.1",
            port=0,
            timeout=0.5,
        )
        self.gateway.__enter__()

        self.client_udp = UDPTransport(
            host="127.0.0.1",
            port=0,
            timeout=0.5,
        )
        self.client_udp.__enter__()

        self.gateway_address = self.gateway.address
        self.client_address = self.client_udp.address

        # Establish the old session's authenticated endpoint.
        ping = self.old_client.encrypt(b"PING")

        self.manager.process_tunnel_datagram(
            self.old_id,
            ping,
            self.client_address,
        )

    def tearDown(self):
        self.client_udp.__exit__(None, None, None)
        self.gateway.__exit__(None, None, None)

    def exchange(self, encrypted):
        """Send a real UDP packet and process it on the gateway."""
        self.client_udp.send(
            self.gateway_address,
            TYPE_DATA,
            encrypted,
        )

        return process_one(
            self.gateway,
            self.manager,
            enable_ipv4_test=True,
            tun=self.tun,
        )

    def receive_ack(self):
        kind, packet, address = self.client_udp.receive()

        self.assertEqual(kind, TYPE_DATA)
        self.assertEqual(address, self.gateway_address)

        return packet

    def activate(self):
        request = self.new_client.encrypt(
            encode_rekey_activate()
        )

        self.assertTrue(self.exchange(request))

        response = self.receive_ack()

        self.assertTrue(
            is_rekey_ack(
                self.new_client.decrypt(response)
            )
        )

        return request

    def test_real_udp_activation(self):
        self.activate()

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )

    def test_real_udp_fresh_retry(self):
        self.activate()

        retry = self.new_client.encrypt(
            encode_rekey_activate()
        )

        self.assertTrue(self.exchange(retry))

        response = self.receive_ack()

        self.assertTrue(
            is_rekey_ack(
                self.new_client.decrypt(response)
            )
        )

    def test_real_udp_replay_rejected(self):
        original_request = self.activate()

        self.assertFalse(
            self.exchange(original_request)
        )

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )

    def test_real_udp_old_session_rejected(self):
        self.activate()

        old_packet = self.old_client.encrypt(b"PING")

        self.assertFalse(
            self.exchange(old_packet)
        )

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )


if __name__ == "__main__":
    unittest.main()
