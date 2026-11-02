
"""Integration tests for PQVPN UDP rekey dispatcher.

Uses an in-memory UDP transport and fake TUN interface to
exercise gateway.udp_gateway.process_one without network setup.
"""

import os
import unittest

from gateway.session_manager import SessionManager, SessionError
from gateway.udp_gateway import process_one
from modules.encryption.key_derivation import SessionKeys
from modules.encryption.cipher_suites import ReplayError
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)
from modules.networking.transport.session_control import (
    encode_rekey_activate,
    is_rekey_ack,
)


class FakeUDP:
    def __init__(self, packet, address):
        self.packet = packet
        self.address = address
        self.sent = []

    def receive(self):
        return TYPE_DATA, self.packet, self.address

    def send(self, address, kind, payload):
        self.sent.append((address, kind, payload))


class FakeTun:
    def __init__(self):
        self.written = []

    def write_packet(self, packet):
        self.written.append(packet)


def create_session(manager):
    keys = SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )

    sid = manager.create(
        keys,
        "server",
        authorized=True,
    )

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


class TestUDPRekeyDispatch(unittest.TestCase):

    def setUp(self):
        self.manager = SessionManager()
        self.address = ("127.0.0.1", 45000)
        self.tun = FakeTun()

        self.old_id, self.old_client = create_session(
            self.manager
        )

        self.new_id, self.new_client = create_session(
            self.manager
        )

        # Establish the active session's endpoint.
        ping = self.old_client.encrypt(b"PING")

        self.manager.process_tunnel_datagram(
            self.old_id,
            ping,
            self.address,
        )

    def dispatch(self, packet, address=None):
        udp = FakeUDP(
            packet,
            address if address is not None else self.address,
        )

        accepted = process_one(
            udp,
            self.manager,
            enable_ipv4_test=True,
            tun=self.tun,
        )

        return accepted, udp

    def activate(self):
        request = self.new_client.encrypt(
            encode_rekey_activate()
        )

        return self.dispatch(request)

    def test_initial_activation_returns_ack(self):
        accepted, udp = self.activate()

        self.assertTrue(accepted)
        self.assertEqual(len(udp.sent), 1)
        self.assertEqual(udp.sent[0][0], self.address)
        self.assertEqual(udp.sent[0][1], TYPE_DATA)

        self.assertTrue(
            is_rekey_ack(
                self.new_client.decrypt(udp.sent[0][2])
            )
        )

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )

    def test_old_session_retired_after_activation(self):
        self.activate()

        old_packet = self.old_client.encrypt(b"PING")

        accepted, udp = self.dispatch(old_packet)

        self.assertFalse(accepted)
        self.assertEqual(udp.sent, [])

        with self.assertRaises(SessionError):
            self.manager.get(self.old_id)

    def test_fresh_retry_returns_ack(self):
        self.activate()

        retry = self.new_client.encrypt(
            encode_rekey_activate()
        )

        accepted, udp = self.dispatch(retry)

        self.assertTrue(accepted)
        self.assertEqual(len(udp.sent), 1)

        self.assertTrue(
            is_rekey_ack(
                self.new_client.decrypt(udp.sent[0][2])
            )
        )

    def test_replayed_activation_rejected(self):
        request = self.new_client.encrypt(
            encode_rekey_activate()
        )

        accepted, _ = self.dispatch(request)
        self.assertTrue(accepted)

        accepted, udp = self.dispatch(request)

        self.assertFalse(accepted)
        self.assertEqual(udp.sent, [])

    def test_wrong_endpoint_rejected(self):
        request = self.new_client.encrypt(
            encode_rekey_activate()
        )

        accepted, udp = self.dispatch(
            request,
            ("127.0.0.1", 45001),
        )

        self.assertFalse(accepted)
        self.assertEqual(udp.sent, [])

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )

    def test_tampered_activation_rejected(self):
        request = bytearray(
            self.new_client.encrypt(
                encode_rekey_activate()
            )
        )

        request[-1] ^= 1

        accepted, udp = self.dispatch(bytes(request))

        self.assertFalse(accepted)
        self.assertEqual(udp.sent, [])

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )

    def test_staged_session_cannot_send_ping(self):
        packet = self.new_client.encrypt(b"PING")

        accepted, udp = self.dispatch(packet)

        self.assertFalse(accepted)
        self.assertEqual(udp.sent, [])

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )


if __name__ == "__main__":
    unittest.main()
