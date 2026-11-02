
"""PQVPN client automatic rekey integration tests.

Tests encrypted activation, ACK validation, retry behavior,
session switching and fail-closed errors without AWS or TUN.
"""

import os
import unittest
from unittest.mock import patch

from modules.encryption.key_derivation import SessionKeys
from modules.networking.transport.client_rekey import (
    make_client_session,
    rekey_session,
    RekeyError,
)
from modules.networking.transport.packet_framing import TYPE_DATA
from modules.networking.transport.session_control import (
    is_rekey_activate,
    encode_rekey_ack,
)
from modules.networking.transport.session_transport import (
    SecureSessionTransport,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
)


DESTINATION = ("127.0.0.1", 51820)
WRONG_PEER = ("127.0.0.1", 51822)


def create_pair():
    keys = SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )

    sid = os.urandom(16)

    client = make_client_session(keys, sid)

    server = SecureSessionTransport(
        sid,
        keys.server_to_client_key,
        keys.server_nonce_prefix,
        SERVER_TO_CLIENT,
        keys.client_to_server_key,
        keys.client_nonce_prefix,
        CLIENT_TO_SERVER,
    )

    return client, server


class FakeUDP:
    """Simulate UDP sends, responses and dropped ACKs."""

    def __init__(self, responder=None):
        self.responder = responder
        self.sent = []
        self.incoming = []

    def send(self, destination, kind, payload):
        self.sent.append((destination, kind, payload))

        if self.responder is not None:
            result = self.responder(
                len(self.sent),
                destination,
                kind,
                payload,
            )

            if result is not None:
                self.incoming.append(result)

    def receive(self):
        if self.incoming:
            return self.incoming.pop(0)

        raise TimeoutError("No UDP response")


class TestClientRekey(unittest.TestCase):

    def setUp(self):
        self.current, self.old_server = create_pair()
        self.staged, self.new_server = create_pair()

    def perform(self, udp, *, attempts=2, timeout=0.02):
        with patch(
            "modules.networking.transport.client_rekey."
            "establish_session",
            return_value=self.staged,
        ):
            return rekey_session(
                self.current,
                udp,
                DESTINATION,
                "127.0.0.1",
                51821,
                "0" * 64,
                ack_timeout=timeout,
                max_attempts=attempts,
            )

    def valid_responder(
        self,
        number,
        destination,
        kind,
        packet,
    ):
        self.assertEqual(destination, DESTINATION)
        self.assertEqual(kind, TYPE_DATA)

        plaintext = self.new_server.decrypt(packet)

        self.assertTrue(is_rekey_activate(plaintext))

        response = self.new_server.encrypt(
            encode_rekey_ack()
        )

        return TYPE_DATA, response, DESTINATION

    def test_successful_authenticated_rekey(self):
        udp = FakeUDP(self.valid_responder)

        result = self.perform(udp)

        self.assertIs(result, self.staged)
        self.assertNotEqual(
            result.session_id,
            self.current.session_id,
        )
        self.assertEqual(len(udp.sent), 1)

    def test_dropped_ack_triggers_fresh_retry(self):
        def responder(number, destination, kind, packet):
            self.new_server.decrypt(packet)

            if number == 1:
                return None

            response = self.new_server.encrypt(
                encode_rekey_ack()
            )

            return TYPE_DATA, response, DESTINATION

        udp = FakeUDP(responder)

        result = self.perform(udp)

        self.assertIs(result, self.staged)
        self.assertEqual(len(udp.sent), 2)

        # Every retry must use a new encrypted datagram.
        self.assertNotEqual(
            udp.sent[0][2],
            udp.sent[1][2],
        )

    def test_invalid_ack_does_not_switch_keys(self):
        def responder(number, destination, kind, packet):
            self.new_server.decrypt(packet)

            response = self.new_server.encrypt(
                b"NOT_A_REKEY_ACK"
            )

            return TYPE_DATA, response, DESTINATION

        udp = FakeUDP(responder)

        with self.assertRaises(RekeyError):
            self.perform(udp)

        self.assertEqual(
            self.current.session_id,
            self.current.crypto.session_id
        )

    def test_missing_ack_fails_closed(self):
        udp = FakeUDP()

        with self.assertRaises(RekeyError):
            self.perform(udp)

        self.assertEqual(len(udp.sent), 2)

    def test_wrong_peer_ack_ignored(self):
        def responder(number, destination, kind, packet):
            self.new_server.decrypt(packet)

            response = self.new_server.encrypt(
                encode_rekey_ack()
            )

            return TYPE_DATA, response, WRONG_PEER

        udp = FakeUDP(responder)

        with self.assertRaises(RekeyError):
            self.perform(udp)

    def test_old_session_packet_ignored(self):
        def responder(number, destination, kind, packet):
            self.new_server.decrypt(packet)

            response = self.old_server.encrypt(
                b"PONG"
            )

            return TYPE_DATA, response, DESTINATION

        udp = FakeUDP(responder)

        with self.assertRaises(RekeyError):
            self.perform(udp)

    def test_handshake_failure_fails_closed(self):
        udp = FakeUDP()

        with patch(
            "modules.networking.transport.client_rekey."
            "establish_session",
            side_effect=ConnectionError(
                "Gateway unavailable"
            ),
        ):
            with self.assertRaises(RekeyError):
                rekey_session(
                    self.current,
                    udp,
                    DESTINATION,
                    "127.0.0.1",
                    51821,
                    "0" * 64,
                )

        self.assertEqual(udp.sent, [])


if __name__ == "__main__":
    unittest.main()

