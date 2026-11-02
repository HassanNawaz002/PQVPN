
"""PQVPN multi-client registry isolation tests."""

import os
import unittest

from gateway.multi_client_registry import (
    MultiClientSessionManager,
    MultiClientError,
)


class TestMultiClientRegistry(unittest.TestCase):

    def setUp(self):
        self.manager = MultiClientSessionManager()

        self.manager.register_client(
            "client-a",
            "10.77.0.2",
        )

        self.manager.register_client(
            "client-b",
            "10.77.0.3",
        )

        self.a1 = os.urandom(16)
        self.a2 = os.urandom(16)
        self.b1 = os.urandom(16)

        self.manager.register_session("client-a", self.a1)
        self.manager.register_session("client-b", self.b1)

    def test_two_clients_registered(self):
        self.assertEqual(self.manager.client_count(), 2)

    def test_unique_tunnel_ip_mapping(self):
        self.assertEqual(
            self.manager.client_for_ip("10.77.0.2"),
            "client-a",
        )
        self.assertEqual(
            self.manager.client_for_ip("10.77.0.3"),
            "client-b",
        )

    def test_duplicate_ip_rejected(self):
        with self.assertRaises(MultiClientError):
            self.manager.register_client(
                "client-c",
                "10.77.0.2",
            )

    def test_duplicate_client_rejected(self):
        with self.assertRaises(MultiClientError):
            self.manager.register_client(
                "client-a",
                "10.77.0.4",
            )

    def test_invalid_tunnel_ip_rejected(self):
        with self.assertRaises(MultiClientError):
            self.manager.register_client(
                "client-c",
                "192.168.1.10",
            )

    def test_independent_active_sessions(self):
        self.assertEqual(
            self.manager.active_session("client-a"),
            self.a1,
        )
        self.assertEqual(
            self.manager.active_session("client-b"),
            self.b1,
        )

    def test_staging_does_not_interrupt_other_client(self):
        self.manager.register_session(
            "client-a",
            self.a2,
        )

        self.assertEqual(
            self.manager.active_session("client-a"),
            self.a1,
        )
        self.assertEqual(
            self.manager.active_session("client-b"),
            self.b1,
        )

    def test_rekey_only_retires_own_sessions(self):
        self.manager.register_session(
            "client-a",
            self.a2,
        )

        self.manager.activate("client-a", self.a2)

        self.assertEqual(
            self.manager.active_session("client-a"),
            self.a2,
        )
        self.assertEqual(
            self.manager.active_session("client-b"),
            self.b1,
        )
        self.assertEqual(
            self.manager.session_count(),
            2,
        )

        with self.assertRaises(MultiClientError):
            self.manager.owner_of_session(self.a1)

    def test_cross_client_activation_rejected(self):
        self.manager.register_session(
            "client-a",
            self.a2,
        )

        with self.assertRaises(MultiClientError):
            self.manager.activate("client-b", self.a2)

        self.assertEqual(
            self.manager.active_session("client-b"),
            self.b1,
        )

    def test_unknown_session_rejected(self):
        with self.assertRaises(MultiClientError):
            self.manager.activate(
                "client-a",
                os.urandom(16),
            )

    def test_duplicate_session_rejected(self):
        with self.assertRaises(MultiClientError):
            self.manager.register_session(
                "client-a",
                self.a1,
            )


if __name__ == "__main__":
    unittest.main()
