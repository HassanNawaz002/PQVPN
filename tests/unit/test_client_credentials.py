
"""Tests for PQVPN independent client credential registry."""

import os
import unittest

from gateway.client_credentials import (
    ClientCredentialRegistry,
    CredentialError,
)


class TestClientCredentials(unittest.TestCase):

    def setUp(self):
        self.registry = ClientCredentialRegistry()
        self.a_psk = os.urandom(32)
        self.b_psk = os.urandom(32)

        self.registry.add_client("client-a", self.a_psk)
        self.registry.add_client("client-b", self.b_psk)

    def test_two_clients_registered(self):
        self.assertEqual(self.registry.client_count(), 2)

    def test_correct_client_a_psk(self):
        self.assertTrue(
            self.registry.verify("client-a", self.a_psk)
        )

    def test_correct_client_b_psk(self):
        self.assertTrue(
            self.registry.verify("client-b", self.b_psk)
        )

    def test_cross_client_psk_rejected(self):
        self.assertFalse(
            self.registry.verify("client-a", self.b_psk)
        )

    def test_wrong_psk_rejected(self):
        self.assertFalse(
            self.registry.verify("client-a", os.urandom(32))
        )

    def test_unknown_client_rejected(self):
        self.assertFalse(
            self.registry.verify("unknown-client", self.a_psk)
        )

    def test_duplicate_client_rejected(self):
        with self.assertRaises(CredentialError):
            self.registry.add_client("client-a", os.urandom(32))

    def test_invalid_psk_length_rejected(self):
        with self.assertRaises(CredentialError):
            self.registry.add_client("client-c", b"short")

    def test_revoked_client_rejected(self):
        self.registry.revoke("client-a")

        self.assertFalse(
            self.registry.verify("client-a", self.a_psk)
        )
        self.assertFalse(
            self.registry.is_enabled("client-a")
        )

    def test_other_client_unaffected_by_revocation(self):
        self.registry.revoke("client-a")

        self.assertTrue(
            self.registry.verify("client-b", self.b_psk)
        )

    def test_unknown_revocation_rejected(self):
        with self.assertRaises(CredentialError):
            self.registry.revoke("unknown")


if __name__ == "__main__":
    unittest.main()
