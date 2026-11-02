
"""Tests for PQVPN local multi-client credential loading."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from gateway.client_config import (
    load_client_config,
    ClientConfigError,
)


class TestClientConfig(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "clients.json"

    def write(self, data):
        self.path.write_text(
            json.dumps(data),
            encoding="utf-8",
        )
        if os.name == "posix":
            self.path.chmod(0o600)

    def client(self, name, key_byte):
        return {
            "client_id": name,
            "psk_hex": (bytes([key_byte]) * 32).hex(),
        }

    def test_two_independent_clients(self):
        self.write({
            "clients": [
                self.client("client-a", 1),
                self.client("client-b", 2),
            ]
        })

        registry = load_client_config(self.path)

        self.assertEqual(registry.client_count(), 2)
        self.assertTrue(
            registry.verify("client-a", bytes([1]) * 32)
        )
        self.assertTrue(
            registry.verify("client-b", bytes([2]) * 32)
        )

    def test_cross_client_psk_rejected(self):
        self.write({
            "clients": [
                self.client("client-a", 1),
                self.client("client-b", 2),
            ]
        })

        registry = load_client_config(self.path)

        self.assertFalse(
            registry.verify("client-b", bytes([1]) * 32)
        )

    def test_empty_clients_rejected(self):
        self.write({"clients": []})

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    def test_duplicate_client_rejected(self):
        self.write({
            "clients": [
                self.client("client-a", 1),
                self.client("client-a", 2),
            ]
        })

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    def test_invalid_psk_rejected(self):
        self.write({
            "clients": [
                {
                    "client_id": "client-a",
                    "psk_hex": "invalid",
                }
            ]
        })

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    def test_invalid_client_id_rejected(self):
        self.write({
            "clients": [
                self.client("../invalid", 1),
            ]
        })

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    def test_unexpected_fields_rejected(self):
        self.write({
            "clients": [self.client("client-a", 1)],
            "debug": True,
        })

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    def test_missing_file_rejected(self):
        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    def test_duplicate_json_keys_rejected(self):
        self.path.write_text(
            '{"clients":[],"clients":[]}',
            encoding="utf-8",
        )
        if os.name == "posix":
            self.path.chmod(0o600)

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)

    @unittest.skipUnless(
        os.name == "posix",
        "POSIX file permissions only",
    )
    def test_insecure_permissions_rejected(self):
        self.write({
            "clients": [self.client("client-a", 1)]
        })
        self.path.chmod(0o644)

        with self.assertRaises(ClientConfigError):
            load_client_config(self.path)


if __name__ == "__main__":
    unittest.main()
