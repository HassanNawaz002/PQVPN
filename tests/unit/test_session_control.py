
"""PQVPN session control payload tests."""

import unittest

from modules.networking.transport.session_control import (
    encode_rekey_activate,
    encode_rekey_ack,
    is_rekey_activate,
    is_rekey_ack,
)


class TestSessionControl(unittest.TestCase):

    def test_activation_encoding(self):
        payload = encode_rekey_activate()
        self.assertTrue(is_rekey_activate(payload))
        self.assertFalse(is_rekey_ack(payload))

    def test_ack_encoding(self):
        payload = encode_rekey_ack()
        self.assertTrue(is_rekey_ack(payload))
        self.assertFalse(is_rekey_activate(payload))

    def test_random_payload_rejected(self):
        self.assertFalse(is_rekey_activate(b"PING"))
        self.assertFalse(is_rekey_ack(b"PING"))

    def test_modified_activation_rejected(self):
        payload = encode_rekey_activate() + b"X"
        self.assertFalse(is_rekey_activate(payload))

    def test_plaintext_label_rejected(self):
        self.assertFalse(is_rekey_activate(b"REKEY_ACTIVATE"))


if __name__ == "__main__":
    unittest.main()
