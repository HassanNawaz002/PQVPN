
"""Gateway single-client session handover tests."""

import os
import unittest

from gateway.session_manager import SessionManager, SessionError
from modules.encryption.key_derivation import SessionKeys


def new_keys():
    return SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )


class TestSessionHandover(unittest.TestCase):

    def setUp(self):
        self.manager = SessionManager()
        self.old_id = os.urandom(16)
        self.new_id = os.urandom(16)

        self.manager.register(
            self.old_id, new_keys(), "server", authorized=True
        )

    def test_new_session_can_be_staged(self):
        self.manager.register(
            self.new_id, new_keys(), "server", authorized=True
        )
        self.assertEqual(self.manager.count(), 2)

    def test_old_session_remains_active_until_commit(self):
        self.manager.register(
            self.new_id, new_keys(), "server", authorized=True
        )
        self.assertEqual(self.manager.active_session_id(), self.old_id)

    def test_commit_switches_active_session(self):
        self.manager.register(
            self.new_id, new_keys(), "server", authorized=True
        )
        self.manager.activate(self.new_id)

        self.assertEqual(self.manager.active_session_id(), self.new_id)

    def test_commit_retires_old_session(self):
        self.manager.register(
            self.new_id, new_keys(), "server", authorized=True
        )
        self.manager.activate(self.new_id)

        with self.assertRaises(SessionError):
            self.manager.get(self.old_id)

    def test_unknown_session_cannot_be_activated(self):
        with self.assertRaises(SessionError):
            self.manager.activate(os.urandom(16))


if __name__ == "__main__":
    unittest.main()
