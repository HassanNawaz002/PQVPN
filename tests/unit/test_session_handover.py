
"""PQVPN gateway single-client session handover tests."""

import os
import unittest

from gateway.session_manager import SessionManager, SessionError
from modules.encryption.key_derivation import SessionKeys


def new_keys():
    """Generate independent session keys for testing."""
    return SessionKeys(
        client_to_server_key=os.urandom(32),
        server_to_client_key=os.urandom(32),
        client_nonce_prefix=os.urandom(4),
        server_nonce_prefix=os.urandom(4),
    )


class TestSessionHandover(unittest.TestCase):

    def setUp(self):
        """Create an active gateway session."""
        self.manager = SessionManager()

        self.old_id = os.urandom(16)
        self.new_id = os.urandom(16)

        while self.new_id == self.old_id:
            self.new_id = os.urandom(16)

        self.manager.register(
            self.old_id,
            new_keys(),
            "server",
            authorized=True,
        )

    def test_new_session_can_be_staged(self):
        """A second authorized session can be registered."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.assertEqual(self.manager.count(), 2)

    def test_old_session_remains_active_until_commit(self):
        """Staging must not automatically switch sessions."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )

    def test_commit_switches_active_session(self):
        """Activation selects the staged session."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.manager.activate(self.new_id)

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )

    def test_commit_retires_old_session(self):
        """Old session must become unavailable after activation."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.manager.activate(self.new_id)

        with self.assertRaises(SessionError):
            self.manager.get(self.old_id)

    def test_unknown_session_cannot_be_activated(self):
        """Unknown session IDs must never be activated."""
        unknown_id = os.urandom(16)

        while unknown_id == self.old_id:
            unknown_id = os.urandom(16)

        with self.assertRaises(SessionError):
            self.manager.activate(unknown_id)

    def test_active_session_stays_selected_during_staging(self):
        """Registering a new session preserves the active session."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.assertEqual(
            self.manager.active_session_id(),
            self.old_id,
        )

    def test_activation_reduces_registry_to_one_session(self):
        """Committing a handover retires other sessions."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.manager.activate(self.new_id)

        self.assertEqual(self.manager.count(), 1)

        self.assertEqual(
            self.manager.active_session_id(),
            self.new_id,
        )

    def test_closing_active_session_does_not_promote_staged(self):
        """Closing the active session must not activate staged keys."""
        self.manager.register(
            self.new_id,
            new_keys(),
            "server",
            authorized=True,
        )

        self.manager.close(self.old_id)

        self.assertIsNone(
            self.manager.active_session_id()
        )

        self.assertEqual(self.manager.count(), 1)


if __name__ == "__main__":
    unittest.main()
