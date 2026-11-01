
import unittest
from dataclasses import replace

from modules.encryption.ml_dsa import (
    generate_keypair,
    public_key_fingerprint,
)
from modules.encryption.key_derivation import keys_match
from modules.encryption.hybrid_handshake import (
    client_start,
    server_respond,
    client_finish,
    server_finish,
    HandshakeError,
)


class TestHybridHandshake(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.identity_public, cls.identity_secret = generate_keypair()
        cls.fingerprint = public_key_fingerprint(
            cls.identity_public
        )

    def _start(self):
        state, hello = client_start()
        server_state, response = server_respond(
            hello,
            self.identity_public,
            self.identity_secret,
        )
        return state, server_state, response

    def test_authenticated_key_agreement(self):
        client_state, server_state, response = self._start()

        client_keys, proof = client_finish(
            client_state, response, self.fingerprint
        )
        server_keys = server_finish(server_state, proof)

        self.assertTrue(keys_match(client_keys, server_keys))

    def test_untrusted_gateway_rejected(self):
        client_state, _, response = self._start()

        with self.assertRaises(HandshakeError):
            client_finish(
                client_state,
                response,
                "0" * 64,
            )

    def test_tampered_server_hello_rejected(self):
        client_state, _, response = self._start()

        tampered = replace(
            response,
            server_nonce=b"\x00" * 32,
        )

        with self.assertRaises(HandshakeError):
            client_finish(
                client_state,
                tampered,
                self.fingerprint,
            )

    def test_invalid_client_confirmation_rejected(self):
        client_state, server_state, response = self._start()

        _, proof = client_finish(
            client_state, response, self.fingerprint
        )

        bad_proof = bytes([proof[0] ^ 1]) + proof[1:]

        with self.assertRaises(HandshakeError):
            server_finish(server_state, bad_proof)

    def test_client_state_cannot_be_reused(self):
        client_state, _, response = self._start()

        client_finish(
            client_state, response, self.fingerprint
        )

        with self.assertRaises(HandshakeError):
            client_finish(
                client_state, response, self.fingerprint
            )


if __name__ == "__main__":
    unittest.main()
