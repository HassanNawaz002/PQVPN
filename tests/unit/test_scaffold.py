import unittest
from shared.config import ClientPolicy, Gateway
from shared.errors import TunnelNotReady
from modules.encryption.hybrid_handshake import establish_session
from modules.networking.policy.policy_engine import is_selected_executable

class TestScaffold(unittest.TestCase):
    def test_gateway_validation(self):
        self.assertEqual(Gateway("sg", "127.0.0.1", "sg").udp_port, 51820)
        with self.assertRaises(ValueError): Gateway("sg", "127.0.0.1", "sg", 99999)
    def test_policy_selection(self):
        p = ClientPolicy(executable_paths=(r"C:\Apps\Browser.exe",))
        self.assertTrue(is_selected_executable(p, r"C:\Apps\Browser.exe"))
        self.assertFalse(is_selected_executable(p, r"C:\Apps\Other.exe"))
    def test_crypto_fails_closed(self):
        with self.assertRaises(TunnelNotReady): establish_session()

if __name__ == "__main__": unittest.main()
