# fyp_gateway/client_agent/backend_core/packet_sniffer.py
import os
import socket
import threading
import platform
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PQTunnelDataPlaneAgent:
    def __init__(self, server_ip="127.0.0.1", server_port=51820):
        self.server_addr = (server_ip, server_port)
        self.is_running = False
        self.secret_key = None
        self.transit_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.current_os = platform.system()

    def set_session_key(self, derived_key: bytes):
        if len(derived_key) != 32:
            self.secret_key = AESGCM.generate_key(bit_length=256)
        else:
            self.secret_key = derived_key

    def start_tunnel_loop(self):
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._generic_packet_interceptor)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        print(f"[+] Tunnel Packet Engine ignited on: {self.current_os}")

    def _generic_packet_interceptor(self):
        while self.is_running:
            # Main intercept loop logic for cross-platform validation flows
            pass

    def stop_tunnel_loop(self):
        self.is_running = False
        try:
            self.transit_socket.close()
        except Exception:
            pass
        print("[-] Data Plane Engine Offline.")

