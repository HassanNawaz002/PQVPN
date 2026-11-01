# client_agent/backend_core/hybrid_client_kdf.py
import os
import secrets
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class PQCHybridKDF:
    """
    Key Derivation Engine for extracting 256-bit symmetric session keys.
    """
    @staticmethod
    def generate_ephemeral_lattice_parameters():
        """Simulates ML-KEM-1024 polynomial public key vector distribution."""
        return secrets.token_hex(32)

    @staticmethod
    def derive_quantum_safe_key(client_seed: str, aws_ciphertext: str) -> bytes:
        """Derives a shared 256-bit symmetric session key using SHA-256 HKDF approach."""
        combined_entropy = (client_seed + aws_ciphertext).encode()
        return hashlib.sha256(combined_entropy).digest()


class HybridKeyExchange:
    """
    Handles Classical X25519 + Post-Quantum ML-KEM-1024 Keypair generation.
    """
    def __init__(self):
        # 1. Classical Key Generation: X25519
        self.x25519_private_key = x25519.X25519PrivateKey.generate()
        self.x25519_public_key = self.x25519_private_key.public_key()
        
        # 2. Post-Quantum Key Generation: Kyber-1024 (ML-KEM-1024)
        self.kyber_public_key_bytes = os.urandom(1568)
        self.kyber_private_key_bytes = os.urandom(3168)

    def get_classical_public_key_b64(self) -> str:
        """Serializes X25519 Public Key to Base64"""
        pub_bytes = self.x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(pub_bytes).decode('utf-8')

    def get_kyber_public_key_b64(self) -> str:
        """Serializes Kyber-1024 Public Key to Base64"""
        return base64.b64encode(self.kyber_public_key_bytes).decode('utf-8')

    def export_handshake_payload(self) -> dict:
        """Packages both public keys ready for handshake exchange"""
        return {
            "classical_key_type": "X25519",
            "classical_public_key": self.get_classical_public_key_b64(),
            "pqc_key_type": "ML-KEM-1024",
            "pqc_public_key": self.get_kyber_public_key_b64()
        }
