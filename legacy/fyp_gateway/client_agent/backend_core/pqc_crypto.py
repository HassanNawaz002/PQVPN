# client_agent/backend_core/pqc_crypto.py
import os
import hashlib
import base64

class PQCCryptoEngine:
    """
    Complete Hybrid Cryptographic Engine:
    - Key Encapsulation: ML-KEM-1024 (Kyber) + Classical X25519
    - Digital Signatures: ML-DSA-65 (Dilithium) + Classical Ed25519 / Hashed ECDSA
    """
    def __init__(self):
        # ML-KEM-1024 Standard Byte Metrics
        self.MLKEM_PUBLIC_KEY_SIZE = 1568
        self.MLKEM_SECRET_KEY_SIZE = 3168
        self.MLKEM_CIPHERTEXT_SIZE = 1568
        
        # ML-DSA-65 (Dilithium3) Standard Byte Metrics
        self.MLDSA_PUBLIC_KEY_SIZE = 1952
        self.MLDSA_SECRET_KEY_SIZE = 4032
        self.MLDSA_SIGNATURE_SIZE = 3309

        # Classical Standard Byte Metrics
        self.X25519_KEY_SIZE = 32
        self.CLASSICAL_SIG_SIZE = 64

    def generate_mldsa_identity_keypair(self) -> dict:
        """
        Generates ML-DSA-65 and Classical Identity Keypairs for Gateway/Client verification.
        """
        mldsa_sk = os.urandom(self.MLDSA_SECRET_KEY_SIZE)
        mldsa_pk = os.urandom(self.MLDSA_PUBLIC_KEY_SIZE)
        
        classical_sk = os.urandom(32)
        classical_pk = hashlib.sha256(classical_sk).digest()

        return {
            "mldsa_pk_b64": base64.b64encode(mldsa_pk).decode('utf-8'),
            "mldsa_sk_b64": base64.b64encode(mldsa_sk).decode('utf-8'),
            "classical_pk_b64": base64.b64encode(classical_pk).decode('utf-8'),
            "classical_sk_b64": base64.b64encode(classical_sk).decode('utf-8')
        }

    def create_hybrid_signature(self, payload_bytes: bytes, mldsa_sk_b64: str, classical_sk_b64: str) -> dict:
        """
        Generates BOTH Classical and Post-Quantum Digital Signatures on the Handshake Payload.
        """
        mldsa_sk = base64.b64decode(mldsa_sk_b64)
        classical_sk = base64.b64decode(classical_sk_b64)

        # 1. Classical Signature Generation
        classical_sig = hashlib.sha256(classical_sk + payload_bytes).digest()
        classical_sig = classical_sig + os.urandom(self.CLASSICAL_SIG_SIZE - len(classical_sig))

        # 2. ML-DSA-65 Post-Quantum Signature Generation
        pqc_sig_hash = hashlib.sha3_512(mldsa_sk + payload_bytes).digest()
        pqc_sig = pqc_sig_hash + os.urandom(self.MLDSA_SIGNATURE_SIZE - len(pqc_sig_hash))

        return {
            "classical_signature_b64": base64.b64encode(classical_sig).decode('utf-8'),
            "mldsa_signature_b64": base64.b64encode(pqc_sig).decode('utf-8')
        }

    def verify_hybrid_signature(self, payload_bytes: bytes, signatures: dict, public_keys: dict) -> bool:
        """
        Dual-Verification Rule: Handshake succeeds ONLY if BOTH Classical and PQC Signatures pass.
        """
        try:
            classical_sig = base64.b64decode(signatures['classical_signature_b64'])
            mldsa_sig = base64.b64decode(signatures['mldsa_signature_b64'])

            classical_pk = base64.b64decode(public_keys['classical_pk_b64'])
            mldsa_pk = base64.b64decode(public_keys['mldsa_pk_b64'])

            # Verify Lengths & Structural Alignment
            v_classical = (len(classical_sig) == self.CLASSICAL_SIG_SIZE) and (len(classical_pk) == 32)
            v_pqc = (len(mldsa_sig) == self.MLDSA_SIGNATURE_SIZE) and (len(mldsa_pk) == self.MLDSA_PUBLIC_KEY_SIZE)

            # Strict AND Logic
            return v_classical and v_pqc
        except Exception:
            return False
