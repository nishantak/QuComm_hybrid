import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ClassicalBackend:
    """
    Minimal AES-GCM backend exposing setup_keys(), encrypt(), decrypt().
    No networking; suitable for single-process benchmark.
    """
    def __init__(self):
        self.key: Optional[bytes] = None
        self.aesgcm: Optional[AESGCM] = None

    def setup_keys(self):
        """Generate a fresh AES-GCM-256 key. Returns timing breakdown dict."""
        from time import perf_counter
        t0 = perf_counter()
        self.key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)
        t1 = perf_counter()
        return {
            "kem_keygen_B_ms": 0.0,
            "encaps_A_ms": 0.0,
            "decaps_B_ms": 0.0,
            "sign_keygen_ms": 0.0,
            "pk_distribution_ms": 0.0,
            "symmetric_keygen_ms": (t1 - t0) * 1000.0,
        }

    def encrypt(self, message: bytes) -> bytes:
        if not self.aesgcm:
            raise RuntimeError("Keys not initialized. Call setup_keys() first.")
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, message, None)
        return nonce + ct

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.aesgcm:
            raise RuntimeError("Keys not initialized. Call setup_keys() first.")
        nonce, ct = ciphertext[:12], ciphertext[12:]
        return self.aesgcm.decrypt(nonce, ct, None)

    # Granular symmetric API for benchmarking parity with PQC backends
    def encrypt_symmetric(self, message: bytes) -> bytes:
        return self.encrypt(message)

    def decrypt_symmetric(self, payload: bytes) -> bytes:
        return self.decrypt(payload)
