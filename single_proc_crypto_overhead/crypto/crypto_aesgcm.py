import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # AES-GCM standard (96-bit)
KEY_SIZE = 32    # 256-bit key

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext_with_tag). 'ciphertext_with_tag' includes the GCM tag appended.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-GCM-256 requires 32-byte key, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-GCM-256 requires 32-byte key, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"AES-GCM requires {NONCE_SIZE}-byte nonce, got {len(nonce)}")
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)
