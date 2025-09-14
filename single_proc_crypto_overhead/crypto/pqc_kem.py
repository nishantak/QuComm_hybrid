from typing import Optional, Tuple
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt


class PQCKEM:
    """Real ML-KEM-768 implementation for post-quantum key encapsulation."""
    
    def __init__(self) -> None:
        self.public_key: Optional[bytes] = None
        self.secret_key: Optional[bytes] = None
        self.shared_key: Optional[bytes] = None

    def generate_keys(self) -> Tuple[bytes, bytes]:
        """Generate a new ML-KEM-768 keypair."""
        self.public_key, self.secret_key = generate_keypair()
        return self.public_key, self.secret_key

    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using peer's public key."""
        if peer_public_key is None:
            raise ValueError("peer_public_key must not be None")
        ciphertext, shared_secret = encrypt(peer_public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret using our secret key."""
        if self.secret_key is None:
            raise RuntimeError("No secret key — call generate_keys() first")
        self.shared_key = decrypt(ciphertext, self.secret_key)
        return self.shared_key

    def get_public_key(self) -> bytes:
        """Get the public key, generating if necessary."""
        if self.public_key is None:
            self.generate_keys()
        return self.public_key

    def get_shared_key(self) -> Optional[bytes]:
        """Get the current shared key."""
        return self.shared_key
