from typing import Tuple
from pqcrypto.sign import ml_dsa_65 as mldsa


class PQCSign:
    """ML-DSA-65 signatures using pqcrypto with detached signatures."""

    def __init__(self) -> None:
        self.public_key: bytes | None = None
        self.secret_key: bytes | None = None

    def generate_keys(self) -> Tuple[bytes, bytes]:
        pk, sk = mldsa.generate_keypair()
        self.public_key, self.secret_key = pk, sk
        return pk, sk

    def sign_detached(self, message: bytes) -> bytes:
        if self.secret_key is None:
            raise RuntimeError("No secret key — call generate_keys() first")
        # pqcrypto API: sign(secret_key, message) -> signature bytes
        return mldsa.sign(self.secret_key, message)

    def verify_detached(self, signature: bytes, message: bytes) -> bool:
        if self.public_key is None:
            raise RuntimeError("No public key — call generate_keys() first")
        # pqcrypto API: verify(public_key, message, signature) -> bool
        return mldsa.verify(self.public_key, message, signature)

    def signature_length(self) -> int:
        return int(getattr(mldsa, "SIGNATURE_SIZE", 0))

