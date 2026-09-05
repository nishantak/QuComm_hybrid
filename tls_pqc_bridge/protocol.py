from enum import IntEnum


PROTOCOL_ID = b"QCOMM-TWO-PLANE-V1"
SUITE_ID = b"TLS13-EXPORTER-MLKEM768-MLDSA65-HKDFSHA256-AES256GCM"
MODES = ("baseline", "native", "hybrid")
ALPN_IDS = {
    "baseline": b"qcomm/baseline/1",
    "native": b"qcomm/baseline/1",
    "hybrid": b"qcomm/hybrid/1",
}
TLS_GROUP_BY_MODE = {
    "baseline": "X25519",
    "native": "X25519MLKEM768",
    "hybrid": "X25519",
}
EXPORTER_LABEL = b"EXPERIMENTAL-QCOMM-TWO-PLANE-V1"
CATKDF_LABEL = b"QCOMM-CATKDF-V1"

NONCE_SIZE = 32
FINISHED_SIZE = 32
AES_KEY_SIZE = 32
AES_IV_SIZE = 12
RECORD_TAG_SIZE = 16
TRANSFER_DIGEST_SIZE = 32
# A protected TRANSFER_DATA frame is exactly 65,536 bytes at this payload size.
TRANSFER_CHUNK_SIZE = 64 * 1024 - (12 + 8 + 1 + 8 + RECORD_TAG_SIZE)
MAX_TRANSFER_BYTES = 1024**3


class MessageType(IntEnum):
    SERVER_INIT = 1
    CLIENT_KEM = 2
    SERVER_FINISHED = 3
    CLIENT_FINISHED = 4
    PROTECTED = 5
    PING = 16
    PONG = 17
    TRANSFER_START = 18
    TRANSFER_DATA = 19
    TRANSFER_END = 20
    TRANSFER_ACK = 21


APPLICATION_TYPES = frozenset(
    {
        MessageType.PING,
        MessageType.PONG,
        MessageType.TRANSFER_START,
        MessageType.TRANSFER_DATA,
        MessageType.TRANSFER_END,
        MessageType.TRANSFER_ACK,
    }
)
