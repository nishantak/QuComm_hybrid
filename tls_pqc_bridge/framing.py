import struct
from dataclasses import dataclass
from typing import Protocol

from tls_pqc_bridge.errors import ProtocolError
from tls_pqc_bridge.protocol import (
    FINISHED_SIZE,
    NONCE_SIZE,
    RECORD_TAG_SIZE,
    TRANSFER_CHUNK_SIZE,
    TRANSFER_DIGEST_SIZE,
    MessageType,
)


MAGIC = b"QCHN"
VERSION = 1
HEADER = struct.Struct("!4sBBHI")

MAX_PAYLOAD_BY_TYPE = {
    MessageType.SERVER_INIT: NONCE_SIZE + 1184 + 3309,
    MessageType.CLIENT_KEM: 1088,
    MessageType.SERVER_FINISHED: FINISHED_SIZE,
    MessageType.CLIENT_FINISHED: FINISHED_SIZE,
    MessageType.PROTECTED: 8 + 1 + TRANSFER_CHUNK_SIZE + 8 + RECORD_TAG_SIZE,
    MessageType.PING: NONCE_SIZE,
    MessageType.PONG: NONCE_SIZE,
    MessageType.TRANSFER_START: 8 + NONCE_SIZE,
    MessageType.TRANSFER_DATA: 8 + TRANSFER_CHUNK_SIZE,
    MessageType.TRANSFER_END: 8 + TRANSFER_DIGEST_SIZE,
    MessageType.TRANSFER_ACK: 8 + TRANSFER_DIGEST_SIZE,
}


class ByteStream(Protocol):
    def recv(self, size: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...


@dataclass(frozen=True)
class Frame:
    kind: MessageType
    payload: bytes
    header: bytes

    @property
    def wire(self) -> bytes:
        return self.header + self.payload


def encode_frame(kind: MessageType, payload: bytes) -> bytes:
    return _encode_frame_parts(kind, (payload,))


class FramedTransport:
    def __init__(self, stream: ByteStream):
        self._stream = stream
        self.bytes_sent = 0
        self.bytes_received = 0

    def send(self, kind: MessageType, payload: bytes) -> bytes:
        return self.send_parts(kind, (payload,))

    def send_parts(self, kind: MessageType, parts: tuple[bytes, ...]) -> bytes:
        wire = _encode_frame_parts(kind, parts)
        self._stream.sendall(wire)
        self.bytes_sent += len(wire)
        return wire

    def receive(self, expected: MessageType | None = None) -> Frame:
        header = self._receive_exact(HEADER.size)
        magic, version, raw_kind, flags, length = HEADER.unpack(header)

        if magic != MAGIC:
            raise ProtocolError("invalid frame magic")
        if version != VERSION:
            raise ProtocolError(f"unsupported frame version {version}")
        if flags != 0:
            raise ProtocolError("frame flags must be zero")
        try:
            kind = MessageType(raw_kind)
        except ValueError as error:
            raise ProtocolError(f"unknown message type {raw_kind}") from error
        if expected is not None and kind is not expected:
            raise ProtocolError(f"expected {expected.name}, received {kind.name}")

        maximum = MAX_PAYLOAD_BY_TYPE[kind]
        if length > maximum:
            raise ProtocolError(
                f"{kind.name} payload claims {length} bytes; maximum is {maximum}"
            )
        payload = self._receive_exact(length)
        self.bytes_received += len(header) + len(payload)
        return Frame(kind, payload, header)

    def _receive_exact(self, size: int) -> bytes:
        chunks = bytearray(size)
        view = memoryview(chunks)
        received = 0
        while received < size:
            chunk = self._stream.recv(size - received)
            if not chunk:
                raise ProtocolError(
                    f"connection closed after {received} of {size} expected bytes"
                )
            view[received : received + len(chunk)] = chunk
            received += len(chunk)
        return bytes(chunks)


def _encode_frame_parts(kind: MessageType, parts: tuple[bytes, ...]) -> bytes:
    payload_size = sum(len(part) for part in parts)
    maximum = MAX_PAYLOAD_BY_TYPE[kind]
    if payload_size > maximum:
        raise ProtocolError(
            f"{kind.name} payload is {payload_size} bytes; maximum is {maximum}"
        )
    header = HEADER.pack(MAGIC, VERSION, kind, 0, payload_size)
    return b"".join((header, *parts))
