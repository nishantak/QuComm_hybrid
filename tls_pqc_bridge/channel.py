import struct
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tls_pqc_bridge.errors import IntegrityError, ProtocolError
from tls_pqc_bridge.framing import FramedTransport, MAX_PAYLOAD_BY_TYPE
from tls_pqc_bridge.hybrid import TrafficSecrets
from tls_pqc_bridge.protocol import (
    APPLICATION_TYPES,
    PROTOCOL_ID,
    RECORD_TAG_SIZE,
    MessageType,
)


MAX_RECORDS_PER_KEY = 2**15
RECORD_PREFIX = struct.Struct("!QB")
AAD_FIELDS = struct.Struct("!cQBI")


class ApplicationChannel(Protocol):
    @property
    def bytes_sent(self) -> int: ...

    @property
    def bytes_received(self) -> int: ...

    def send(self, kind: MessageType, payload: bytes) -> None: ...

    def send_parts(self, kind: MessageType, parts: tuple[bytes, ...]) -> None: ...

    def receive(self, expected: MessageType) -> bytes: ...


class PlainChannel:
    def __init__(self, transport: FramedTransport):
        self._transport = transport

    @property
    def bytes_sent(self) -> int:
        return self._transport.bytes_sent

    @property
    def bytes_received(self) -> int:
        return self._transport.bytes_received

    def send(self, kind: MessageType, payload: bytes) -> None:
        self.send_parts(kind, (payload,))

    def send_parts(self, kind: MessageType, parts: tuple[bytes, ...]) -> None:
        _require_application_type(kind)
        self._transport.send_parts(kind, parts)

    def receive(self, expected: MessageType) -> bytes:
        _require_application_type(expected)
        return self._transport.receive(expected).payload


class ProtectedChannel:
    def __init__(
        self,
        transport: FramedTransport,
        secrets: TrafficSecrets,
        role: str,
    ):
        if role == "client":
            send_key, send_iv, send_direction = (
                secrets.client_key,
                secrets.client_iv,
                b"C",
            )
            receive_key, receive_iv, receive_direction = (
                secrets.server_key,
                secrets.server_iv,
                b"S",
            )
        elif role == "server":
            send_key, send_iv, send_direction = (
                secrets.server_key,
                secrets.server_iv,
                b"S",
            )
            receive_key, receive_iv, receive_direction = (
                secrets.client_key,
                secrets.client_iv,
                b"C",
            )
        else:
            raise ValueError("role must be 'client' or 'server'")

        self._transport = transport
        self._send_cipher = AESGCM(send_key)
        self._receive_cipher = AESGCM(receive_key)
        self._send_iv = send_iv
        self._receive_iv = receive_iv
        self._send_direction = send_direction
        self._receive_direction = receive_direction
        self._send_sequence = 0
        self._receive_sequence = 0

    @property
    def bytes_sent(self) -> int:
        return self._transport.bytes_sent

    @property
    def bytes_received(self) -> int:
        return self._transport.bytes_received

    def send(self, kind: MessageType, payload: bytes) -> None:
        self.send_parts(kind, (payload,))

    def send_parts(self, kind: MessageType, parts: tuple[bytes, ...]) -> None:
        _require_application_type(kind)
        payload_size = sum(len(part) for part in parts)
        if payload_size > MAX_PAYLOAD_BY_TYPE[kind]:
            raise ProtocolError(f"{kind.name} payload exceeds its protocol limit")
        sequence = self._next_send_sequence()
        aad = _record_aad(self._send_direction, sequence, kind, payload_size)
        payload = parts[0] if len(parts) == 1 else b"".join(parts)
        ciphertext = self._send_cipher.encrypt(
            _record_nonce(self._send_iv, sequence), payload, aad
        )
        prefix = RECORD_PREFIX.pack(sequence, kind)
        self._transport.send_parts(MessageType.PROTECTED, (prefix, ciphertext))

    def receive(self, expected: MessageType) -> bytes:
        _require_application_type(expected)
        if self._receive_sequence >= MAX_RECORDS_PER_KEY:
            raise ProtocolError(
                "protected record limit reached; reconnect before receiving"
            )
        protected = self._transport.receive(MessageType.PROTECTED).payload
        if len(protected) < RECORD_PREFIX.size + RECORD_TAG_SIZE:
            raise ProtocolError("protected record is too short")
        sequence, raw_kind = RECORD_PREFIX.unpack_from(protected)
        try:
            kind = MessageType(raw_kind)
        except ValueError as error:
            raise ProtocolError(f"unknown protected message type {raw_kind}") from error
        _require_application_type(kind)
        if sequence != self._receive_sequence:
            raise IntegrityError(
                f"expected protected sequence {self._receive_sequence}, received {sequence}"
            )
        ciphertext = memoryview(protected)[RECORD_PREFIX.size :]
        plaintext_size = len(ciphertext) - RECORD_TAG_SIZE
        if plaintext_size > MAX_PAYLOAD_BY_TYPE[kind]:
            raise ProtocolError(
                f"protected {kind.name} payload exceeds its protocol limit"
            )
        aad = _record_aad(self._receive_direction, sequence, kind, plaintext_size)
        try:
            plaintext = self._receive_cipher.decrypt(
                _record_nonce(self._receive_iv, sequence), ciphertext, aad
            )
        except InvalidTag as error:
            raise IntegrityError("protected record authentication failed") from error
        self._receive_sequence += 1
        if kind is not expected:
            raise ProtocolError(f"expected {expected.name}, received {kind.name}")
        return plaintext

    def _next_send_sequence(self) -> int:
        if self._send_sequence >= MAX_RECORDS_PER_KEY:
            raise ProtocolError(
                "protected record limit reached; reconnect before sending"
            )
        sequence = self._send_sequence
        self._send_sequence += 1
        return sequence


def _record_nonce(static_iv: bytes, sequence: int) -> bytes:
    value = int.from_bytes(static_iv, "big") ^ sequence
    return value.to_bytes(len(static_iv), "big")


def _record_aad(
    direction: bytes, sequence: int, kind: MessageType, plaintext_size: int
) -> bytes:
    return PROTOCOL_ID + AAD_FIELDS.pack(direction, sequence, kind, plaintext_size)


def _require_application_type(kind: MessageType) -> None:
    if kind not in APPLICATION_TYPES:
        raise ProtocolError(f"{kind.name} is not an application message type")
