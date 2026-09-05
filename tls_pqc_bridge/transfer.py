import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass

from tls_pqc_bridge.channel import ApplicationChannel
from tls_pqc_bridge.errors import IntegrityError, ProtocolError
from tls_pqc_bridge.protocol import (
    MAX_TRANSFER_BYTES,
    NONCE_SIZE,
    TRANSFER_CHUNK_SIZE,
    TRANSFER_DIGEST_SIZE,
    MessageType,
)


TRANSFER_START = struct.Struct("!Q32s")
TRANSFER_POSITION = struct.Struct("!Q")
TRANSFER_END = struct.Struct("!Q32s")


@dataclass(frozen=True)
class TransferSpec:
    size: int
    seed: bytes

    def __post_init__(self) -> None:
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not 0 <= self.size <= MAX_TRANSFER_BYTES
        ):
            raise ValueError(
                f"transfer size must be an integer between 0 and {MAX_TRANSFER_BYTES}"
            )
        if not isinstance(self.seed, bytes) or len(self.seed) != NONCE_SIZE:
            raise ValueError(f"transfer seed must be {NONCE_SIZE} bytes")


def client_exchange(channel: ApplicationChannel, size: int) -> dict[str, float]:
    token = secrets.token_bytes(NONCE_SIZE)
    ping_started = time.perf_counter_ns()
    channel.send(MessageType.PING, token)
    pong = channel.receive(MessageType.PONG)
    ping_rtt_ms = _elapsed_ms(ping_started)
    if not hmac.compare_digest(pong, token):
        raise IntegrityError("PONG does not match PING")

    transfer = TransferSpec(size, secrets.token_bytes(NONCE_SIZE))
    total_started = time.perf_counter_ns()
    upload_started = time.perf_counter_ns()
    sent_digest = send_transfer(channel, transfer)
    upload_ms = _elapsed_ms(upload_started)

    download_started = time.perf_counter_ns()
    received_transfer, received_digest = receive_transfer(channel)
    download_ms = _elapsed_ms(download_started)
    if received_transfer != transfer or not hmac.compare_digest(
        received_digest, sent_digest
    ):
        raise IntegrityError("server response does not match the uploaded payload")
    channel.send(
        MessageType.TRANSFER_ACK,
        TRANSFER_END.pack(received_transfer.size, received_digest),
    )
    total_ms = _elapsed_ms(total_started)
    return {
        "ping_rtt_ms": ping_rtt_ms,
        "upload_send_ms": upload_ms,
        "download_receive_ms": download_ms,
        "transfer_total_ms": total_ms,
        "throughput_mbps": _throughput_mbps(size, total_ms),
    }


def server_exchange(channel: ApplicationChannel) -> dict[str, float]:
    ping_started = time.perf_counter_ns()
    ping = channel.receive(MessageType.PING)
    if len(ping) != NONCE_SIZE:
        raise ProtocolError(f"PING must be {NONCE_SIZE} bytes")
    channel.send(MessageType.PONG, ping)
    ping_service_ms = _elapsed_ms(ping_started)

    total_started = time.perf_counter_ns()
    upload_started = time.perf_counter_ns()
    transfer, received_digest = receive_transfer(channel)
    upload_ms = _elapsed_ms(upload_started)

    download_started = time.perf_counter_ns()
    sent_digest = send_transfer(channel, transfer)
    download_ms = _elapsed_ms(download_started)
    acknowledgement = channel.receive(MessageType.TRANSFER_ACK)
    acknowledged_size, acknowledged_digest = _parse_end(acknowledgement, "TRANSFER_ACK")
    if acknowledged_size != transfer.size or not hmac.compare_digest(
        acknowledged_digest, sent_digest
    ):
        raise IntegrityError("client did not confirm the returned payload")
    if not hmac.compare_digest(received_digest, sent_digest):
        raise IntegrityError("bidirectional transfer digests differ")
    total_ms = _elapsed_ms(total_started)
    return {
        "ping_service_ms": ping_service_ms,
        "upload_receive_ms": upload_ms,
        "download_send_ms": download_ms,
        "transfer_total_ms": total_ms,
        "throughput_mbps": _throughput_mbps(transfer.size, total_ms),
        "payload_bytes": transfer.size,
    }


def send_transfer(channel: ApplicationChannel, transfer: TransferSpec) -> bytes:
    channel.send(
        MessageType.TRANSFER_START,
        TRANSFER_START.pack(transfer.size, transfer.seed),
    )
    block = _payload_block(transfer.seed)
    digest = hashlib.sha256()
    offset = 0
    while offset < transfer.size:
        chunk = block[: min(TRANSFER_CHUNK_SIZE, transfer.size - offset)]
        digest.update(chunk)
        channel.send_parts(
            MessageType.TRANSFER_DATA,
            (TRANSFER_POSITION.pack(offset), chunk),
        )
        offset += len(chunk)
    value = digest.digest()
    channel.send(MessageType.TRANSFER_END, TRANSFER_END.pack(transfer.size, value))
    return value


def receive_transfer(channel: ApplicationChannel) -> tuple[TransferSpec, bytes]:
    start = channel.receive(MessageType.TRANSFER_START)
    if len(start) != TRANSFER_START.size:
        raise ProtocolError("TRANSFER_START has an invalid length")
    total, seed = TRANSFER_START.unpack(start)
    if total > MAX_TRANSFER_BYTES:
        raise ProtocolError(
            f"transfer declares {total} bytes; maximum is {MAX_TRANSFER_BYTES}"
        )
    transfer = TransferSpec(total, seed)
    block = _payload_block(seed)
    digest = hashlib.sha256()
    offset = 0
    while offset < total:
        payload = channel.receive(MessageType.TRANSFER_DATA)
        expected_chunk_size = min(TRANSFER_CHUNK_SIZE, total - offset)
        if len(payload) != TRANSFER_POSITION.size + expected_chunk_size:
            raise ProtocolError("TRANSFER_DATA has an invalid length")
        received_offset = TRANSFER_POSITION.unpack_from(payload)[0]
        if received_offset != offset:
            raise ProtocolError(
                f"expected transfer offset {offset}, received {received_offset}"
            )
        chunk = payload[TRANSFER_POSITION.size :]
        if chunk != block[:expected_chunk_size]:
            raise IntegrityError(f"payload content differs at offset {offset}")
        digest.update(chunk)
        offset += len(chunk)

    end = channel.receive(MessageType.TRANSFER_END)
    declared_total, declared_digest = _parse_end(end, "TRANSFER_END")
    actual_digest = digest.digest()
    if declared_total != total or not hmac.compare_digest(
        declared_digest, actual_digest
    ):
        raise IntegrityError("transfer terminator does not match received content")
    return transfer, actual_digest


def _payload_block(seed: bytes) -> bytes:
    return hashlib.shake_256(b"QCOMM payload v1\x00" + seed).digest(TRANSFER_CHUNK_SIZE)


def _parse_end(payload: bytes, name: str) -> tuple[int, bytes]:
    if len(payload) != TRANSFER_END.size:
        raise ProtocolError(f"{name} has an invalid length")
    size, digest = TRANSFER_END.unpack(payload)
    if len(digest) != TRANSFER_DIGEST_SIZE:
        raise AssertionError("transfer digest size disagrees with protocol constants")
    return size, digest


def _throughput_mbps(payload_bytes: int, duration_ms: float) -> float:
    if duration_ms <= 0:
        raise RuntimeError("monotonic clock returned a non-positive transfer duration")
    return (2 * payload_bytes * 8) / (duration_ms / 1_000) / 1_000_000


def _elapsed_ms(started_ns: int) -> float:
    return (time.perf_counter_ns() - started_ns) / 1_000_000
