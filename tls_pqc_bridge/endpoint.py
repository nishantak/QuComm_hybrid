import math
import socket
import time
from pathlib import Path

from tls_pqc_bridge.channel import PlainChannel, ProtectedChannel
from tls_pqc_bridge.files import write_json_atomic
from tls_pqc_bridge.framing import FramedTransport
from tls_pqc_bridge.hybrid import client_handshake, server_handshake
from tls_pqc_bridge.identity import (
    CredentialPaths,
    load_pinned_public_key,
    load_server_identity,
    normalize_server_name,
)
from tls_pqc_bridge.protocol import (
    ALPN_IDS,
    MAX_TRANSFER_BYTES,
    MODES,
    TLS_GROUP_BY_MODE,
)
from tls_pqc_bridge.tls import (
    TlsStream,
    create_client_context,
    create_server_context,
    export_classical_secret,
    negotiated_parameters,
    wrap_client,
    wrap_server,
)
from tls_pqc_bridge.transfer import client_exchange, server_exchange


def run_client(
    mode: str,
    host: str,
    port: int,
    server_name: str,
    credentials: Path,
    payload_bytes: int,
    timeout_seconds: float,
) -> dict[str, object]:
    _require_mode(mode)
    _require_host_and_port(host, port, allow_zero=False)
    if (
        isinstance(payload_bytes, bool)
        or not isinstance(payload_bytes, int)
        or not 0 <= payload_bytes <= MAX_TRANSFER_BYTES
    ):
        raise ValueError(f"payload_bytes must be between 0 and {MAX_TRANSFER_BYTES}")
    _require_timeout(timeout_seconds)
    server_name = normalize_server_name(server_name)
    paths = CredentialPaths(credentials.resolve())
    alpn_id = ALPN_IDS[mode]
    tls_group = TLS_GROUP_BY_MODE[mode]
    context = create_client_context(paths.ca_certificate, alpn_id, tls_group)
    pinned_identity = load_pinned_public_key(paths) if mode == "hybrid" else None
    cpu_started = time.process_time_ns()

    tcp_started = time.perf_counter_ns()
    raw_socket = socket.create_connection((host, port), timeout=timeout_seconds)
    tcp_connect_ms = _elapsed_ms(tcp_started)
    raw_socket.settimeout(timeout_seconds)
    raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    stream = None
    try:
        tls_started = time.perf_counter_ns()
        stream = wrap_client(
            context,
            raw_socket,
            server_name,
            timeout_seconds,
            alpn_id,
            tls_group,
        )
        tls_handshake_ms = _elapsed_ms(tls_started)
        connection = stream.connection
        transport = FramedTransport(stream)

        pqc_metrics: dict[str, float] = {}
        if mode == "hybrid":
            exporter_started = time.perf_counter_ns()
            classical_secret = export_classical_secret(connection, server_name)
            exporter_ms = _elapsed_ms(exporter_started)
            handshake = client_handshake(
                transport,
                classical_secret,
                pinned_identity,
                server_name,
            )
            pqc_metrics = {"tls_exporter_ms": exporter_ms, **handshake.metrics}
            channel = ProtectedChannel(transport, handshake.secrets, "client")
        else:
            channel = PlainChannel(transport)

        channel_ready_ms = _elapsed_ms(tcp_started)
        application_sent_start = channel.bytes_sent
        application_received_start = channel.bytes_received
        application_metrics = client_exchange(channel, payload_bytes)
        metrics: dict[str, object] = {
            "success": True,
            "endpoint": "client",
            "mode": mode,
            "payload_bytes": payload_bytes,
            "tcp_connect_ms": tcp_connect_ms,
            "tls_handshake_ms": tls_handshake_ms,
            "pqc_handshake_ms": pqc_metrics.get("pqc_handshake_ms"),
            "channel_ready_ms": channel_ready_ms,
            "handshake_framed_bytes_sent": application_sent_start,
            "handshake_framed_bytes_received": application_received_start,
            "application_framed_bytes_sent": channel.bytes_sent
            - application_sent_start,
            "application_framed_bytes_received": channel.bytes_received
            - application_received_start,
            **negotiated_parameters(connection),
            **pqc_metrics,
            **application_metrics,
            "process_cpu_ms": _process_elapsed_ms(cpu_started),
        }
        return metrics
    finally:
        _close_tls(stream, raw_socket)


def run_server(
    mode: str,
    host: str,
    port: int,
    credentials: Path,
    timeout_seconds: float,
    ready_file: Path,
) -> dict[str, object]:
    _require_mode(mode)
    _require_host_and_port(host, port, allow_zero=True)
    _require_timeout(timeout_seconds)
    paths = CredentialPaths(credentials.resolve())
    alpn_id = ALPN_IDS[mode]
    tls_group = TLS_GROUP_BY_MODE[mode]
    context = create_server_context(
        paths.server_certificate,
        paths.server_private_key,
        alpn_id,
        tls_group,
    )
    identity = load_server_identity(paths) if mode == "hybrid" else None
    cpu_started = time.process_time_ns()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        listener.settimeout(timeout_seconds)
        write_json_atomic(ready_file, {"port": listener.getsockname()[1]})
        raw_socket, _peer = listener.accept()

    raw_socket.settimeout(timeout_seconds)
    raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    stream = None
    try:
        tls_started = time.perf_counter_ns()
        stream = wrap_server(context, raw_socket, timeout_seconds, alpn_id, tls_group)
        tls_handshake_ms = _elapsed_ms(tls_started)
        connection = stream.connection
        transport = FramedTransport(stream)

        pqc_metrics: dict[str, float] = {}
        if mode == "hybrid":
            exporter_started = time.perf_counter_ns()
            classical_secret = export_classical_secret(connection, identity.server_name)
            exporter_ms = _elapsed_ms(exporter_started)
            handshake = server_handshake(transport, classical_secret, identity)
            pqc_metrics = {"tls_exporter_ms": exporter_ms, **handshake.metrics}
            channel = ProtectedChannel(transport, handshake.secrets, "server")
        else:
            channel = PlainChannel(transport)

        channel_ready_ms = _elapsed_ms(tls_started)
        application_sent_start = channel.bytes_sent
        application_received_start = channel.bytes_received
        application_metrics = server_exchange(channel)
        metrics: dict[str, object] = {
            "success": True,
            "endpoint": "server",
            "mode": mode,
            "tls_handshake_ms": tls_handshake_ms,
            "pqc_handshake_ms": pqc_metrics.get("pqc_handshake_ms"),
            "channel_ready_ms": channel_ready_ms,
            "handshake_framed_bytes_sent": application_sent_start,
            "handshake_framed_bytes_received": application_received_start,
            "application_framed_bytes_sent": channel.bytes_sent
            - application_sent_start,
            "application_framed_bytes_received": channel.bytes_received
            - application_received_start,
            **negotiated_parameters(connection),
            **pqc_metrics,
            **application_metrics,
            "process_cpu_ms": _process_elapsed_ms(cpu_started),
        }
        return metrics
    finally:
        _close_tls(stream, raw_socket)


def _require_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")


def _require_host_and_port(host: str, port: int, allow_zero: bool) -> None:
    if not host or "\x00" in host:
        raise ValueError("host must be a non-empty address without null bytes")
    minimum = 0 if allow_zero else 1
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not minimum <= port <= 65535
    ):
        raise ValueError(f"port must be between {minimum} and 65535")


def _require_timeout(timeout_seconds: float) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be finite and positive")


def _close_tls(stream: TlsStream | None, raw_socket: socket.socket) -> None:
    if stream is not None:
        stream.close()
    else:
        raw_socket.close()


def _elapsed_ms(started_ns: int) -> float:
    return (time.perf_counter_ns() - started_ns) / 1_000_000


def _process_elapsed_ms(started_ns: int) -> float:
    return (time.process_time_ns() - started_ns) / 1_000_000
