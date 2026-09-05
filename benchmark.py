import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, median, stdev

from OpenSSL import SSL as openssl_ssl
from scipy.stats import t

from tls_pqc_bridge.channel import RECORD_PREFIX
from tls_pqc_bridge.files import write_json_atomic
from tls_pqc_bridge.framing import HEADER, MAX_PAYLOAD_BY_TYPE
from tls_pqc_bridge.identity import (
    CredentialPaths,
    load_server_name,
    normalize_server_name,
)
from tls_pqc_bridge.protocol import (
    ALPN_IDS,
    MAX_TRANSFER_BYTES,
    MODES,
    RECORD_TAG_SIZE,
    TLS_GROUP_BY_MODE,
    TRANSFER_CHUNK_SIZE,
    MessageType,
)
from tls_pqc_bridge.tls import ALLOWED_TLS13_CIPHERS


DEFAULT_SIZES = (1024, 100 * 1024, 1024**2, 100 * 1024**2, 500 * 1024**2, 1024**3)
DEFAULT_SEED = 0xC0FFEE
MODE_LABELS = {
    "baseline": "Classical TLS",
    "native": "Native hybrid TLS",
    "hybrid": "TLS + PQC bridge",
}
PAIRED_MODE_COMPARISONS = (
    ("baseline", "native"),
    ("baseline", "hybrid"),
    ("native", "hybrid"),
)
MEASUREMENTS = (
    "tcp_connect_ms",
    "tls_handshake_ms",
    "tls_exporter_ms",
    "pqc_handshake_ms",
    "pqc_kem_keygen_ms",
    "pqc_signature_sign_ms",
    "pqc_signature_verify_ms",
    "pqc_encapsulation_ms",
    "pqc_decapsulation_ms",
    "pqc_kdf_ms",
    "channel_ready_ms",
    "ping_rtt_ms",
    "ping_service_ms",
    "upload_send_ms",
    "upload_receive_ms",
    "download_send_ms",
    "download_receive_ms",
    "transfer_total_ms",
    "throughput_mbps",
    "process_cpu_ms",
    "handshake_framed_bytes_sent",
    "handshake_framed_bytes_received",
    "application_framed_bytes_sent",
    "application_framed_bytes_received",
)
RUN_FIELDS = (
    "success",
    "mode",
    "payload_bytes",
    "error_type",
    "error",
    "completed_utc",
    "execution_order",
    "repetition",
    "run_id",
)
ENDPOINT_FIELDS = (
    "success",
    "endpoint",
    "mode",
    "payload_bytes",
    "tls_version",
    "tls_cipher",
    "tls_group",
    "alpn",
    "error_type",
    "error",
    *MEASUREMENTS,
)
FLAT_RUN_FIELDS = RUN_FIELDS + tuple(
    f"{endpoint}_{field}"
    for endpoint in ("client", "server")
    for field in ENDPOINT_FIELDS
)
COMMON_ENDPOINT_MEASUREMENTS = {
    "client": {
        "tcp_connect_ms",
        "tls_handshake_ms",
        "channel_ready_ms",
        "ping_rtt_ms",
        "upload_send_ms",
        "download_receive_ms",
        "transfer_total_ms",
        "throughput_mbps",
        "process_cpu_ms",
        "handshake_framed_bytes_sent",
        "handshake_framed_bytes_received",
        "application_framed_bytes_sent",
        "application_framed_bytes_received",
    },
    "server": {
        "tls_handshake_ms",
        "channel_ready_ms",
        "ping_service_ms",
        "upload_receive_ms",
        "download_send_ms",
        "transfer_total_ms",
        "throughput_mbps",
        "process_cpu_ms",
        "handshake_framed_bytes_sent",
        "handshake_framed_bytes_received",
        "application_framed_bytes_sent",
        "application_framed_bytes_received",
    },
}
HYBRID_ENDPOINT_MEASUREMENTS = {
    "client": {
        "tls_exporter_ms",
        "pqc_handshake_ms",
        "pqc_signature_verify_ms",
        "pqc_encapsulation_ms",
        "pqc_kdf_ms",
    },
    "server": {
        "tls_exporter_ms",
        "pqc_handshake_ms",
        "pqc_kem_keygen_ms",
        "pqc_signature_sign_ms",
        "pqc_decapsulation_ms",
        "pqc_kdf_ms",
    },
}
BYTE_MEASUREMENTS = {
    "handshake_framed_bytes_sent",
    "handshake_framed_bytes_received",
    "application_framed_bytes_sent",
    "application_framed_bytes_received",
}


def run_benchmark(
    output: Path,
    credentials: Path,
    server_name: str,
    sizes: tuple[int, ...],
    runs: int,
    warmups: int,
    seed: int,
    timeout_seconds: float,
) -> int:
    _validate_plan(sizes, runs, warmups, timeout_seconds)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    credentials = credentials.resolve()
    server_name = normalize_server_name(server_name)
    configured_name = load_server_name(CredentialPaths(credentials))
    if server_name != configured_name:
        raise ValueError(
            f"server_name {server_name!r} does not match credential identity "
            f"{configured_name!r}"
        )
    output = output.resolve()
    manifest = _environment_manifest(
        credentials,
        server_name,
        sizes,
        runs,
        warmups,
        seed,
        timeout_seconds,
    )
    output.mkdir(parents=True, exist_ok=False)
    write_json_atomic(output / "manifest.json", manifest)

    rng = random.Random(seed)
    warmup_size = min(max(sizes), 1024**2)
    for warmup_index in range(warmups):
        modes = list(MODES)
        rng.shuffle(modes)
        for mode in modes:
            row = _run_connection(
                mode,
                warmup_size,
                f"warmup-{warmup_index + 1}-{mode}",
                credentials,
                server_name,
                timeout_seconds,
                output,
            )
            if not row["success"]:
                _write_table_csv(output / "warmup-failure.csv", [_flatten_run(row)])
                _write_status_csv(
                    output / "status.csv", 0, 0, 0, False, warmup_failed=True
                )
                raise RuntimeError(f"warm-up failed: {row['error']}")

    rows: list[dict[str, object]] = []
    execution_order = 0
    for repetition in range(1, runs + 1):
        conditions = [(mode, size) for size in sizes for mode in MODES]
        rng.shuffle(conditions)
        for mode, size in conditions:
            execution_order += 1
            run_id = f"{execution_order:04d}-{mode}-{size}-r{repetition}"
            row = _run_connection(
                mode,
                size,
                run_id,
                credentials,
                server_name,
                timeout_seconds,
                output,
            )
            row.update(
                {
                    "completed_utc": datetime.now(UTC).isoformat(),
                    "execution_order": execution_order,
                    "repetition": repetition,
                    "run_id": run_id,
                }
            )
            rows.append(row)
            _append_run_csv(output / "runs.csv", row)

    summary = _summarize(rows, sizes)
    _write_summary_csv(output / "summary.csv", summary)
    comparisons = _paired_comparisons(rows, sizes)
    _write_table_csv(output / "paired-comparisons.csv", comparisons)
    failures = [row for row in rows if not row["success"]]
    _write_status_csv(
        output / "status.csv",
        len(rows),
        len(failures),
        len(rows) - len(failures),
        not failures,
    )
    return len(failures)


def _run_connection(
    mode: str,
    payload_bytes: int,
    run_id: str,
    credentials: Path,
    server_name: str,
    timeout_seconds: float,
    output: Path,
) -> dict[str, object]:
    project_root = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix=f"{run_id}-", dir=output) as run_dir_name:
        run_dir = Path(run_dir_name)
        ready_file = run_dir / "ready.json"
        server_result = run_dir / "server.json"
        client_result = run_dir / "client.json"
        server_command = [
            sys.executable,
            str(project_root / "bob.py"),
            "--mode",
            mode,
            "--credentials",
            str(credentials),
            "--timeout-seconds",
            str(timeout_seconds),
            "--ready-file",
            str(ready_file),
            "--result-file",
            str(server_result),
        ]
        server = subprocess.Popen(
            server_command,
            cwd=project_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            port = _wait_for_server(server, ready_file, 15.0)
            client_command = [
                sys.executable,
                str(project_root / "alice.py"),
                "--mode",
                mode,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--server-name",
                server_name,
                "--credentials",
                str(credentials),
                "--payload-bytes",
                str(payload_bytes),
                "--timeout-seconds",
                str(timeout_seconds),
                "--result-file",
                str(client_result),
            ]
            try:
                client = subprocess.run(
                    client_command,
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds + 15.0,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                return _failed_row(
                    mode, payload_bytes, "client timeout", str(error), None, None
                )
            try:
                _server_stdout, server_stderr = server.communicate(
                    timeout=timeout_seconds + 15.0
                )
            except subprocess.TimeoutExpired as error:
                return _failed_row(
                    mode,
                    payload_bytes,
                    "server timeout",
                    str(error),
                    _read_result(client_result),
                    None,
                )

            client_metrics = _read_result(client_result)
            server_metrics = _read_result(server_result)
            success = (
                client.returncode == 0
                and server.returncode == 0
                and bool(client_metrics and client_metrics.get("success"))
                and bool(server_metrics and server_metrics.get("success"))
            )
            if not success:
                error = " | ".join(
                    part
                    for part in (
                        client.stderr.strip(),
                        server_stderr.strip(),
                        _result_error(client_metrics),
                        _result_error(server_metrics),
                    )
                    if part
                )
                return _failed_row(
                    mode,
                    payload_bytes,
                    "endpoint failure",
                    error,
                    client_metrics,
                    server_metrics,
                )
            _validate_successful_pair(
                client_metrics, server_metrics, mode, payload_bytes
            )
            return {
                "success": True,
                "mode": mode,
                "payload_bytes": payload_bytes,
                "client": client_metrics,
                "server": server_metrics,
                "error": None,
                "error_type": None,
            }
        except Exception as error:
            return _failed_row(
                mode,
                payload_bytes,
                type(error).__name__,
                str(error),
                _read_result(client_result),
                _read_result(server_result),
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                server.communicate()


def _validate_successful_pair(
    client: dict[str, object],
    server: dict[str, object],
    mode: str,
    payload_bytes: int,
) -> None:
    for endpoint, result in (("client", client), ("server", server)):
        expected_identity = {
            "success": True,
            "endpoint": endpoint,
            "mode": mode,
            "payload_bytes": payload_bytes,
            "tls_version": "TLSv1.3",
            "tls_group": TLS_GROUP_BY_MODE[mode],
            "alpn": ALPN_IDS[mode].decode("ascii"),
        }
        for field, expected in expected_identity.items():
            if result.get(field) != expected:
                raise ValueError(
                    f"{endpoint} result field {field} is {result.get(field)!r}; "
                    f"expected {expected!r}"
                )
        if result.get("tls_cipher") not in ALLOWED_TLS13_CIPHERS:
            raise ValueError(f"{endpoint} result has an invalid TLS 1.3 cipher")

        required = COMMON_ENDPOINT_MEASUREMENTS[endpoint]
        if mode == "hybrid":
            required = required | HYBRID_ENDPOINT_MEASUREMENTS[endpoint]
        for field in required:
            value = result.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{endpoint} result field {field} is not numeric")
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"{endpoint} result field {field} must be finite and nonnegative"
                )
            if field in BYTE_MEASUREMENTS and not isinstance(value, int):
                raise ValueError(f"{endpoint} result field {field} must be an integer")

        unexpected = sorted(
            field
            for field in MEASUREMENTS
            if field not in required and result.get(field) is not None
        )
        if unexpected:
            raise ValueError(
                f"{endpoint} result contains inapplicable measurements: "
                f"{', '.join(unexpected)}"
            )

        measured_components_ms = float(result["tls_handshake_ms"])
        if endpoint == "client":
            measured_components_ms += float(result["tcp_connect_ms"])
        if mode == "hybrid":
            measured_components_ms += float(result["tls_exporter_ms"])
            measured_components_ms += float(result["pqc_handshake_ms"])
            pqc_operations_ms = sum(
                float(result[field])
                for field in HYBRID_ENDPOINT_MEASUREMENTS[endpoint]
                if field not in {"tls_exporter_ms", "pqc_handshake_ms"}
            )
            if float(result["pqc_handshake_ms"]) + 1e-9 < pqc_operations_ms:
                raise ValueError(f"{endpoint} PQC component timings are inconsistent")
        if float(result["channel_ready_ms"]) + 1e-9 < measured_components_ms:
            raise ValueError(f"{endpoint} channel-ready timing is inconsistent")

        transfer_ms = float(result["transfer_total_ms"])
        expected_throughput = (
            (2 * payload_bytes * 8) / (transfer_ms / 1_000) / 1_000_000
        )
        if not math.isclose(
            float(result["throughput_mbps"]), expected_throughput, rel_tol=1e-12
        ):
            raise ValueError(
                f"{endpoint} throughput is inconsistent with transfer time"
            )
        transfer_components = {
            "client": ("upload_send_ms", "download_receive_ms"),
            "server": ("upload_receive_ms", "download_send_ms"),
        }[endpoint]
        measured_transfer_ms = sum(
            float(result[field]) for field in transfer_components
        )
        if transfer_ms + 1e-9 < measured_transfer_ms:
            raise ValueError(f"{endpoint} transfer component timings are inconsistent")

    if client["tls_cipher"] != server["tls_cipher"]:
        raise ValueError("Alice and Bob report different TLS cipher suites")
    if client["tls_group"] != server["tls_group"]:
        raise ValueError("Alice and Bob report different TLS key-exchange groups")
    for sent_by, received_by, direction in (
        (client, server, "Alice-to-Bob"),
        (server, client, "Bob-to-Alice"),
    ):
        for phase in ("handshake", "application"):
            if (
                sent_by[f"{phase}_framed_bytes_sent"]
                != received_by[f"{phase}_framed_bytes_received"]
            ):
                raise ValueError(f"{direction} {phase} byte counters disagree")
    expected_handshake = _expected_handshake_bytes(mode)
    expected_application = _expected_application_bytes(mode, payload_bytes)
    for endpoint, result in (("client", client), ("server", server)):
        for direction in ("sent", "received"):
            if (
                result[f"handshake_framed_bytes_{direction}"]
                != expected_handshake[endpoint, direction]
            ):
                raise ValueError(
                    f"{endpoint} {direction} handshake bytes disagree with framing"
                )
            if (
                result[f"application_framed_bytes_{direction}"]
                != expected_application[endpoint, direction]
            ):
                raise ValueError(
                    f"{endpoint} {direction} application bytes disagree with framing"
                )


def _expected_handshake_bytes(mode: str) -> dict[tuple[str, str], int]:
    if mode != "hybrid":
        return {
            (endpoint, direction): 0
            for endpoint in ("client", "server")
            for direction in ("sent", "received")
        }
    client_sent = sum(
        HEADER.size + MAX_PAYLOAD_BY_TYPE[kind]
        for kind in (MessageType.CLIENT_KEM, MessageType.CLIENT_FINISHED)
    )
    server_sent = sum(
        HEADER.size + MAX_PAYLOAD_BY_TYPE[kind]
        for kind in (MessageType.SERVER_INIT, MessageType.SERVER_FINISHED)
    )
    return {
        ("client", "sent"): client_sent,
        ("client", "received"): server_sent,
        ("server", "sent"): server_sent,
        ("server", "received"): client_sent,
    }


def _expected_application_bytes(
    mode: str, payload_bytes: int
) -> dict[tuple[str, str], int]:
    chunks = math.ceil(payload_bytes / TRANSFER_CHUNK_SIZE)
    record_overhead = HEADER.size
    if mode == "hybrid":
        record_overhead += RECORD_PREFIX.size + RECORD_TAG_SIZE
    transfer_payload = (
        MAX_PAYLOAD_BY_TYPE[MessageType.TRANSFER_START]
        + payload_bytes
        + 8 * chunks
        + MAX_PAYLOAD_BY_TYPE[MessageType.TRANSFER_END]
    )
    client_sent = (
        MAX_PAYLOAD_BY_TYPE[MessageType.PING]
        + transfer_payload
        + MAX_PAYLOAD_BY_TYPE[MessageType.TRANSFER_ACK]
        + record_overhead * (chunks + 4)
    )
    server_sent = (
        MAX_PAYLOAD_BY_TYPE[MessageType.PONG]
        + transfer_payload
        + record_overhead * (chunks + 3)
    )
    return {
        ("client", "sent"): client_sent,
        ("client", "received"): server_sent,
        ("server", "sent"): server_sent,
        ("server", "received"): client_sent,
    }


def _wait_for_server(
    server: subprocess.Popen[str], ready_file: Path, timeout_seconds: float
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if ready_file.exists():
            try:
                value = json.loads(ready_file.read_text(encoding="utf-8"))
            except OSError:
                time.sleep(0.01)
                continue
            port = value.get("port")
            if isinstance(port, int) and 1 <= port <= 65535:
                return port
            raise RuntimeError("server readiness file has an invalid port")
        if server.poll() is not None:
            stderr = server.stderr.read() if server.stderr else ""
            raise RuntimeError(f"server exited before readiness: {stderr.strip()}")
        time.sleep(0.01)
    raise TimeoutError("server did not become ready within 15 seconds")


def _failed_row(
    mode: str,
    payload_bytes: int,
    error_type: str,
    error: str,
    client: dict[str, object] | None,
    server: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "success": False,
        "mode": mode,
        "payload_bytes": payload_bytes,
        "client": client,
        "server": server,
        "error_type": error_type,
        "error": error,
    }


def _read_result(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _result_error(result: dict[str, object] | None) -> str:
    if not result or result.get("success"):
        return ""
    return f"{result.get('endpoint', 'endpoint')}: {result.get('error_type')}: {result.get('error')}"


def _summarize(
    rows: list[dict[str, object]], sizes: tuple[int, ...]
) -> list[dict[str, object]]:
    summary: list[dict[str, object]] = []
    for mode in MODES:
        for payload_bytes in sizes:
            selected = [
                row
                for row in rows
                if row["mode"] == mode
                and row["payload_bytes"] == payload_bytes
                and row["success"]
            ]
            attempted = sum(
                row["mode"] == mode and row["payload_bytes"] == payload_bytes
                for row in rows
            )
            for endpoint in ("client", "server"):
                for metric in MEASUREMENTS:
                    values = [
                        float(row[endpoint][metric])
                        for row in selected
                        if isinstance(row.get(endpoint), dict)
                        and isinstance(row[endpoint].get(metric), (int, float))
                    ]
                    if values:
                        summary.append(
                            {
                                "mode": mode,
                                "payload_bytes": payload_bytes,
                                "endpoint": endpoint,
                                "metric": metric,
                                "attempted": attempted,
                                "n": len(values),
                                **_descriptive_statistics(values),
                            }
                        )
    return summary


def _descriptive_statistics(values: list[float]) -> dict[str, float | None]:
    average = mean(values)
    if len(values) == 1:
        standard_deviation = None
        lower = None
        upper = None
    else:
        standard_deviation = stdev(values)
        margin = (
            t.ppf(0.975, len(values) - 1) * standard_deviation / math.sqrt(len(values))
        )
        lower = average - margin
        upper = average + margin
    return {
        "mean": average,
        "median": median(values),
        "standard_deviation": standard_deviation,
        "ci95_low": lower,
        "ci95_high": upper,
        "minimum": min(values),
        "maximum": max(values),
    }


def _paired_comparisons(
    rows: list[dict[str, object]], sizes: tuple[int, ...]
) -> list[dict[str, object]]:
    comparisons: list[dict[str, object]] = []
    for payload_bytes in sizes:
        indexed = {
            (int(row["repetition"]), str(row["mode"])): row
            for row in rows
            if row["payload_bytes"] == payload_bytes and row["success"]
        }
        for reference_mode, candidate_mode in PAIRED_MODE_COMPARISONS:
            repetitions = sorted(
                {
                    repetition
                    for repetition, _mode in indexed
                    if (repetition, reference_mode) in indexed
                    and (repetition, candidate_mode) in indexed
                }
            )
            for endpoint in ("client", "server"):
                for metric in MEASUREMENTS:
                    differences: list[float] = []
                    relative_changes: list[float] = []
                    for repetition in repetitions:
                        reference = indexed[repetition, reference_mode]
                        candidate = indexed[repetition, candidate_mode]
                        reference_value = reference[endpoint].get(metric)
                        candidate_value = candidate[endpoint].get(metric)
                        if not isinstance(
                            reference_value, (int, float)
                        ) or not isinstance(candidate_value, (int, float)):
                            continue
                        reference_number = float(reference_value)
                        candidate_number = float(candidate_value)
                        differences.append(candidate_number - reference_number)
                        if reference_number != 0:
                            relative_changes.append(
                                100
                                * (candidate_number - reference_number)
                                / reference_number
                            )
                    if differences:
                        row: dict[str, object] = {
                            "reference_mode": reference_mode,
                            "candidate_mode": candidate_mode,
                            "payload_bytes": payload_bytes,
                            "endpoint": endpoint,
                            "metric": metric,
                            "paired_n": len(differences),
                        }
                        row.update(
                            {
                                f"difference_{key}": value
                                for key, value in _descriptive_statistics(
                                    differences
                                ).items()
                            }
                        )
                        row["relative_paired_n"] = len(relative_changes)
                        if len(relative_changes) >= 2:
                            row.update(
                                {
                                    f"relative_percent_{key}": value
                                    for key, value in _descriptive_statistics(
                                        relative_changes
                                    ).items()
                                }
                            )
                        comparisons.append(row)
    return comparisons


def _append_run_csv(path: Path, row: dict[str, object]) -> None:
    write_header = not path.exists()
    with path.open("a", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=FLAT_RUN_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(_flatten_run(row))
        output.flush()
        os.fsync(output.fileno())


def _flatten_run(row: dict[str, object]) -> dict[str, object]:
    flattened = {
        key: value for key, value in row.items() if key not in {"client", "server"}
    }
    for endpoint in ("client", "server"):
        metrics = row.get(endpoint)
        if isinstance(metrics, dict):
            flattened.update(
                {f"{endpoint}_{key}": value for key, value in metrics.items()}
            )
    return flattened


def _write_summary_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fields = (
        list(rows[0])
        if rows
        else [
            "mode",
            "payload_bytes",
            "endpoint",
            "metric",
            "attempted",
            "n",
            "mean",
            "median",
            "standard_deviation",
            "ci95_low",
            "ci95_high",
            "minimum",
            "maximum",
        ]
    )
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_table_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = sorted({field for row in rows for field in row})
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_status_csv(
    path: Path,
    attempted: int,
    failed: int,
    successful: int,
    valid: bool,
    *,
    warmup_failed: bool = False,
) -> None:
    _write_table_csv(
        path,
        [
            {
                "attempted_runs": attempted,
                "failed_runs": failed,
                "successful_runs": successful,
                "valid": valid,
                "warmup_failed": warmup_failed,
            }
        ],
    )


def _validate_plan(
    sizes: tuple[int, ...], runs: int, warmups: int, timeout_seconds: float
) -> None:
    if (
        not sizes
        or any(isinstance(size, bool) or not isinstance(size, int) for size in sizes)
        or len(set(sizes)) != len(sizes)
    ):
        raise ValueError("sizes must be a non-empty sequence of unique values")
    if any(size <= 0 or size > MAX_TRANSFER_BYTES for size in sizes):
        raise ValueError(f"each size must be between 1 and {MAX_TRANSFER_BYTES}")
    if isinstance(runs, bool) or not isinstance(runs, int) or runs < 2:
        raise ValueError("at least two measured runs are required")
    if isinstance(warmups, bool) or not isinstance(warmups, int) or warmups < 1:
        raise ValueError("at least one warm-up per mode is required")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be finite and positive")


def _environment_manifest(
    credentials: Path,
    server_name: str,
    sizes: tuple[int, ...],
    runs: int,
    warmups: int,
    seed: int,
    timeout_seconds: float,
) -> dict[str, object]:
    packages = sorted(
        (
            distribution.metadata["Name"],
            distribution.version,
        )
        for distribution in importlib.metadata.distributions()
        if distribution.metadata["Name"]
    )
    project_root = Path(__file__).resolve().parent
    source_files, source_tree_hash = _source_fingerprints(project_root)
    commit = _git_output(project_root, "rev-parse", "HEAD")
    status = _git_output(project_root, "status", "--porcelain")
    return {
        "created_utc": datetime.now(UTC).isoformat(),
        "benchmark": {
            "modes": list(MODES),
            "mode_labels": MODE_LABELS,
            "tls_group_by_mode": TLS_GROUP_BY_MODE,
            "paired_mode_comparisons": [list(pair) for pair in PAIRED_MODE_COMPARISONS],
            "runs_per_condition": runs,
            "warmups_per_mode": warmups,
            "payload_sizes_bytes": list(sizes),
            "randomization_seed": seed,
            "timeout_seconds": timeout_seconds,
            "network": "TCP over IPv4 loopback; no network emulation",
            "server_name": server_name,
        },
        "credentials": {
            "ca_certificate_sha256": _file_sha256(credentials / "ca-cert.pem"),
            "server_certificate_sha256": _file_sha256(credentials / "server-cert.pem"),
            "mldsa_public_key_sha256": _file_sha256(
                credentials / "server-mldsa65-public.bin"
            ),
        },
        "environment": {
            "logical_cpu_count": os.cpu_count(),
            "machine": platform.machine(),
            "operating_system": platform.platform(),
            "processor": platform.processor(),
            "python": sys.version,
            "pyopenssl_ssl": openssl_ssl.SSLeay_version(
                openssl_ssl.SSLEAY_VERSION
            ).decode("ascii"),
            "python_ssl": ssl.OPENSSL_VERSION,
            "packages": dict(packages),
        },
        "repository": {
            "commit": commit,
            "dirty": None if status is None else bool(status),
            "source_files_sha256": source_files,
            "source_tree_sha256": source_tree_hash,
        },
    }


def _source_fingerprints(project_root: Path) -> tuple[dict[str, str], str]:
    paths = list((project_root / "tls_pqc_bridge").glob("*.py"))
    paths.extend(
        project_root / name
        for name in (
            "alice.py",
            "benchmark.py",
            "bob.py",
            "plot.py",
            "requirements.txt",
        )
    )
    paths.sort(key=lambda path: path.relative_to(project_root).as_posix())
    fingerprints: dict[str, str] = {}
    tree = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(project_root).as_posix()
        fingerprint = _file_sha256(path)
        fingerprints[relative] = fingerprint
        tree.update(len(relative).to_bytes(4, "big"))
        tree.update(relative.encode("utf-8"))
        tree.update(bytes.fromhex(fingerprint))
    return fingerprints, tree.hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_output(directory: Path, *arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=directory,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run randomized, process-isolated TLS-PQC Bridge measurements"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--size", type=int, action="append", dest="sizes")
    parser.add_argument("--runs", type=int, default=16)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    arguments = parser.parse_args()
    failures = run_benchmark(
        arguments.output,
        arguments.credentials.resolve(),
        arguments.server_name,
        tuple(arguments.sizes or DEFAULT_SIZES),
        arguments.runs,
        arguments.warmups,
        arguments.seed,
        arguments.timeout_seconds,
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
