import argparse
import json
import os
import subprocess
import sys
import time
from typing import Dict, List, Any


LOGS_DIR = os.path.join(os.getcwd(), "logs")
LOG_DIR_DIR = os.path.join(LOGS_DIR, "log")
SERVER_DIR = os.path.join(LOGS_DIR, "server")
CLIENT_DIR = os.path.join(LOGS_DIR, "client")


def ensure_logs_dir() -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR_DIR, exist_ok=True)
    os.makedirs(SERVER_DIR, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)


def append_log(message: str) -> None:
    ensure_logs_dir()
    try:
        with open(os.path.join(LOG_DIR_DIR, "benchmark.log"), "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {message}\n")
    except Exception:
        pass


def run_server_get_proc(host: str, port: int, tls_version: str, ciphers: str, cert: str, key: str, payload_bytes: int, use_hybrid: bool = False) -> subprocess.Popen:
    python_exe = sys.executable
    cmd = [
        python_exe,
        "bob.py",
        "--host",
        host,
        "--port",
        str(port),
        "--tls",
        tls_version,
        "--ciphers",
        ciphers,
        "--cert",
        cert,
        "--key",
        key,
        "--bytes",
        str(payload_bytes),
    ]
    if use_hybrid:
        cmd.append("--hybrid")
    
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Wait for readiness line
    assert proc.stdout is not None
    start_wait = time.time()
    while True:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                append_log("Server exited before readiness")
                raise RuntimeError("Server exited before readiness")
            if time.time() - start_wait > 20:
                append_log("Timed out waiting for server readiness")
                raise TimeoutError("Timed out waiting for server readiness")
            continue
        if "SERVER_READY" in line or "HYBRID_SERVER_READY" in line or "SIMPLE_HYBRID_SERVER_READY" in line or "POST_QUANTUM_HYBRID_SERVER_READY" in line or "SIMULATED_POST_QUANTUM_HYBRID_SERVER_READY" in line or "REAL_POST_QUANTUM_HYBRID_SERVER_READY" in line:
            append_log("Server ready detected")
            break
    return proc


def run_client(host: str, port: int, tls_version: str, ciphers: str, cafile: str, payload_bytes: int, use_hybrid: bool = False) -> None:
    python_exe = sys.executable
    cmd = [
        python_exe,
        "alice.py",
        "--host",
        host,
        "--port",
        str(port),
        "--tls",
        tls_version,
        "--ciphers",
        ciphers,
        "--cafile",
        cafile,
        "--bytes",
        str(payload_bytes),
    ]
    if use_hybrid:
        cmd.append("--hybrid")
    
    append_log(f"Running client: {cmd}")
    subprocess.run(cmd, check=True)


def aggregate_results_in_memory() -> Dict[str, Any]:
    combined: Dict[str, Any] = {}
    server_file = os.path.join(SERVER_DIR, "server_metrics.json")
    client_file = os.path.join(CLIENT_DIR, "client_metrics.json")
    if os.path.exists(server_file):
        with open(server_file, "r", encoding="utf-8") as f:
            combined["server"] = json.load(f)
    if os.path.exists(client_file):
        with open(client_file, "r", encoding="utf-8") as f:
            combined["client"] = json.load(f)
    return combined


def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else float('nan')


def _std(values: List[float]) -> float:
    n = len(values)
    if n <= 1:
        return 0.0
    m = _mean(values)
    var = sum((v - m) ** 2 for v in values) / (n - 1)
    return var ** 0.5


def compute_stats(all_runs: List[Dict[str, Any]], stats_path: str) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"versions": []}
    for entry in all_runs:
        tls_version = entry.get("tls_version")
        runs = entry.get("runs", [])
        # collect numeric fields separately for client and server
        server_fields: Dict[str, List[float]] = {}
        client_fields: Dict[str, List[float]] = {}
        success_count = 0
        for run in runs:
            server = run.get("server", {})
            client = run.get("client", {})
            if client.get("success") and server.get("success", True):
                success_count += 1
            for k, v in server.items():
                if _is_number(v):
                    server_fields.setdefault(k, []).append(float(v))
            for k, v in client.items():
                if _is_number(v):
                    client_fields.setdefault(k, []).append(float(v))
        server_stats = {k: {"mean": _mean(vals), "std": _std(vals), "n": len(vals)} for k, vals in server_fields.items()}
        client_stats = {k: {"mean": _mean(vals), "std": _std(vals), "n": len(vals)} for k, vals in client_fields.items()}
        version_summary = {
            "tls_version": tls_version,
            "runs": len(runs),
            "success_rate": success_count / len(runs) if runs else 0.0,
            "server_stats": server_stats,
            "client_stats": client_stats,
        }
        summary["versions"].append(version_summary)
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark orchestrator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=44330)
    parser.add_argument("--tls", choices=["1.2", "1.3"], nargs="+", default=["1.3"])
    parser.add_argument("--ciphers", default="AESGCM:CHACHA20:AES256:AES128")
    parser.add_argument("--cert", default="server_cert.pem")
    parser.add_argument("--key", default="server_key.pem")
    parser.add_argument("--bytes", type=int, default=1024 * 1024)
    parser.add_argument("--runs", type=int, default=1, help="Number of runs per TLS version")
    parser.add_argument("--hybrid", action="store_true", help="Use hybrid quantum-safe TLS")
    parser.add_argument("--export-csv-only", action="store_true", help="Export CSVs from existing logs without rerunning")
    return parser.parse_args()


def main() -> None:
    ensure_logs_dir()
    args = parse_args()
    all_runs = []

    if args.export_csv_only:
        # Only export stats.csv from existing stats.json
        stats_path_existing = os.path.join(LOGS_DIR, "stats.json")
        existing_summary = None
        if os.path.exists(stats_path_existing):
            with open(stats_path_existing, "r", encoding="utf-8") as f:
                existing_summary = json.load(f)
        export_csvs([], existing_summary)
        if existing_summary:
            write_text_summary(existing_summary, os.path.join(LOGS_DIR, "summary.txt"))
        return

    for tls_version in args.tls:
        run_results = []
        for i in range(args.runs):
            server_proc = None
            try:
                tls_type = "Hybrid" if args.hybrid else "Classical"
                append_log(f"Starting {tls_type} server for TLS {tls_version} run {i+1}/{args.runs}")
                server_proc = run_server_get_proc(
                    host=args.host,
                    port=args.port,
                    tls_version=tls_version,
                    ciphers=args.ciphers,
                    cert=args.cert,
                    key=args.key,
                    payload_bytes=args.bytes,
                    use_hybrid=args.hybrid,
                )
                run_client(
                    host=args.host,
                    port=args.port,
                    tls_version=tls_version,
                    ciphers=args.ciphers,
                    cafile=args.cert,
                    payload_bytes=args.bytes,
                    use_hybrid=args.hybrid,
                )
                combined = aggregate_results_in_memory()
                run_results.append(combined)
            finally:
                if server_proc is not None:
                    try:
                        server_proc.terminate()
                        server_proc.wait(timeout=5)
                    except Exception:
                        try:
                            server_proc.kill()
                        except Exception:
                            pass
        tls_type = "hybrid" if args.hybrid else "classical"
        all_runs.append({"tls_version": f"{tls_version}_{tls_type}", "runs": run_results})

    # Combined results are kept in-memory only (no file persisted)

    # Compute and save stats
    stats_path = os.path.join(LOGS_DIR, "stats.json")
    summary = compute_stats(all_runs, stats_path)
    # Print concise summary to stdout
    for v in summary.get("versions", []):
        print(f"TLS {v['tls_version']} runs={v['runs']} success_rate={v['success_rate']:.2f}")
        
        # Client metrics
        client_stats = v.get("client_stats", {})
        if client_stats:
            print("  CLIENT METRICS:")
            for metric in ["handshake_time_ms", "rtt_ms", "end_to_end_transfer_time_ms", "throughput_bytes_per_sec"]:
                stat = client_stats.get(metric)
                if stat:
                    print(f"    {metric}: {stat['mean']:.6f} +- {stat['std']:.6f}")
        
        # Server metrics
        server_stats = v.get("server_stats", {})
        if server_stats:
            print("  SERVER METRICS:")
            for metric in ["handshake_time_ms", "transfer_duration_ms", "throughput_bytes_per_sec"]:
                stat = server_stats.get(metric)
                if stat:
                    print(f"    {metric}: {stat['mean']:.6f} +- {stat['std']:.6f}")
        print("")

    # Also export CSVs
    export_csvs(all_runs, summary)
    # And write a human-readable text summary file mirroring terminal output
    write_text_summary(summary, os.path.join(LOGS_DIR, "summary.txt"))


# (no helper flatten needed)


def export_csvs(all_runs: List[Dict[str, Any]], summary: Dict[str, Any] | None) -> None:
    import csv
    ensure_logs_dir()
    # Combined runs CSV (one row per run per TLS version)
    combined_rows: List[Dict[str, Any]] = []
    client_rows: List[Dict[str, Any]] = []
    server_rows: List[Dict[str, Any]] = []
    for version_entry in all_runs:
        tls_version = version_entry.get("tls_version")
        runs = version_entry.get("runs", [])
        for idx, run in enumerate(runs):
            server = run.get("server", {})
            client = run.get("client", {})
            base = {"tls_version": tls_version, "run_index": idx + 1}
            combined = dict(base)
            for k, v in client.items():
                combined[f"client.{k}"] = v
            for k, v in server.items():
                combined[f"server.{k}"] = v
            combined_rows.append(combined)

            cr = dict(base)
            for k, v in client.items():
                cr[k] = v
            client_rows.append(cr)

            sr = dict(base)
            for k, v in server.items():
                sr[k] = v
            server_rows.append(sr)

    def _write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            with open(path, "w", newline="", encoding="utf-8") as f:
                f.write("")
            return
        # gather union headers
        headers: List[str] = []
        seen = set()
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    headers.append(k)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

    # Only write per-run CSVs if we have in-memory runs (not on export-csv-only)
    if combined_rows:
        _write_csv(os.path.join(CLIENT_DIR, "client_metrics.csv"), client_rows)
        _write_csv(os.path.join(SERVER_DIR, "server_metrics.csv"), server_rows)

    # Stats CSV from summary if available
    if summary:
        stats_rows: List[Dict[str, Any]] = []
        for version in summary.get("versions", []):
            tls_version = version.get("tls_version")
            runs = version.get("runs")
            success_rate = version.get("success_rate")
            for scope_key in ("client_stats", "server_stats"):
                scope_stats = version.get(scope_key, {})
                scope = "client" if scope_key == "client_stats" else "server"
                for metric, stats in scope_stats.items():
                    stats_rows.append({
                        "tls_version": tls_version,
                        "scope": scope,
                        "metric": metric,
                        "mean": stats.get("mean"),
                        "std": stats.get("std"),
                        "n": stats.get("n"),
                        "runs": runs,
                        "success_rate": success_rate,
                    })
        _write_csv(os.path.join(LOGS_DIR, "stats.csv"), stats_rows)


def write_text_summary(summary: Dict[str, Any], path: str) -> None:
    lines: List[str] = []
    for v in summary.get("versions", []):
        lines.append(f"TLS {v['tls_version']} runs={v['runs']} success_rate={v['success_rate']:.2f}")
        
        # Client metrics
        client_stats = v.get("client_stats", {})
        if client_stats:
            lines.append("  CLIENT METRICS:")
            for metric in ["handshake_time_ms", "rtt_ms", "end_to_end_transfer_time_ms", "throughput_bytes_per_sec"]:
                stat = client_stats.get(metric)
                if stat:
                    lines.append(f"    {metric}: {stat['mean']:.6f} +- {stat['std']:.6f}")
        
        # Server metrics
        server_stats = v.get("server_stats", {})
        if server_stats:
            lines.append("  SERVER METRICS:")
            for metric in ["handshake_time_ms", "transfer_duration_ms", "throughput_bytes_per_sec"]:
                stat = server_stats.get(metric)
                if stat:
                    lines.append(f"    {metric}: {stat['mean']:.6f} +- {stat['std']:.6f}")
    
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()


