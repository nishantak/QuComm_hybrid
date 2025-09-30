import argparse
import json
import os
import socket
import ssl
import subprocess
import time
from typing import List, Tuple


LOGS_DIR = os.path.join(os.getcwd(), "logs")
LOG_DIR_DIR = os.path.join(LOGS_DIR, "log")
SERVER_DIR = os.path.join(LOGS_DIR, "server")
DEFAULT_PAYLOAD_BYTES = 1024 * 1024  # 1,048,576


def ensure_logs_dir() -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR_DIR, exist_ok=True)
    os.makedirs(SERVER_DIR, exist_ok=True)


def append_log(message: str) -> None:
    ensure_logs_dir()
    try:
        with open(os.path.join(LOG_DIR_DIR, "server.log"), "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {message}\n")
    except Exception:
        pass


def generate_self_signed_cert(cert_file: str, key_file: str, cn: str = "localhost", days: int = 1) -> None:
    # Use openssl to generate a self-signed certificate if missing
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        key_file,
        "-out",
        cert_file,
        "-days",
        str(days),
        "-subj",
        f"/CN={cn}",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def build_ssl_context(tls_version: str, ciphers: str, cert_file: str, key_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if tls_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        raise ValueError("Unsupported TLS version. Use '1.3'.")

    # Cipher configuration: set_ciphers affects TLS 1.2 and below
    if ciphers:
        try:
            context.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
    # For TLS 1.3 try setting cipher suites if available
    if hasattr(context, "set_ciphersuites") and tls_version == "1.3" and ciphers:
        try:
            context.set_ciphersuites(ciphers)
        except Exception:
            pass

    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def recv_exact(sock: ssl.SSLSocket, total_bytes: int) -> Tuple[bytes, List[float]]:
    chunks: List[bytes] = []
    per_recv_durations: List[float] = []
    bytes_remaining = total_bytes
    while bytes_remaining > 0:
        t0 = time.perf_counter()
        chunk = sock.recv(min(16384, bytes_remaining))
        t1 = time.perf_counter()
        per_recv_durations.append(t1 - t0)
        if not chunk:
            break
        chunks.append(chunk)
        bytes_remaining -= len(chunk)
    return b"".join(chunks), per_recv_durations


def serve(host: str, port: int, tls_version: str, ciphers: str, cert_file: str, key_file: str, payload_bytes: int) -> None:
    ensure_logs_dir()
    generate_self_signed_cert(cert_file, key_file)

    context = build_ssl_context(tls_version, ciphers, cert_file, key_file)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)

    print("SERVER_READY", flush=True)
    append_log("Server ready and listening")

    metrics = {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "ciphers_requested": ciphers,
        "cert_file": cert_file,
        "key_file": key_file,
        "cert_size_bytes": os.path.getsize(cert_file) if os.path.exists(cert_file) else None,
        "key_size_bytes": os.path.getsize(key_file) if os.path.exists(key_file) else None,
    }

    conn, addr = server_sock.accept()
    raw_conn = conn
    try:
        try:
            # TLS handshake timing
            t_hs_start = time.perf_counter()
            ssl_conn = context.wrap_socket(raw_conn, server_side=True, do_handshake_on_connect=False)
            ssl_conn.do_handshake()
            t_hs_end = time.perf_counter()
            metrics["handshake_time_ms"] = (t_hs_end - t_hs_start) * 1000.0
            metrics["negotiated_tls_version"] = ssl_conn.version()
            metrics["negotiated_cipher"] = ssl_conn.cipher()
            append_log(f"Handshake complete with {addr} in {metrics['handshake_time_ms']:.3f}ms")

            # small RTT ping echo (client may send a small ping first)
            try:
                ssl_conn.settimeout(0.05)
                prelude = ssl_conn.recv(4)
                if prelude:
                    ssl_conn.sendall(prelude)
            except Exception:
                try:
                    ssl_conn.settimeout(None)
                except Exception:
                    pass
            finally:
                try:
                    ssl_conn.settimeout(None)
                except Exception:
                    pass

            # Receive payload (decryption time approximated by recv duration)
            t_transfer_start = time.perf_counter()
            t_decrypt_start = time.perf_counter()
            data, per_recv_times = recv_exact(ssl_conn, payload_bytes)
            t_decrypt_end = time.perf_counter()
            bytes_received = len(data)

            metrics["bytes_received"] = bytes_received
            metrics["per_recv_call_time_ms"] = [x * 1000.0 for x in per_recv_times]
            decrypt_time = (t_decrypt_end - t_decrypt_start) * 1000.0
            metrics["decrypt_time_ms"] = decrypt_time

            # Echo back (encryption approximated by send duration)
            t_encrypt_start = time.perf_counter()
            total_sent = 0
            view = memoryview(data)
            while total_sent < bytes_received:
                sent = ssl_conn.send(view[total_sent:])
                total_sent += sent
            t_encrypt_end = time.perf_counter()
            encrypt_time = (t_encrypt_end - t_encrypt_start) * 1000.0
            metrics["bytes_sent"] = total_sent
            metrics["encrypt_time_ms"] = encrypt_time

            t_transfer_end = time.perf_counter()
            transfer_duration = t_transfer_end - t_transfer_start
            metrics["transfer_duration_ms"] = transfer_duration * 1000.0
            metrics["throughput_bytes_per_sec"] = bytes_received / transfer_duration if transfer_duration > 0 else None
            metrics["success"] = True
            append_log(f"Transfer complete: {bytes_received} bytes in {metrics['transfer_duration_ms']:.3f}ms")
        except Exception as e:
            metrics["success"] = False
            metrics["error"] = str(e)
            append_log(f"Error: {e}")
    finally:
        try:
            if 'ssl_conn' in locals():
                ssl_conn.shutdown(socket.SHUT_RDWR)
                ssl_conn.close()
        except Exception:
            pass
        try:
            raw_conn.close()
        except Exception:
            pass
        server_sock.close()

    # Write metrics
    with open(os.path.join(SERVER_DIR, "server_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS echo server (Bob)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=44330, help="Port to bind")
    parser.add_argument("--tls", choices=["1.3"], default="1.3", help="TLS version")
    parser.add_argument("--ciphers", default="", help="Cipher suites preference string")
    parser.add_argument("--cert", default="server_cert.pem", help="Certificate file path")
    parser.add_argument("--key", default="server_key.pem", help="Private key file path")
    parser.add_argument("--bytes", type=int, default=DEFAULT_PAYLOAD_BYTES, help="Payload size in bytes")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    serve(
        host=args.host,
        port=args.port,
        tls_version=args.tls,
        ciphers=args.ciphers,
        cert_file=args.cert,
        key_file=args.key,
        payload_bytes=args.bytes,
    )


