import argparse
import json
import os
import socket
import ssl
import time


LOGS_DIR = os.path.join(os.getcwd(), "logs")
LOG_DIR_DIR = os.path.join(LOGS_DIR, "log")
CLIENT_DIR = os.path.join(LOGS_DIR, "client")
DEFAULT_PAYLOAD_BYTES = 1024 * 1024


def ensure_logs_dir() -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR_DIR, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)


def append_log(message: str) -> None:
    ensure_logs_dir()
    try:
        with open(os.path.join(LOG_DIR_DIR, "client.log"), "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {message}\n")
    except Exception:
        pass


def build_ssl_context(tls_version: str, ciphers: str, ca_file: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if tls_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        raise ValueError("Unsupported TLS version. Use '1.3'.")

    # Cipher configuration (TLS 1.2 via set_ciphers; TLS 1.3 via set_ciphersuites if available)
    if ciphers:
        try:
            context.set_ciphers(ciphers)
        except ssl.SSLError:
            pass
    if hasattr(context, "set_ciphersuites") and ciphers and tls_version == "1.3":
        try:
            context.set_ciphersuites(ciphers)
        except Exception:
            pass

    context.check_hostname = False  # self-signed; use CA file for trust
    context.verify_mode = ssl.CERT_REQUIRED
    if ca_file and os.path.exists(ca_file):
        context.load_verify_locations(cafile=ca_file)
    else:
        # Fall back to default CAs (will likely fail for self-signed)
        context.load_default_certs()
    return context


def run_client(host: str, port: int, tls_version: str, ciphers: str, ca_file: str, payload_bytes: int) -> None:
    ensure_logs_dir()
    metrics = {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "ciphers_requested": ciphers,
        "ca_file": ca_file,
        "payload_bytes": payload_bytes,
    }

    try:
        # TCP connect timing
        addr = (host, port)
        t_tcp_start = time.perf_counter()
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.connect(addr)
        t_tcp_end = time.perf_counter()
        metrics["tcp_connect_time_ms"] = (t_tcp_end - t_tcp_start) * 1000.0
        append_log(f"TCP connected to {addr} in {metrics['tcp_connect_time_ms']:.3f}ms")

        # TLS handshake timing
        context = build_ssl_context(tls_version, ciphers, ca_file)
        t_hs_start = time.perf_counter()
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=host, do_handshake_on_connect=True)
        t_hs_end = time.perf_counter()
        metrics["handshake_time_ms"] = (t_hs_end - t_hs_start) * 1000.0
        metrics["negotiated_tls_version"] = ssl_sock.version()
        metrics["negotiated_cipher"] = ssl_sock.cipher()
        append_log(f"Handshake complete in {metrics['handshake_time_ms']:.3f}ms")

        # RTT ping (small 4-byte payload echo)
        ping_payload = b"PING"
        t_rtt_start = time.perf_counter()
        ssl_sock.sendall(ping_payload)
        _pong = ssl_sock.recv(len(ping_payload))
        t_rtt_end = time.perf_counter()
        metrics["rtt_ms"] = (t_rtt_end - t_rtt_start) * 1000.0

        # Prepare 1MB payload
        payload = b"A" * payload_bytes

        # Send timing (encryption approximated by send duration)
        t_send_start = time.perf_counter()
        total_sent = 0
        view = memoryview(payload)
        while total_sent < payload_bytes:
            sent = ssl_sock.send(view[total_sent:])
            total_sent += sent
        t_send_end = time.perf_counter()
        metrics["bytes_sent"] = total_sent
        metrics["encrypt_time_ms"] = (t_send_end - t_send_start) * 1000.0

        # Receive echo timing (decryption approximated by recv duration)
        t_recv_start = time.perf_counter()
        received = 0
        chunks = []
        while received < payload_bytes:
            chunk = ssl_sock.recv(min(16384, payload_bytes - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        t_recv_end = time.perf_counter()
        echo = b"".join(chunks)
        metrics["bytes_received"] = len(echo)
        metrics["decrypt_time_ms"] = (t_recv_end - t_recv_start) * 1000.0

        # End-to-end transfer
        transfer_time = (t_recv_end - t_send_start)
        metrics["end_to_end_transfer_time_ms"] = transfer_time * 1000.0
        metrics["throughput_bytes_per_sec"] = payload_bytes / transfer_time if transfer_time > 0 else None
        metrics["success"] = (len(echo) == payload_bytes)
        append_log(f"Transfer success={metrics['success']} bytes={len(echo)} time={transfer_time:.6f}s")
    except Exception as e:
        metrics["success"] = False
        metrics["error"] = str(e)
        append_log(f"Error: {e}")
        try:
            raw_sock.close()
        except Exception:
            pass
        raise
    finally:
        try:
            if 'ssl_sock' in locals():
                ssl_sock.shutdown(socket.SHUT_RDWR)
                ssl_sock.close()
        except Exception:
            pass

    with open(os.path.join(CLIENT_DIR, "client_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TLS client (Alice)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=44330, help="Server port")
    parser.add_argument("--tls", choices=["1.3"], default="1.3", help="TLS version")
    parser.add_argument("--ciphers", default="", help="Cipher suites preference string")
    parser.add_argument("--cafile", default="server_cert.pem", help="CA or server cert to trust")
    parser.add_argument("--bytes", type=int, default=DEFAULT_PAYLOAD_BYTES, help="Payload size in bytes")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_client(
        host=args.host,
        port=args.port,
        tls_version=args.tls,
        ciphers=args.ciphers,
        ca_file=args.cafile,
        payload_bytes=args.bytes,
    )


