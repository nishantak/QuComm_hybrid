import argparse
import sys
import traceback
from pathlib import Path

from tls_pqc_bridge.endpoint import MODES, run_client
from tls_pqc_bridge.files import write_json_atomic


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one TLS-PQC Bridge client connection"
    )
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("--result-file", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        metrics = run_client(
            arguments.mode,
            arguments.host,
            arguments.port,
            arguments.server_name,
            arguments.credentials,
            arguments.payload_bytes,
            arguments.timeout_seconds,
        )
    except Exception as error:
        write_json_atomic(
            arguments.result_file,
            {
                "success": False,
                "endpoint": "client",
                "mode": arguments.mode,
                "error_type": type(error).__name__,
                "error": str(error),
            },
        )
        traceback.print_exc(file=sys.stderr)
        return 1
    write_json_atomic(arguments.result_file, metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
