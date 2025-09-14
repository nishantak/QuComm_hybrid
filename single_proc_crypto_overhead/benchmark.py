import time
import statistics
import json
import csv
import os
import traceback
from datetime import datetime
from backends.classical import ClassicalBackend
from backends.hybrid_kem import HybridKEMBackend
from backends.full_pqc import FullPQCBackend

class BenchmarkRunner:
    def __init__(self, message_size=1024, runs=8, repetitions=100, log_dir="logs"):
        self.message_size = message_size
        self.runs = runs
        self.repetitions = repetitions
        self.backend_classes = {
            "Classical": ClassicalBackend,
            "HybridKEM": HybridKEMBackend,
            "FullPQC": FullPQCBackend, 
        }
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def _time_key_setup(self, backend, name):
        """Capture detailed timings from backend.setup_keys() if provided."""
        try:
            result = backend.setup_keys()
            # Support backends returning a dict of timings; else compute total only
            if isinstance(result, dict):
                return result, False
            else:
                # Fallback: only total setup time measured here is not available; mark zeros
                return {
                    "kem_keygen_B_ms": 0.0,
                    "encaps_A_ms": 0.0,
                    "decaps_B_ms": 0.0,
                    "sign_keygen_ms": 0.0,
                    "pk_distribution_ms": 0.0,
                    "symmetric_keygen_ms": 0.0,
                }, False
        except Exception as e:
            print(f"[!] {name} key setup failed: {e}")
            traceback.print_exc()
            return None, True

    def _time_encryption_decryption(self, backend, name, message):
        """Time symmetric encrypt and decrypt only (exclude sign/verify)."""
        try:
            encrypt_fn = getattr(backend, "encrypt_symmetric", getattr(backend, "encrypt"))
            decrypt_fn = getattr(backend, "decrypt_symmetric", getattr(backend, "decrypt"))
            start = time.perf_counter()
            ct = encrypt_fn(message)
            mid = time.perf_counter()
            pt = decrypt_fn(ct)
            end = time.perf_counter()
            assert pt == message, "plaintext mismatch"
            return ((mid-start)*1000, (end-mid)*1000), False
        except Exception as e:
            print(f"[!] {name} enc/dec failed: {e}")
            traceback.print_exc()
            return (None, None), True

    def _time_latency(self, backend, name, message):
        start = time.perf_counter()
        try:
            ct = backend.encrypt(message)
            pt = backend.decrypt(ct)
            end = time.perf_counter()
            assert pt == message, "plaintext mismatch"
            return (end-start)*1000, False
        except Exception as e:
            print(f"[!] {name} latency failed: {e}")
            traceback.print_exc()
            return None, True

    def _time_throughput(self, backend, name, message):
        try:
            start = time.perf_counter()
            for _ in range(self.repetitions):
                ct = backend.encrypt(message)
                pt = backend.decrypt(ct)
                assert pt == message, "plaintext mismatch"
            end = time.perf_counter()
            total_time = end-start
            return self.repetitions / total_time, False
        except Exception as e:
            print(f"[!] {name} throughput failed: {e}")
            traceback.print_exc()
            return None, True

    def _time_sign_verify(self, backend, name, message):
        """Time detached sign and verify of the symmetric payload, if supported."""
        try:
            # Produce a payload with symmetric encryption only
            encrypt_fn = getattr(backend, "encrypt_symmetric", getattr(backend, "encrypt"))
            decrypt_fn = getattr(backend, "decrypt_symmetric", getattr(backend, "decrypt"))
            payload = encrypt_fn(message)
            # Validate symmetric path
            assert decrypt_fn(payload) == message

            # If backend supports signatures, time them
            sign_obj = getattr(backend, "sign", None)
            if sign_obj is None:
                return (0.0, 0.0), False

            start = time.perf_counter()
            sig = sign_obj.sign_detached(payload)
            mid = time.perf_counter()
            ok = sign_obj.verify_detached(sig, payload)
            end = time.perf_counter()
            if not ok:
                raise RuntimeError("Signature verification failed")
            return ((mid-start)*1000, (end-mid)*1000), False
        except Exception as e:
            print(f"[!] {name} sign/verify failed: {e}")
            traceback.print_exc()
            return (None, None), True

    def run(self):
        message = b"x" * self.message_size
        results = {}

        for name, backend_cls in self.backend_classes.items():
            print(f"\nBenchmarking {name} ...")
            latency, enc, dec, thr, failures = [], [], [], [], 0
            kem_keygen_B, kem_encaps_A, kem_decaps_B = [], [], []
            sign_keygen, pk_distribution, symmetric_keygen = [], [], []
            sign_time, verify_time = [], []

            for i in range(self.runs):
                backend = backend_cls()  # fresh backend each run

                kdetail, fail = self._time_key_setup(backend, name)
                if fail or kdetail is None:
                    failures += 1
                else:
                    kem_keygen_B.append(kdetail.get("kem_keygen_B_ms", 0.0))
                    kem_encaps_A.append(kdetail.get("encaps_A_ms", 0.0))
                    kem_decaps_B.append(kdetail.get("decaps_B_ms", 0.0))
                    sign_keygen.append(kdetail.get("sign_keygen_ms", 0.0))
                    pk_distribution.append(kdetail.get("pk_distribution_ms", 0.0))
                    symmetric_keygen.append(kdetail.get("symmetric_keygen_ms", 0.0))

                (etime, dtime), fail = self._time_encryption_decryption(backend, name, message)
                if fail:
                    failures += 1
                else:
                    enc.append(etime)
                    dec.append(dtime)

                ltime, fail = self._time_latency(backend, name, message)
                if fail:
                    failures += 1
                else:
                    latency.append(ltime)

                # Sign/verify timings (if available)
                (stime, vtime), fail_sv = self._time_sign_verify(backend, name, message)
                if fail_sv:
                    failures += 1
                else:
                    sign_time.append(stime)
                    verify_time.append(vtime)

                tput, fail = self._time_throughput(backend, name, message)
                if fail:
                    failures += 1
                else:
                    thr.append(tput)

            results[name] = {
                "Latency (ms)": self._stats(latency),
                "KEM Keygen B (ms)": self._stats(kem_keygen_B),
                "KEM Encaps A (ms)": self._stats(kem_encaps_A),
                "KEM Decaps B (ms)": self._stats(kem_decaps_B),
                "Sign Keygen (ms)": self._stats(sign_keygen),
                "PK Distribution (ms)": self._stats(pk_distribution),
                "Symmetric Keygen (ms)": self._stats(symmetric_keygen),
                "Enc (ms)": self._stats(enc),
                "Dec (ms)": self._stats(dec),
                "Sign (ms)": self._stats(sign_time),
                "Verify (ms)": self._stats(verify_time),
                "Throughput (msg/s)": self._stats(thr),
                "Failures": failures,
            }

        self._print_results(results)
        self._save_results(results)
        return results

    def _stats(self, data):
        if not data:
            return "n/a"
        mean = statistics.mean(data)
        std = statistics.pstdev(data)
        return f"{mean:.4f} +- {std:.4f}"

    def _print_results(self, results):
        print("\n=== Benchmark Results ===")
        for name, metrics in results.items():
            print(f"\n{name}:")
            for k, v in metrics.items():
                print(f"  {k}: {v}")

    def _save_results(self, results):
        json_path = os.path.join(self.log_dir, f"benchmark.json")
        csv_path = os.path.join(self.log_dir, f"benchmark.csv")

        # Save JSON
        with open(json_path, "w") as jf:
            json.dump(results, jf, indent=2)

        # Save CSV
        with open(csv_path, "w", newline="") as cf:
            writer = csv.writer(cf)
            headers = ["Backend"] + list(next(iter(results.values())).keys())
            writer.writerow(headers)
            for name, metrics in results.items():
                row = [name] + list(metrics.values())
                writer.writerow(row)

        print(f"\n[+] Results saved to:\n  {json_path}\n  {csv_path}")
