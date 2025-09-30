# Hybrid 2-Plane Quantum-Classical Framework

A comprehensive benchmarking framework for evaluating a 2-plane post-quantum hybrid end-to-end implementation, with real-world network measurements and cryptographic overhead analysis.

## Overview

This project implements and benchmarks a **two-plane hybrid end-to-end architecture** that combines classical and post-quantum cryptography to provide quantum-safe communication.

### Architecture

- **Plane 1 (Classical):** TLS 1.3 handshake with ECDHE key exchange and RSA/ECDSA signatures
- **Plane 2 (Post-Quantum):** ML-KEM (Kyber) key encapsulation and ML-DSA (Dilithium) signatures  
- **Key Bridge:** HKDF-Extract combines both shared secrets into a single master secret (ETSI Compliant latest)
- **Result:** Session remains secure unless **both** classical and post-quantum algorithms are broken

## Project Structure

```
qcomm_benchmark/
├── classical_alice_bob/          # Classical TLS 1.3 implementation for comparison
│   ├── alice.py                  # TLS client
│   ├── bob.py                    # TLS server
│   ├── benchmark.py              # Benchmarking suite
│   └── logs/                     # Performance metrics and logs
|
├── hybrid_qu_alice_bob/          # Post-quantum hybrid implementation
│   ├── alice.py                  # Hybrid TLS client
│   ├── bob.py                    # Hybrid TLS server
│   ├── benchmark.py              # Hybrid benchmarking orchestrator
│   ├── hybrid_tls_real_pqc.py    # Post-quantum hybrid protocol
│   └── logs/                     # Hybrid performance metrics
|
├── single_proc_crypto_overhead/  # Isolated pq cryptographic algorithm microbenchmarks
    ├── app.py                    # Single-process benchmark runner
    ├── benchmark.py              # Microbenchmark implementation
    ├── backends/                 # Cryptographic backends
    │   ├── classical.py          # AES-GCM-256 (symmetric only)
    │   ├── hybrid_kem.py         # ML-KEM-768 + AES-GCM
    │   └── full_pqc.py           # ML-KEM-768 + ML-DSA-65 + AES-GCM
    ├── crypto/                   # Post-quantum cryptographic primitives
    │   ├── pqc_kem.py            # ML-KEM-768 implementation
    │   ├── pqc_sign.py           # ML-DSA-65 implementation
    │   └── crypto_aesgcm.py      # AES-GCM utilities
    └── logs/                     # Microbenchmark results

```

## Technical Implementation

### Post-Quantum Algorithms

- **ML-KEM-768/1024:** NIST-standardized key encapsulation mechanism (Kyber)
  - Security Level 3/5 (equivalent to AES-192/256)
  - Public key: 1184/1568 bytes, Secret key: 2400/3040 bytes
  - Ciphertext: 1088/1568 bytes, Shared secret: 32 bytes

- **ML-DSA-65/87:** NIST-standardized digital signature algorithm (Dilithium)
  - Security Level 3/5 (equivalent to AES-192/256)
  - Public key: 1952/2592 bytes, Secret key: 4032/4864 bytes
  - Signature: ~3309/~4624 bytes

### Hybrid Protocol Flow

1. **ClientHello:** Sends ECDHE, ML-KEM, and ML-DSA public keys
2. **ServerHello:** Responds with server's public keys for all algorithms
3. **Key Exchange (Parallel):**
   - ECDHE key exchange --> `Z_ec` (classical shared secret)
   - ML-KEM encapsulation --> `Z_pq` (post-quantum shared secret)
4. **Authentication:** Server signs handshake transcript with ML-DSA
5. **Key Bridge:** `master_secret = HKDF-Extract(salt, Z_ec || Z_pq)`
6. **Session Keys:** Derived from master secret using HKDF-Expand
7. **Data Protection:** AES-GCM encryption with derived session keys

## Usage

### Prerequisites

```bash
# Install required dependencies
pip install cryptography pqcrypto
```

### Classical TLS Benchmarking

```bash
cd classical_alice_bob

# Run single benchmark (1MB)
python benchmark.py --tls 1.3 --runs 1

# Run with custom parameters
python benchmark.py --host 127.0.0.1 --port 44330 --tls 1.3 --ciphers "AESGCM:CHACHA20" --runs 32 --bytes 2097152
```

### Hybrid TLS Benchmarking

```bash
cd hybrid_qu_alice_bob

# Run hybrid benchmark (1MB)
python benchmark.py --hybrid --tls 1.3 --runs 1

# Compare classical vs hybrid
python benchmark.py --tls 1.3 --runs 32  # Classical
python benchmark.py --hybrid --tls 1.3 --runs 32  # Hybrid
```

### Cryptographic Overhead Analysis

```bash
cd single_proc_crypto_overhead

# Run microbenchmarks
python app.py

# Custom benchmark configuration
python -c "
from benchmark import BenchmarkRunner
runner = BenchmarkRunner(
    message_size=2048,    # 2KB messages
    runs=16,              # 16 experiment runs
    repetitions=200,      # 200 messages per run
    log_dir='custom_logs'
)
results = runner.run()
"
```

## Metrics

### Network-Level Metrics

- **Handshake Time:** Complete TLS handshake duration (ms)
- **Round-Trip Time (RTT):** Application-layer latency in 4-byte PING (ms)
- **Throughput:** Data transfer rate (bytes/sec)
- **Encryption/Decryption Time:** Symmetric crypto overhead (ms)
- **End-to-End Transfer Time:** Total data exchange time (ms)

### Cryptographic Overhead Metrics

- **KEM Key Generation:** ML-KEM keypair generation time (ms)
- **KEM Encapsulation/Decapsulation:** Key exchange operations (ms)
- **Signature Generation/Verification:** ML-DSA operations (ms)
- **Public Key Distribution:** Key exchange overhead (ms)
- **Symmetric Key Generation:** AES key setup time (ms)

<br>

**Statistical Analysis**

- **Mean and Standard Deviation:** For all timing measurements
- **Success Rate:** Percentage of successful handshakes
- **Sample Count:** Number of [successfull] measurements per metric
- **Confidence Intervals:** Statistical reliability indicators

## Results and Output

### Generated Files

- **`logs/stats.json`:** Comprehensive statistical analysis
- **`logs/stats.csv`:** Tabular data for analysis
- **`logs/summary.txt`:** Human-readable performance summary
- **`logs/client/client_metrics.json`:** Client-side detailed metrics
- **`logs/server/server_metrics.json`:** Server-side detailed metrics


### Distributed Testing (should work, I hope)

```bash
# Server (Bob) - Run on remote machine
python bob.py --host 0.0.0.0 --port 44330 --tls 1.3

# Client (Alice) - Run on local machine
python alice.py --host <SERVER_IP> --port 44330 --tls 1.3 --cafile server_cert.pem

# testing
python benchmark.py --host <SERVER_IP> --tls 1.3 --runs 50
```


## Security Considerations

### Quantum Safety

- **Hybrid Property:** Session remains secure unless both classical and post-quantum algorithms are broken
- **Algorithm Selection:** Uses NIST-standardized ML-KEM and ML-DSA algorithms
- **Forward Secrecy:** Each session uses fresh ephemeral keys

### Implementation Security

- **PQC Algorithms:** Uses proper post-quantum cryptographic implementations
- **Proper Key Derivation:** HKDF-based key combination following ETSI standards
- **Secure Randomness:** Uses cryptographically secure random number generation
