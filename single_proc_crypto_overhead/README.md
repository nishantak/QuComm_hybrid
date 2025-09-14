# Single-Process Cryptographic Overhead Benchmark

Microbenchmark suite to measure compute overhead of classical and post‑quantum cryptography (PQC) in a single process. Focuses on AES-GCM, ML‑KEM‑768, and ML‑DSA‑65.

### Directory Structure

```
single_proc_crypto_overhead/
├── app.py                          # Main benchmark runner (single-process)
├── benchmark.py                    # Benchmark implementation
|
├── backends/                       # Cryptographic backend implementations
│   ├── classical.py                # AES-GCM (symmetric only)
│   ├── hybrid_kem.py               # Real ML-KEM-768 + AES-GCM
│   ├── full_pqc.py                 # Real ML-KEM-768 + ML-DSA-65 + AES-GCM
|
└── crypto/
    ├── crypto_aesgcm.py            # AES-GCM utilities
    ├── pqc_kem.py                  # Real ML-KEM-768 implementation
    └── pqc_sign.py                 # Real ML-DSA-65 implementation
```

### Backends

1. **Classical**: AES‑GCM‑256 symmetric encryption/decryption.
2. **Hybrid KEM**: Two‑party ML‑KEM‑768 key establishment to derive a 32‑byte AES‑GCM key.
3. **Full PQC**: Two‑party ML‑KEM‑768 + ML‑DSA‑65 detached signatures over the AES‑GCM payload.


## PQC Implementation Details

### ML‑KEM‑768 (Key Encapsulation Mechanism)
- **Algorithm**: ML-KEM-768 (NIST PQC Standard)
- **Key Sizes**: Public key 1184 bytes, Secret key 2400 bytes
- **Ciphertext**: 1088 bytes
- **Shared Secret**: 32 bytes
- **Implementation**: `pqcrypto.kem.ml_kem_768`
- **Flow (two‑party)**:
  - Bob (B) generates `(pk_B, sk_B)`.
  - Alice (A) encapsulates: `(ct, ss_A) = Encaps(pk_B)`.
  - Bob decapsulates: `ss_B = Decaps(ct, sk_B)`.
  - Assert `ss_A == ss_B`; use as AES‑GCM key.

### ML‑DSA‑65 (Digital Signatures)
- **Algorithm**: ML-DSA-65 (NIST PQC Standard)
- **Key Sizes**: Public key 1952 bytes, Secret key 4032 bytes
- **Signature Size**: ~3309 bytes (`SIGNATURE_SIZE`)
- **Implementation**: `pqcrypto.sign.ml_dsa_65` detached signatures
- **Usage**: `sig = sign_detached(payload)`, verify with `verify_detached(sig, payload)`

### Current Status
- All primitives are real and functional in single‑process microbenchmarks.

---

Note: uses detached signatures.

---

## Benchmark Workflow

1. `app.py` instantiates `BenchmarkRunner`.
2. Fresh backend instance per run.
3. Call sequence per run:
   - `setup_keys()` --> records KEM(A/B), signature keygen, pk distribution, symmetric keygen.
   - `encrypt_symmetric()/decrypt_symmetric()` --> AES‑GCM only timings.
   - `encrypt()/decrypt()` --> end‑to‑end with signatures.
   - `sign_detached()/verify_detached()` --> measured explicitly.
4. Results saved to `logs/benchmark.json` and `logs/benchmark.csv`.


## Implementation Details

### Real PQC Key Exchange

**Hybrid KEM Backend**:
```python
def setup_keys(self):
    # Generate real ML-KEM-768 keys
    kem = PQCKEM()
    pk, sk = kem.generate_keys()
    
    # Perform real encapsulation
    ct, ss = kem.encapsulate(pk)
    
    # Use real shared secret for AES-GCM
    self.shared_key = ss
```

**Full PQC Backend**:
```python
def setup_keys(self):
    # Generate real ML-KEM-768 keys
    kem = PQCKEM()
    pk, sk = kem.generate_keys()
    ct, ss = kem.encapsulate(pk)
    
    # Generate real ML-DSA-65 keys (store for use)
    self.sign_obj = PQCSign()
    sig_pk, sig_sk = self.sign_obj.generate_keys()
    
    self.shared_key = ss
```

### Message Flow (FullPQC)

1. Key Setup (two‑party KEM): A-->B encaps/decaps --> shared key.
2. Symmetric: `message --> AES‑GCM (nonce || ct)`.
3. Signature: `sig = ML‑DSA‑65.sign_detached(payload)`.
4. Transmitted blob: `sig || payload`.
5. Verify: `verify_detached(sig, payload)`; then AES‑GCM decrypt.

### Timing Measurements

- KEM Keygen B (ms): ML‑KEM keypair generation at Bob.
- KEM Encaps A (ms): Encapsulation at Alice.
- KEM Decaps B (ms): Decapsulation at Bob.
- Sign Keygen (ms): ML‑DSA key generation.
- PK Distribution (ms): Public key distribution (simulated copy time).
- Symmetric Keygen (ms): AES‑GCM key generation (Classical only).
- Enc/Dec (ms): AES‑GCM encrypt/decrypt times.
- Sign/Verify (ms): Detached signature generation/verification times.
- Latency (ms): End‑to‑end `encrypt()`-->`decrypt()` including signatures.
- Throughput (msg/s): End‑to‑end per‑message rate including signatures.

---

## Usage
```bash
python -m app
```
---

## Dependencies

```bash
pip install cryptography pqcrypto
```

- `cryptography`: AES‑GCM implementation
- `pqcrypto`: Post‑quantum primitives (ML‑KEM‑768, ML‑DSA‑65)

