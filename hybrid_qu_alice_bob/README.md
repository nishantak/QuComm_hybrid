# Post-Quantum Hybrid TLS Benchmark: Alice (client) <--> Bob (server)

A comprehensive benchmark suite for measuring post-quantum hybrid TLS performance with real ML-KEM and ML-DSA cryptographic algorithms.


## Post-Quantum Hybrid TLS Specification

### Cryptographic Components
- **Plane 1 (Classical)**: ECDHE (P-256) + RSA/ECDSA signatures
- **Plane 2 (Post-Quantum)**: ML-KEM-1024 (Key Encapsulation) + ML-DSA-65 (Digital Signatures)
- **Key Bridge**: HKDF-Extract(salt, Z_ec || Z_pq) --> master_secret
- **Session Keys**: Derived using HKDF-Expand from combined master secret

### Hybrid Handshake Flow
1. **ClientHello**: Client sends ECDHE, ML-KEM, and ML-DSA public keys
2. **ServerHello**: Server responds with its public keys
3. **Key Exchange**: 
   - ECDH key exchange (Plane 1)
   - ML-KEM encapsulation/decapsulation (Plane 2)
4. **Authentication**: ML-DSA signature generation and verification
5. **Key Derivation**: Combined secret derivation using HKDF
6. **Session Keys**: AES-GCM session keys derived for data encryption

## Files

- **`bob.py`**: Post-quantum hybrid TLS echo server with comprehensive server-side metrics collection
- **`alice.py`**: Post-quantum hybrid TLS client with detailed timing measurements and client-side metrics collection
- **`benchmark.py`**: Orchestration framework supporting both classical and hybrid TLS modes
- **`hybrid_tls_real_pqc.py`**: Core post-quantum hybrid TLS implementation with real ML-KEM and ML-DSA algorithms

## Quick Start

### Hybrid TLS Benchmark
```bash
python benchmark.py --hybrid --runs 1
```

### Multiple Hybrid Runs with Statistical Analysis
```bash
python benchmark.py --hybrid --runs 32 --bytes 1048576
```

### Log Files
- **`logs/log/server.log`**: Server operation logs with timestamps
- **`logs/log/client.log`**: Client operation logs with timestamps  
- **`logs/log/benchmark.log`**: Orchestration and coordination logs

## Technical Implementation

### Post-Quantum Cryptographic Library
- **ML-KEM-1024**: Key encapsulation mechanism for post-quantum key exchange (Level 5)
- **ML-DSA-65**: Digital signature algorithm for post-quantum authentication (Level 3)
- **Fallback Support**: RSA when `pqcrypto` library is not available


### Hybrid TLS Implementation

#### Key Generation
- **ECDHE Keys**: P-256 elliptic curve key pairs for classical key exchange
- **ML-KEM Keys**: 1024-bit ML-KEM key pairs for post-quantum key encapsulation
- **ML-DSA Keys**: 65-bit ML-DSA key pairs for post-quantum digital signatures

#### Handshake Process
- **Client Key Generation**: All three generated during handshake
- **Server Key Generation**: Server generates corresponding key pairs
- **Dual Key Exchange**: 
  - ECDH shared secret computation
  - ML-KEM encapsulation/decapsulation
- **Combined Secret**: HKDF-Extract combines both shared secrets
- **Session Key Derivation**: HKDF-Expand generates AES-GCM session keys

#### Data Encryption
- **AES-GCM**: 256-bit AES in Galois/Counter Mode for data encryption
- **Session Keys**: Separate client/server encryption keys and IVs
- **Chunked Transfer**: 16KB chunks to match classical TLS measurement methodology

### Measurement Methodology

#### Handshake Timing
- **Total Handshake Time**: Complete hybrid handshake duration
- **Component Timing**: Individual timing for each handshake phase:
  - `client_hello_time_ms`: ClientHello message processing
  - `server_hello_time_ms`: ServerHello message processing
  - `ecdh_time_ms`: ECDH key exchange timing
  - `mlkem_encapsulation_time_ms`: ML-KEM encapsulation (client)
  - `mlkem_decapsulation_time_ms`: ML-KEM decapsulation (server)
  - `signature_generation_time_ms`: ML-DSA signature generation (server)
  - `signature_verification_time_ms`: ML-DSA signature verification (client)
  - `key_derivation_time_ms`: Combined key derivation timing

#### Data Transfer Performance
- **Chunked I/O**: 16,384-byte chunks to match classical TLS methodology
- **Network Timing**: Includes all network round-trips and latency
- **Encryption/Decryption**: AES-GCM timing for each chunk

#### Round-Trip Time (RTT)
- **Method**: Client sends 4-byte `PING`, server echoes back
- **Measurement**: Application-layer round-trip timing
- **Purpose**: Network latency baseline measurement

### Statistical Analysis

#### Metrics Collected
- **Client Metrics**:
  - `handshake_time_ms`: Total hybrid handshake duration
  - `rtt_ms`: Round-trip time measurement
  - `end_to_end_transfer_time_ms`: Complete data transfer time: Client send time + network round-trip + server processing + client receive time
  - `throughput_bytes_per_sec`: Data transfer rate
  - `encrypt_time_ms`: Encryption timing approximation
  - `decrypt_time_ms`: Decryption timing approximation

- **Server Metrics**:
  - `handshake_time_ms`: Total hybrid handshake duration
  - `transfer_duration_ms`: Server-side data processing time: Server receive time + server processing + server send time
  - `throughput_bytes_per_sec`: Server-side data transfer rate
  - `per_recv_call_time_ms`: Individual receive call timings
  - `encrypt_time_ms`: Encryption timing approximation
  - `decrypt_time_ms`: Decryption timing approximation

## Dependencies

### Required Libraries
- **Python 3.8+**: Required for modern features and type hints
- **cryptography**: For classical cryptographic operations (ECDHE, AES-GCM)
- **pqcrypto**: For real ML-KEM and ML-DSA implementations (optional)

### Optional Dependencies
- **pqcrypto**: Real post-quantum cryptographic library
  - `pqcrypto.kem.ml_kem_1024`: ML-KEM key encapsulation
  - `pqcrypto.sign.ml_dsa_65`: ML-DSA digital signatures
- **Fallback**: RSA simulation when pqcrypto is not available

## Security Considerations

### Post-Quantum Security
- **ML-KEM-1024**: Provides 128-bit post-quantum security level
- **ML-DSA-65**: Provides 128-bit post-quantum security level
- **Hybrid Approach**: Maintains classical security while adding post-quantum protection
- **Forward Secrecy**: Both classical and post-quantum components provide forward secrecy

### Implementation Security
- **Key Generation**: Cryptographically secure random number generation
- **Key Derivation**: HKDF-based key derivation following TLS 1.3 standards
- **Authentication**: ML-DSA signatures provide post-quantum authentication
- **Encryption**: AES-GCM provides authenticated encryption
