# Classical TLS Benchmark: Alice (client) <--> Bob (server)

A comprehensive benchmark suite for measuring classical TLS 1.3 performance with detailed timing analysis and statistical reporting.


## Files

- **`bob.py`**: TLS echo server with automatic certificate generation, 1MB echo capability, and comprehensive server-side metrics collection
- **`alice.py`**: TLS client with certificate validation, detailed timing measurements, and client-side metrics collection  
- **`benchmark.py`**: Orchestration framework for running multiple test iterations, statistical analysis, and results aggregation

## Usage

### Single Benchmark Run
```bash
python benchmark.py --tls 1.3 --runs 1
```

### Multiple Runs
```bash
python benchmark.py --tls 1.3 --runs 32 --bytes 1048576
```


### Log Files
- **`logs/log/server.log`**: Server operation logs with timestamps
- **`logs/log/client.log`**: Client operation logs with timestamps  
- **`logs/log/benchmark.log`**: Orchestration and coordination logs

## Distributed Testing

### Server Setup (Bob)
```bash
python bob.py --host 0.0.0.0 --port 44330 --tls 1.3 --ciphers "AESGCM:AES256:AES128"
```

### Client Setup (Alice)
```bash
# Copy server_cert.pem from Bob to Alice first
python alice.py --host <BOB_PUBLIC_IP> --port 44330 --tls 1.3 --ciphers "AESGCM:AES256:AES128" --cafile server_cert.pem
```

### Orchestrated Remote Testing
```bash
python benchmark.py --host <BOB_PUBLIC_IP> --tls 1.3 --runs 16
```

## Technical Implementation

### Certificate Management
- **Automatic Generation**: If `--cert/--key` files don't exist, `bob.py` automatically generates RSA-2048 self-signed certificates using OpenSSL
- **Certificate Validation**: Client validates server certificates using `verify_mode=CERT_REQUIRED`
- **Hostname Checking**: Disabled for self-signed certificates (appropriate for benchmarking)

### SSL Context Configuration
- **Server Context**: `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` with version pinning
- **Client Context**: `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with certificate validation
- **Cipher Suite Control**: 
  - TLS 1.2: Direct cipher suite specification via `set_ciphers()`
  - TLS 1.3: Cipher suite preferences via `set_ciphersuites()` when available

### Measurement Methodology

#### Handshake Timing
- **Server**: Measured around `do_handshake()` call using `time.perf_counter()`
- **Client**: Measured around `wrap_socket(..., do_handshake_on_connect=True)` using `time.perf_counter()`
- **Precision**: Microsecond-level timing with high-resolution performance counters

#### Round-Trip Time (RTT)
- **Method**: Client sends 4-byte `PING`, server echoes back
- **Measurement**: Application-layer ping round-trip timing
- **Purpose**: Network latency baseline measurement

#### Data Transfer Performance
- **Payload Size**: Configurable (default 1,048,576 bytes)
- **Transfer Method**: Chunked I/O with 16,384-byte chunks to simulate real-world conditions
- **Server Processing**: 
  - Reads exact payload size using `recv_exact()` with per-call timing
  - Tracks individual `recv()` call durations for detailed analysis
  - Echoes data back to client
- **Client Processing**:
  - Sends payload in chunks using multiple `send()` calls
  - Receives echo in chunks using multiple `recv()` calls
  - Measures end-to-end transfer time

#### Cryptographic Timing Approximation
- **Encryption Time**: Approximated by `send()` wall-clock duration
- **Decryption Time**: Approximated by `recv()` wall-clock duration
- **Rationale**: Captures end-to-end TLS stack behavior including:
  - Cryptographic operations
  - Kernel buffering effects
  - Network stack overhead
  - Application-level processing

#### Process Management
- **Server Startup**: `benchmark.py` starts `bob.py` and waits for `SERVER_READY` signal
- **Client Execution**: Runs `alice.py` after server readiness confirmation
- **Cleanup**: Proper process termination and resource cleanup

#### Data Collection
- **In-Memory Aggregation**: Metrics collected in memory during benchmark execution
- **JSON Persistence**: Individual run metrics saved as JSON files
- **CSV Export**: Statistical summaries exported in CSV format for analysis tools
- **Human-Readable Output**: Terminal and file output with clear metric separation

#### Error Handling
- **Timeout Protection**: 20-second timeout for server startup
- **Graceful Degradation**: Failed runs excluded from statistical analysis
- **Comprehensive Logging**: All operations logged with timestamps for debugging

## Performance Characteristics

## Dependencies

- **Python 3.8+**: Required for modern SSL context features
- **OpenSSL**: Used for certificate generation and TLS operations
- **Standard Library**: `ssl`, `socket`, `time`, `json`, `csv`, `subprocess`
