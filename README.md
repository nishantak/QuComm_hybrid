# TLS-PQC Bridge

TLS-PQC Bridge is a server-authenticated two-plane research protocol carried inside TLS 1.3. The TLS plane contributes a TLS exporter. The PQC plane contributes an ephemeral ML-KEM-768 secret authenticated by a provisioned ML-DSA-65 server identity. An ETSI-aligned CatKDF key bridge combines both inputs and the exchange transcript, then derives Finished keys and directional AES-256-GCM keys for bridge-protected application records.

The construction is an application protocol, not native hybrid TLS. Its PQC exchange uses TLS application data and adds four ordered one-way messages after the TLS handshake. It does not change TLS library source. The bridge uses normal TLS exporter and application-data operations; the benchmark also calls OpenSSL's group-list configuration API through pyOpenSSL's bundled binding so every comparison uses and verifies one exact TLS group.

## Three runnable modes

| CLI mode | Figure label | TLS group | Application path |
|---|---|---|---|
| `baseline` | Classical TLS | `X25519` | Plain project frames in TLS |
| `native` | Native hybrid TLS | `X25519MLKEM768` | Plain project frames in TLS |
| `hybrid` | TLS + PQC bridge | `X25519` | PQC exchange and bridge-protected records in TLS |

Native hybrid TLS is the standardized reference defined by RFC 9954 and RFC 10024. It is normally the better choice when both endpoints can require it. The application bridge addresses a narrower case: controlled applications can update their endpoint protocol and provision a PQC identity, but cannot rely on the TLS termination layer to expose, require, or authenticate PQ negotiation.

## Security behavior

- Every mode requires TLS 1.3, certificate-chain and DNS/IP service-identity verification, one accepted TLS 1.3 AEAD suite, the prescribed TLS group, and the prescribed ALPN.
- TLS + PQC bridge has no classical fallback. Alice verifies the provisioned ML-DSA-65 identity, the ML-KEM-768 exchange, and both role-specific Finished MACs before application data is accepted.
- The key bridge binds the TLS exporter, ML-KEM secret, normalized service name, provisioned PQC identity, protocol identifiers, and exact encoded exchange frames.
- Bridge-protected records use directional keys, sequence-derived nonces, authenticated direction/order/type/length metadata, strict ordering, and a per-key record limit.
- Alice and Bob stream and validate the payload in both directions. They verify offsets, generated content, totals, SHA-256 digests, and the final acknowledgement.
- All three measurements use the same endpoint processes, TLS wrapper, framing, transfer generator, validation path, and timer definitions. Classical and native modes differ only in their enforced TLS group; bridge mode adds the PQC exchange and protected-record path.

The protocol authenticates Bob to Alice; it does not authenticate Alice. Provisioning creates a local test CA, an ECDSA P-256 server certificate, and an ML-DSA-65 server identity. Production key custody, certificate and pin lifecycle, resumption, key update, formal AKE proof, multi-host evaluation, and side-channel validation are outside this proof of concept.

## Environment

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

Create a local test identity in a directory that does not already exist. The certificate SAN is the authoritative server name, so provisioning does not create a separate metadata file.

```powershell
.venv\Scripts\python -m tls_pqc_bridge.identity credentials --server-name localhost
```

## Run Alice and Bob directly

Start Bob in one terminal:

```powershell
.venv\Scripts\python bob.py --mode hybrid --host 127.0.0.1 --port 4433 --credentials credentials --ready-file artifacts\bob-ready.json --result-file artifacts\bob-result.json
```

After `bob-ready.json` appears, start Alice in another terminal:

```powershell
.venv\Scripts\python alice.py --mode hybrid --host 127.0.0.1 --port 4433 --server-name localhost --credentials credentials --payload-bytes 1048576 --result-file artifacts\alice-result.json
```

Use the same mode at both endpoints. `baseline` selects classical X25519 TLS, `native` selects native `X25519MLKEM768` TLS, and `hybrid` selects X25519 TLS plus the application PQC bridge. Alice and Bob are independent command-line programs using reusable endpoint code.

## Run the experiment and recreate figures

The default experiment measures 16 repetitions of all three modes at 1 KiB, 100 KiB, 1 MiB, 100 MiB, 500 MiB, and 1 GiB per direction: 288 measured connections. It performs two warm-ups per mode, shuffles the full condition plan with seed `0xC0FFEE`, and starts fresh Alice and Bob processes for every observation. The output directory must not exist.

```powershell
.venv\Scripts\python benchmark.py --credentials credentials --server-name localhost --output results\fresh-run
.venv\Scripts\python plot.py results\fresh-run
```

To recreate the retained figures without rerunning the experiment:

```powershell
.venv\Scripts\python plot.py results\2026-09-05-loopback-final
```

## Source layout

| Path | Responsibility |
|---|---|
| `alice.py` | Runnable Alice client. |
| `bob.py` | Runnable Bob server. |
| `benchmark.py` | Process-isolated experiments. |
| `plot.py` | Research figures. |
| `tls_pqc_bridge/` | Reusable protocol, cryptography, framing, identity, transfer, and TLS modules. |
| `PROTOCOL.md` | Protocol description. |


## Limitations

The retained measurements use IPv4 loopback on Windows 11 host without network emulation. They measure this implementation and software stack. They do not measure Internet or two-host latency, loss, MTU behavior, energy use, concurrency, server capacity, a constrained or legacy platform, or operational deployment effort.
