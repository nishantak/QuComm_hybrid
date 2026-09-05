# TLS-PQC Bridge protocol

## Scope and standards relationship

TLS-PQC Bridge is a server-authenticated two-plane application protocol carried by TLS 1.3. The TLS plane contributes a 32-byte exporter value, $k_1$. The PQC plane contributes a 32-byte secret, $k_2$, from an ephemeral ML-KEM-768 exchange authenticated by a provisioned ML-DSA-65 server identity. The key bridge combines the two values and the exchange transcript before bridge-protected application records are enabled.

TLS exporters bind an external protocol to one TLS session. The private-use label and context below separate this use from other exporters ([RFC 5705, Sections 3-4](https://www.rfc-editor.org/rfc/rfc5705.html#section-3); [RFC 9846, Section 7.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-7.5)). TLS 1.3 is specified by RFC 9846, which obsoletes RFC 8446. ML-KEM-768 and ML-DSA-65 are the parameter sets defined by [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) and [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204).

The key bridge is an ETSI-aligned CatKDF instantiation. [ETSI TS 103 744 V1.2.1, Clause 8.2.3](https://www.etsi.org/deliver/etsi_TS/103700_103799/103744/01.02.01_60/ts_103744v010201p.pdf) specifies fixed-order secret concatenation, application information and exchanged messages in a context-formatting function, and a KDF with a separating label. This protocol uses the ETSI HKDF mapping: the label is HKDF salt and the formatted context is HKDF info. It does not claim full ETSI conformance because the first input is a TLS exporter rather than one of the Clause 7.7.2 key-establishment parameter sets.

The PQC exchange does not place ML-KEM material in the TLS `key_share` extension or the TLS key schedule. It is therefore distinct from the native hybrid construction in [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html) and the named groups in [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html). Native hybrid TLS is the preferred standardized choice when both endpoints can require it. TLS-PQC Bridge instead serves controlled applications that can change their application protocol and provision a PQC identity but cannot depend on their TLS termination layer to expose, require, or authenticate PQ negotiation.

## Evaluated modes and TLS plane

The benchmark defines three exact modes. The CLI names are stable machine identifiers; figures use the public labels in this table.

| CLI mode | Public label | Required TLS group | ALPN | Application protection |
|---|---|---|---|---|
| `baseline` | Classical TLS | `X25519` | `qcomm/baseline/1` | Framed TLS application data |
| `native` | Native hybrid TLS | `X25519MLKEM768` | `qcomm/baseline/1` | Framed TLS application data |
| `hybrid` | TLS + PQC bridge | `X25519` | `qcomm/hybrid/1` | PQC exchange, then bridge-protected records inside TLS |

Classical TLS and native hybrid TLS deliberately share an ALPN because their application protocol is identical; their enforced TLS groups are the experimental difference. TLS + PQC bridge has a different ALPN because it adds the PQC exchange and protected-record state machine. Each endpoint configures exactly one TLS group through OpenSSL's `SSL_CTX_set1_curves_list` API, reached through pyOpenSSL's bundled binding. Both endpoints then read and verify the negotiated group. A missing setter, unsupported group, group mismatch, or unreported group is fatal. No TLS library source is modified.

Every mode requires TLS 1.3, a certificate chain rooted in the configured CA, a valid certificate service identity, and one of the project's accepted TLS 1.3 AEAD suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, or `TLS_CHACHA20_POLY1305_SHA256`. Each endpoint also verifies the exact ALPN shown above. There is no TLS-version, certificate, identity, group, mode, ALPN, or bridge-to-classical fallback.

Alice canonicalizes the configured service identity before TLS. DNS names use IDNA2008 with UTS #46 processing, STD3 rules, and non-transitional mapping; the canonical value is a lower-case ASCII A-label with one terminal root dot removed. IP literals use canonical address text. DNS names are sent as SNI; IP literals are not, because the `HostName` form in [RFC 6066, Section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3) excludes address literals. Certificate verification applies the corresponding DNS-ID or IP-ID rule. The same canonical identity enters the exporter context, ML-DSA input, and CatKDF context.

In TLS + PQC bridge mode, both endpoints derive:

```text
context = SHA-256(
    "QCOMM-TWO-PLANE-V1" || 0x00 ||
    "TLS13-EXPORTER-MLKEM768-MLDSA65-HKDFSHA256-AES256GCM" || 0x00 ||
    UTF8(server_name)
)

k1 = TLS-Exporter(
    label   = "EXPERIMENTAL-QCOMM-TWO-PLANE-V1",
    context = context,
    length  = 32
)
```

The label begins with `EXPERIMENTAL` as required for private use by RFC 5705 Section 4. `HKDFSHA256` in the suite identifier names the CatKDF below; the exporter uses the hash selected by the negotiated TLS 1.3 cipher suite.

## Framing

Every project message is TLS application data. A frame is:

```text
magic[4] = "QCHN"
version  = uint8(1)
type     = uint8
flags    = uint16(0)
length   = uint32
payload  = opaque[length]
```

Integers use network byte order. A receiver validates the magic, version, type, zero flags, type-specific length limit, full payload, and the message required by its current state. It rejects the length before allocating peer-controlled payload storage.

## PQC exchange and server authentication

Bob is initiator $A$ in the ETSI KEM transaction because he creates and sends the ephemeral encapsulation key. After TLS completes, Alice and Bob exchange four ordered one-way messages:

```text
Bob                                                   Alice
 |                                                     |
 | SERVER_INIT = nonce || ML-KEM public key || sig    |
 |---------------------------------------------------->|
 |                                                     | verify pinned ML-DSA key
 |                  CLIENT_KEM = ML-KEM ciphertext     |
 |<----------------------------------------------------|
 | decapsulate; derive key-bridge material              | derive key-bridge material
 |                  SERVER_FINISHED = HMAC             |
 |---------------------------------------------------->|
 |                  CLIENT_FINISHED = HMAC             |
 |<----------------------------------------------------|
 | enable bridge-protected records                      | enable bridge-protected records
```

Bob generates a new ML-KEM-768 key pair and a 32-byte random nonce for every connection. His persistent ML-DSA-65 key signs:

```text
"QCOMM-TWO-PLANE-V1/server-auth/" ||
SHA-256(
    L(protocol_id)       || protocol_id       ||
    L(suite_id)          || suite_id          ||
    L(k1)                || k1                ||
    L(UTF8(server_name)) || UTF8(server_name) ||
    L(identity_hash)     || identity_hash     ||
    L(server_nonce)      || server_nonce      ||
    L(kem_public_key)    || kem_public_key
)
```

`L(x)` is the four-byte length of `x`; `identity_hash` is SHA-256 of Alice's provisioned ML-DSA public key. Alice aborts unless verification returns `True`. A key sent by the peer cannot create trust: the verification key exists only in Alice's configuration.

Let $M_A$ be the exact encoded `SERVER_INIT` frame and $M_B$ the exact encoded `CLIENT_KEM` frame, including their headers. The key bridge is:

```text
secret = k1 || k2

key_schedule_id = "QCOMM two-plane handshake and application key schedule v1"
info = LengthDelimit(
           protocol_id, suite_id, UTF8(server_name),
           SHA-256(pinned_mldsa_public_key), key_schedule_id
       )
context = SHA-256(L(info) || info || L(M_A) || M_A || L(M_B) || M_B)

material = HKDF-SHA256(
    IKM  = secret,
    salt = "QCOMM-CATKDF-V1",
    info = context,
    L    = 152
)
```

This is the ETSI concatenate-and-hash context function applied to `(info, M_A, M_B)`, followed by its HKDF mapping. The fixed input order is TLS exporter first and ML-KEM secret second. The 152 output bytes are partitioned once into the client Finished key (32), server Finished key (32), client application key (32), client static IV (12), server application key (32), and server static IV (12).

Let `th = SHA-256(M_A || M_B)`. Bob's Finished value is HMAC-SHA256 under the server Finished key over the length-delimited tuple `(protocol_id, "finished", "server", th)`. Alice's Finished value uses `(protocol_id, "finished", "client", th, encoded_server_finished_frame)`. Alice verifies Bob's MAC before sending hers; Bob verifies Alice's MAC before accepting application data. A modified KEM ciphertext therefore fails key confirmation even when ML-KEM decapsulation returns an implicit-rejection key. Bilateral MAC confirmation follows the mechanism described in [NIST SP 800-227, Section 4.4](https://doi.org/10.6028/NIST.SP.800-227).

## Bridge-protected application records

Classical TLS and native hybrid TLS carry the application frames directly in TLS. TLS + PQC bridge wraps each application message in a `PROTECTED` project frame whose payload is:

```text
sequence_number : uint64
content_type    : uint8
ciphertext      : AES-256-GCM(plaintext, nonce, aad)
```

For direction `D` (`C` for Alice-to-Bob and `S` for Bob-to-Alice), sequence number `s`, content type `t`, and plaintext length `n`:

```text
nonce = static_iv XOR uint96(s)
aad   = protocol_id || D || uint64(s) || uint8(t) || uint32(n)
```

Keys and IVs differ by direction. Sequence numbers start at zero. An outbound sequence number is consumed by an attempted record; an inbound sequence number advances only after successful tag verification. A receiver requires the next exact sequence number before decryption. Modification, replay, reordering, a gap, wrong direction, wrong type, wrong length, oversize data, or record-limit exhaustion terminates the connection. Each direction is limited to $2^{15}$ records per key, above the maximum required by the permitted 1 GiB transfer. This version reconnects instead of implementing key update.

## Application transfer state machine

The application first performs one mandatory authenticated 32-byte PING/PONG, then sends a payload to Bob and returns the same generated content to Alice:

```text
Alice -> Bob: TRANSFER_START, TRANSFER_DATA*, TRANSFER_END
Bob -> Alice: TRANSFER_START, TRANSFER_DATA*, TRANSFER_END
Alice -> Bob: TRANSFER_ACK
```

`TRANSFER_START` contains a uint64 total and a 32-byte random seed. Each data message contains its uint64 offset and the next payload block. SHAKE-256 expands the seed, and each endpoint streams bounded chunks without retaining the full payload. `TRANSFER_END` and `TRANSFER_ACK` contain the byte count and SHA-256 digest. A peer rejects a size above 1 GiB, a wrong state transition, a partial or oversized chunk, a non-contiguous offset, different content, a wrong total, or a wrong digest.

The payload limit makes the largest bridge-protected `TRANSFER_DATA` frame exactly 65,536 bytes after project framing, sequence, content type, offset, and GCM tag are included. TCP `NODELAY` is enabled in every mode so small control messages and short final segments are not coupled to delayed-ACK behavior.

After socket establishment, one non-renewing deadline covers TLS, the PQC exchange, and the application transfer. Alice's preceding TCP connection and Bob's preceding `accept()` have their own bounded waits using the same configured duration. Partial input cannot renew any deadline.

## Security argument and boundary

The TLS exporter binds $k_1$ to the authenticated TLS session. Bob's ML-DSA signature binds his ephemeral ML-KEM key, identity, service name, and algorithm suite to that exporter. CatKDF binds $k_1$, $k_2$, both exchange frames, identity, and suite. Finished MACs detect unequal key derivation. Application authentication covers direction, order, type, length, and content.

Under correct primitive implementations, sound randomness, protected endpoint keys, trustworthy pin provisioning, and the assumption that HKDF-SHA256 is a suitable extractor and PRF, the bridge-protected keys are intended to remain unknown while either $k_1$ or $k_2$ remains unknown to the adversary. This is an assumption-bounded combiner argument, not a formal authenticated-key-exchange proof for TLS-PQC Bridge.

- If the PQC algorithms fail while the authenticated TLS session remains secure, the TLS plane still protects the PQC exchange and application data, and $k_1$ remains unknown.
- If classical TLS key establishment and certificate authentication become breakable while ML-KEM, ML-DSA, the provisioned pin, and the bridge primitives remain secure, an active attacker cannot sign Alice's different exporter-bound context or derive the bridge-protected keys.
- A passive harvest-now/decrypt-later attacker who later recovers a classical TLS secret still lacks $k_2$. The bridge cannot retroactively protect sessions created before deployment.
- If native `X25519MLKEM768` was required and negotiated, native TLS already protects passive recorded confidentiality; the bridge's distinct security contribution is the separately provisioned ML-DSA server-authentication policy and a second application-enforced KEM requirement.

The protocol authenticates Bob to Alice, not Alice to Bob. It does not establish formal AKE security, FIPS-module validation, ETSI protocol conformance, scalable PQC identity lifecycle, production key custody, resumption, key update, side-channel resistance, secret zeroization, or security after both plane inputs or endpoint memory are exposed.
