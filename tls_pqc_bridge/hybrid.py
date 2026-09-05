import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from tls_pqc_bridge.errors import AuthenticationError, ProtocolError
from tls_pqc_bridge.framing import FramedTransport
from tls_pqc_bridge.identity import ServerIdentity
from tls_pqc_bridge.protocol import (
    AES_IV_SIZE,
    AES_KEY_SIZE,
    CATKDF_LABEL,
    FINISHED_SIZE,
    NONCE_SIZE,
    PROTOCOL_ID,
    SUITE_ID,
    MessageType,
)


KEY_MATERIAL_SIZE = 2 * FINISHED_SIZE + 2 * (AES_KEY_SIZE + AES_IV_SIZE)
KDF_INFO = b"QCOMM two-plane handshake and application key schedule v1"


@dataclass(frozen=True)
class TrafficSecrets:
    client_finished_key: bytes
    server_finished_key: bytes
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes

    def __post_init__(self) -> None:
        expected_sizes = {
            "client_finished_key": FINISHED_SIZE,
            "server_finished_key": FINISHED_SIZE,
            "client_key": AES_KEY_SIZE,
            "client_iv": AES_IV_SIZE,
            "server_key": AES_KEY_SIZE,
            "server_iv": AES_IV_SIZE,
        }
        for field, size in expected_sizes.items():
            value = getattr(self, field)
            if not isinstance(value, bytes) or len(value) != size:
                raise ValueError(f"{field} must be exactly {size} bytes")


@dataclass(frozen=True)
class HandshakeResult:
    secrets: TrafficSecrets
    metrics: dict[str, float]


def catkdf(
    classical_secret: bytes,
    post_quantum_secret: bytes,
    server_name: str,
    pinned_identity: bytes,
    server_message: bytes,
    client_message: bytes,
) -> TrafficSecrets:
    if len(classical_secret) != 32 or len(post_quantum_secret) != 32:
        raise ValueError("CatKDF inputs must each be 32 bytes")
    identity_hash = hashlib.sha256(pinned_identity).digest()
    info = _length_delimit(
        PROTOCOL_ID, SUITE_ID, server_name.encode("utf-8"), identity_hash, KDF_INFO
    )
    context = concatenate_and_hash(info, server_message, client_message)
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_MATERIAL_SIZE,
        salt=CATKDF_LABEL,
        info=context,
    ).derive(classical_secret + post_quantum_secret)

    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        value = material[offset : offset + size]
        offset += size
        return value

    secrets_out = TrafficSecrets(
        client_finished_key=take(FINISHED_SIZE),
        server_finished_key=take(FINISHED_SIZE),
        client_key=take(AES_KEY_SIZE),
        client_iv=take(AES_IV_SIZE),
        server_key=take(AES_KEY_SIZE),
        server_iv=take(AES_IV_SIZE),
    )
    if offset != len(material):
        raise AssertionError("key schedule partition is incomplete")
    return secrets_out


def concatenate_and_hash(*values: bytes) -> bytes:
    digest = hashlib.sha256()
    for value in values:
        if len(value) >= 2**32:
            raise ValueError("CatKDF context value exceeds the uint32 length domain")
        digest.update(struct.pack("!I", len(value)))
        digest.update(value)
    return digest.digest()


def client_handshake(
    transport: FramedTransport,
    classical_secret: bytes,
    pinned_identity: bytes,
    server_name: str,
) -> HandshakeResult:
    started = time.perf_counter_ns()
    server_frame = transport.receive(MessageType.SERVER_INIT)
    expected_size = NONCE_SIZE + ml_kem_768.PUBLIC_KEY_SIZE + ml_dsa_65.SIGNATURE_SIZE
    if len(server_frame.payload) != expected_size:
        raise ProtocolError(
            f"SERVER_INIT is {len(server_frame.payload)} bytes; expected {expected_size}"
        )
    server_wire = server_frame.wire
    server_nonce = server_frame.payload[:NONCE_SIZE]
    kem_public_end = NONCE_SIZE + ml_kem_768.PUBLIC_KEY_SIZE
    kem_public = server_frame.payload[NONCE_SIZE:kem_public_end]
    signature = server_frame.payload[kem_public_end:]

    verify_started = time.perf_counter_ns()
    authentication_message = _server_authentication_message(
        classical_secret, server_name, pinned_identity, server_nonce, kem_public
    )
    try:
        verified = ml_dsa_65.verify(pinned_identity, authentication_message, signature)
    except ValueError as error:
        raise AuthenticationError("ML-DSA server signature is malformed") from error
    if not verified:
        raise AuthenticationError("ML-DSA server authentication failed")
    verify_ms = _elapsed_ms(verify_started)

    encapsulation_started = time.perf_counter_ns()
    try:
        kem_ciphertext, post_quantum_secret = ml_kem_768.encrypt(kem_public)
    except ValueError as error:
        raise AuthenticationError("server ML-KEM public key is invalid") from error
    encapsulation_ms = _elapsed_ms(encapsulation_started)
    client_wire = transport.send(MessageType.CLIENT_KEM, kem_ciphertext)

    kdf_started = time.perf_counter_ns()
    key_material = catkdf(
        classical_secret,
        post_quantum_secret,
        server_name,
        pinned_identity,
        server_wire,
        client_wire,
    )
    kdf_ms = _elapsed_ms(kdf_started)
    transcript_hash = hashlib.sha256(server_wire + client_wire).digest()

    server_finished_frame = transport.receive(MessageType.SERVER_FINISHED)
    if len(server_finished_frame.payload) != FINISHED_SIZE:
        raise ProtocolError("SERVER_FINISHED has an invalid length")
    expected_server_finished = _finished_mac(
        key_material.server_finished_key, b"server", transcript_hash
    )
    if not hmac.compare_digest(server_finished_frame.payload, expected_server_finished):
        raise AuthenticationError("server key confirmation failed")

    client_finished = _finished_mac(
        key_material.client_finished_key,
        b"client",
        transcript_hash,
        server_finished_frame.wire,
    )
    transport.send(MessageType.CLIENT_FINISHED, client_finished)
    return HandshakeResult(
        key_material,
        {
            "pqc_signature_verify_ms": verify_ms,
            "pqc_encapsulation_ms": encapsulation_ms,
            "pqc_kdf_ms": kdf_ms,
            "pqc_handshake_ms": _elapsed_ms(started),
        },
    )


def server_handshake(
    transport: FramedTransport,
    classical_secret: bytes,
    identity: ServerIdentity,
) -> HandshakeResult:
    started = time.perf_counter_ns()
    keygen_started = time.perf_counter_ns()
    kem_public, kem_secret = ml_kem_768.generate_keypair()
    keygen_ms = _elapsed_ms(keygen_started)
    server_nonce = secrets.token_bytes(NONCE_SIZE)

    sign_started = time.perf_counter_ns()
    authentication_message = _server_authentication_message(
        classical_secret,
        identity.server_name,
        identity.public_key,
        server_nonce,
        kem_public,
    )
    signature = ml_dsa_65.sign(identity.secret_key, authentication_message)
    sign_ms = _elapsed_ms(sign_started)
    server_wire = transport.send(
        MessageType.SERVER_INIT, server_nonce + kem_public + signature
    )

    client_frame = transport.receive(MessageType.CLIENT_KEM)
    if len(client_frame.payload) != ml_kem_768.CIPHERTEXT_SIZE:
        raise ProtocolError(
            f"CLIENT_KEM is {len(client_frame.payload)} bytes; "
            f"expected {ml_kem_768.CIPHERTEXT_SIZE}"
        )
    client_wire = client_frame.wire
    decapsulation_started = time.perf_counter_ns()
    try:
        post_quantum_secret = ml_kem_768.decrypt(kem_secret, client_frame.payload)
    except ValueError as error:
        raise AuthenticationError(
            "ML-KEM decapsulation rejected the ciphertext"
        ) from error
    decapsulation_ms = _elapsed_ms(decapsulation_started)

    kdf_started = time.perf_counter_ns()
    key_material = catkdf(
        classical_secret,
        post_quantum_secret,
        identity.server_name,
        identity.public_key,
        server_wire,
        client_wire,
    )
    kdf_ms = _elapsed_ms(kdf_started)
    transcript_hash = hashlib.sha256(server_wire + client_wire).digest()
    server_finished = _finished_mac(
        key_material.server_finished_key, b"server", transcript_hash
    )
    server_finished_wire = transport.send(MessageType.SERVER_FINISHED, server_finished)

    client_finished_frame = transport.receive(MessageType.CLIENT_FINISHED)
    if len(client_finished_frame.payload) != FINISHED_SIZE:
        raise ProtocolError("CLIENT_FINISHED has an invalid length")
    expected_client_finished = _finished_mac(
        key_material.client_finished_key,
        b"client",
        transcript_hash,
        server_finished_wire,
    )
    if not hmac.compare_digest(client_finished_frame.payload, expected_client_finished):
        raise AuthenticationError("client key confirmation failed")
    return HandshakeResult(
        key_material,
        {
            "pqc_kem_keygen_ms": keygen_ms,
            "pqc_signature_sign_ms": sign_ms,
            "pqc_decapsulation_ms": decapsulation_ms,
            "pqc_kdf_ms": kdf_ms,
            "pqc_handshake_ms": _elapsed_ms(started),
        },
    )


def _server_authentication_message(
    classical_secret: bytes,
    server_name: str,
    public_identity: bytes,
    server_nonce: bytes,
    kem_public: bytes,
) -> bytes:
    context = concatenate_and_hash(
        PROTOCOL_ID,
        SUITE_ID,
        classical_secret,
        server_name.encode("utf-8"),
        hashlib.sha256(public_identity).digest(),
        server_nonce,
        kem_public,
    )
    return PROTOCOL_ID + b"/server-auth/" + context


def _finished_mac(key: bytes, role: bytes, *transcript_parts: bytes) -> bytes:
    return hmac.digest(
        key,
        _length_delimit(PROTOCOL_ID, b"finished", role, *transcript_parts),
        "sha256",
    )


def _length_delimit(*values: bytes) -> bytes:
    encoded = bytearray()
    for value in values:
        if len(value) >= 2**32:
            raise ValueError("value exceeds the uint32 length domain")
        encoded.extend(struct.pack("!I", len(value)))
        encoded.extend(value)
    return bytes(encoded)


def _elapsed_ms(started_ns: int) -> float:
    return (time.perf_counter_ns() - started_ns) / 1_000_000
