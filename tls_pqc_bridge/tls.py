import hashlib
import ipaddress
import select
import socket
import time
from pathlib import Path
from typing import Callable, TypeVar

from OpenSSL import SSL
from service_identity.cryptography import (
    verify_certificate_hostname,
    verify_certificate_ip_address,
)
from service_identity.exceptions import VerificationError

from tls_pqc_bridge.errors import AuthenticationError, ConfigurationError
from tls_pqc_bridge.protocol import (
    EXPORTER_LABEL,
    PROTOCOL_ID,
    SUITE_ID,
    TLS_GROUP_BY_MODE,
)


TLS_EXPORTER_SIZE = 32
T = TypeVar("T")
ALLOWED_TLS13_CIPHERS = frozenset(
    {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    }
)
CANONICAL_TLS_GROUP_NAMES = {
    group.casefold(): group for group in TLS_GROUP_BY_MODE.values()
}


def create_client_context(
    ca_certificate: Path, alpn_id: bytes, tls_group: str
) -> SSL.Context:
    context = _tls13_context(tls_group)
    try:
        context.load_verify_locations(str(ca_certificate))
    except SSL.Error as error:
        raise ConfigurationError(f"cannot load CA certificate: {error}") from error
    context.set_verify(SSL.VERIFY_PEER, _preserve_openssl_verification)
    context.set_alpn_protos([alpn_id])
    return context


def create_server_context(
    certificate: Path, private_key: Path, alpn_id: bytes, tls_group: str
) -> SSL.Context:
    context = _tls13_context(tls_group)
    try:
        context.use_certificate_file(str(certificate))
        context.use_privatekey_file(str(private_key))
        context.check_privatekey()
    except SSL.Error as error:
        raise ConfigurationError(f"cannot load TLS server identity: {error}") from error

    def select_alpn(_connection: SSL.Connection, offered: list[bytes]) -> bytes:
        if alpn_id not in offered:
            raise SSL.Error("client did not offer the configured bridge mode")
        return alpn_id

    context.set_alpn_select_callback(select_alpn)
    return context


def wrap_client(
    context: SSL.Context,
    raw_socket: socket.socket,
    server_name: str,
    timeout_seconds: float,
    alpn_id: bytes,
    tls_group: str,
) -> "TlsStream":
    connection = SSL.Connection(context, raw_socket)
    connection.set_connect_state()
    # RFC 6066 HostName values identify DNS names, not address literals.
    try:
        address = ipaddress.ip_address(server_name)
    except ValueError:
        address = None
        connection.set_tlsext_host_name(server_name.encode("ascii"))
    stream = TlsStream(connection, raw_socket, timeout_seconds)
    stream.handshake()
    certificate = connection.get_peer_certificate()
    if certificate is None:
        raise AuthenticationError("TLS server sent no certificate")
    try:
        if address is None:
            verify_certificate_hostname(certificate.to_cryptography(), server_name)
        else:
            verify_certificate_ip_address(certificate.to_cryptography(), server_name)
    except (ValueError, VerificationError) as error:
        raise AuthenticationError(
            f"TLS hostname verification failed: {error}"
        ) from error
    _validate_negotiation(connection, alpn_id, tls_group)
    return stream


def wrap_server(
    context: SSL.Context,
    raw_socket: socket.socket,
    timeout_seconds: float,
    alpn_id: bytes,
    tls_group: str,
) -> "TlsStream":
    connection = SSL.Connection(context, raw_socket)
    connection.set_accept_state()
    stream = TlsStream(connection, raw_socket, timeout_seconds)
    stream.handshake()
    _validate_negotiation(connection, alpn_id, tls_group)
    return stream


class TlsStream:
    def __init__(
        self,
        connection: SSL.Connection,
        raw_socket: socket.socket,
        timeout_seconds: float,
    ):
        self.connection = connection
        self._socket = raw_socket
        self._deadline_at = time.monotonic() + timeout_seconds

    def handshake(self) -> None:
        self._retry(self.connection.do_handshake, self._deadline_at)

    def recv(self, size: int) -> bytes:
        try:
            return self._retry(lambda: self.connection.recv(size), self._deadline_at)
        except SSL.ZeroReturnError:
            return b""

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        sent = 0
        deadline = self._deadline_at
        while sent < len(view):
            count = self._retry(lambda: self.connection.send(view[sent:]), deadline)
            if count <= 0:
                raise ConnectionError("TLS write returned no progress")
            sent += count

    def close(self) -> None:
        deadline = self._deadline_at
        try:
            complete = self._retry(self.connection.shutdown, deadline)
            if not complete:
                self._retry(self.connection.shutdown, deadline)
        except (SSL.Error, OSError, TimeoutError):
            pass
        self.connection.close()

    def _retry(self, operation: Callable[[], T], deadline: float) -> T:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("TLS operation timed out")
            try:
                return operation()
            except SSL.WantReadError:
                self._wait(read=True, deadline=deadline)
            except SSL.WantWriteError:
                self._wait(read=False, deadline=deadline)

    def _wait(self, read: bool, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TLS operation timed out")
        readable = [self._socket] if read else []
        writable = [] if read else [self._socket]
        ready_read, ready_write, _errors = select.select(
            readable, writable, [], remaining
        )
        if not ready_read and not ready_write:
            raise TimeoutError("TLS operation timed out")


def exporter_context(server_name: str) -> bytes:
    name = server_name.encode("utf-8")
    if not name or len(name) > 255:
        raise ConfigurationError("server name must encode to 1..255 UTF-8 bytes")
    return hashlib.sha256(PROTOCOL_ID + b"\x00" + SUITE_ID + b"\x00" + name).digest()


def export_classical_secret(connection: SSL.Connection, server_name: str) -> bytes:
    return connection.export_keying_material(
        EXPORTER_LABEL, TLS_EXPORTER_SIZE, exporter_context(server_name)
    )


def negotiated_parameters(connection: SSL.Connection) -> dict[str, str]:
    return {
        "tls_version": connection.get_protocol_version_name(),
        "tls_cipher": connection.get_cipher_name(),
        "tls_group": _negotiated_group(connection),
        "alpn": connection.get_alpn_proto_negotiated().decode("ascii"),
    }


def _tls13_context(tls_group: str) -> SSL.Context:
    context = SSL.Context(SSL.TLS_METHOD)
    context.set_min_proto_version(SSL.TLS1_3_VERSION)
    context.set_max_proto_version(SSL.TLS1_3_VERSION)
    options = SSL.OP_NO_COMPRESSION
    if hasattr(SSL, "OP_NO_RENEGOTIATION"):
        options |= SSL.OP_NO_RENEGOTIATION
    context.set_options(options)
    _set_tls_group(context, tls_group)
    return context


def _set_tls_group(context: SSL.Context, tls_group: str) -> None:
    # pyOpenSSL exposes group inspection but not OpenSSL's group-list setter.
    try:
        configured = SSL._lib.SSL_CTX_set1_curves_list(
            context._context, tls_group.encode("ascii")
        )
    except (AttributeError, UnicodeEncodeError) as error:
        raise ConfigurationError("TLS group configuration is unavailable") from error
    if configured != 1:
        raise ConfigurationError(f"TLS group is unavailable: {tls_group}")


def _negotiated_group(connection: SSL.Connection) -> str:
    group = connection.get_group_name()
    if not group:
        raise AuthenticationError("connection has no negotiated TLS key-exchange group")
    return CANONICAL_TLS_GROUP_NAMES.get(group.casefold(), group)


def _validate_negotiation(
    connection: SSL.Connection, alpn_id: bytes, tls_group: str
) -> None:
    if connection.get_protocol_version_name() != "TLSv1.3":
        raise AuthenticationError("connection did not negotiate TLS 1.3")
    cipher = connection.get_cipher_name()
    if cipher not in ALLOWED_TLS13_CIPHERS:
        raise AuthenticationError(f"unexpected TLS 1.3 cipher suite: {cipher}")
    negotiated_group = _negotiated_group(connection)
    if negotiated_group != tls_group:
        raise AuthenticationError(
            f"unexpected TLS key-exchange group: {negotiated_group}; "
            f"expected {tls_group}"
        )
    if connection.get_alpn_proto_negotiated() != alpn_id:
        raise AuthenticationError(
            "connection did not negotiate the configured bridge mode"
        )


def _preserve_openssl_verification(
    _connection: SSL.Connection,
    _certificate,
    _error_number: int,
    _depth: int,
    preverified: bool,
) -> bool:
    return preverified
