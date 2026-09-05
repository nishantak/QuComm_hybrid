import argparse
import ipaddress
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import idna
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pqcrypto.sign import ml_dsa_65

from tls_pqc_bridge.errors import ConfigurationError


CA_CERT = "ca-cert.pem"
SERVER_CERT = "server-cert.pem"
SERVER_KEY = "server-key.pem"
MLDSA_PUBLIC = "server-mldsa65-public.bin"
MLDSA_SECRET = "server-mldsa65-secret.bin"


@dataclass(frozen=True)
class CredentialPaths:
    directory: Path

    @property
    def ca_certificate(self) -> Path:
        return self.directory / CA_CERT

    @property
    def server_certificate(self) -> Path:
        return self.directory / SERVER_CERT

    @property
    def server_private_key(self) -> Path:
        return self.directory / SERVER_KEY

    @property
    def mldsa_public_key(self) -> Path:
        return self.directory / MLDSA_PUBLIC

    @property
    def mldsa_secret_key(self) -> Path:
        return self.directory / MLDSA_SECRET


@dataclass(frozen=True)
class ServerIdentity:
    public_key: bytes
    secret_key: bytes
    server_name: str


def provision(directory: Path, server_name: str) -> CredentialPaths:
    server_name = normalize_server_name(server_name)
    directory = directory.resolve()
    if directory.exists():
        raise ConfigurationError(f"credential directory already exists: {directory}")

    directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{directory.name}-", dir=directory.parent))
    try:
        _write_credentials(staging, server_name)
        staging.rename(directory)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return CredentialPaths(directory)


def _write_credentials(directory: Path, server_name: str) -> None:
    now = datetime.now(UTC)
    expires = now + timedelta(days=30)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "TLS-PQC Bridge test CA")]
    )
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=None,
                decipher_only=None,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)])
    try:
        subject_name = x509.IPAddress(ipaddress.ip_address(server_name))
    except ValueError:
        subject_name = x509.DNSName(server_name)
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([subject_name]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=None,
                decipher_only=None,
                crl_sign=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    mldsa_public, mldsa_secret = ml_dsa_65.generate_keypair()
    _write_private(
        directory / SERVER_KEY,
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_public(
        directory / SERVER_CERT,
        server_certificate.public_bytes(serialization.Encoding.PEM),
    )
    _write_public(
        directory / CA_CERT,
        ca_certificate.public_bytes(serialization.Encoding.PEM),
    )
    _write_private(directory / MLDSA_SECRET, mldsa_secret)
    _write_public(directory / MLDSA_PUBLIC, mldsa_public)


def load_server_identity(paths: CredentialPaths) -> ServerIdentity:
    public_key = _read_exact(paths.mldsa_public_key, ml_dsa_65.PUBLIC_KEY_SIZE)
    secret_key = _read_exact(paths.mldsa_secret_key, ml_dsa_65.SECRET_KEY_SIZE)
    message = b"TLS-PQC Bridge ML-DSA-65 identity self-test"
    signature = ml_dsa_65.sign(secret_key, message)
    if not ml_dsa_65.verify(public_key, message, signature):
        raise ConfigurationError("ML-DSA public and secret keys do not form a pair")
    return ServerIdentity(public_key, secret_key, load_server_name(paths))


def load_pinned_public_key(paths: CredentialPaths) -> bytes:
    return _read_exact(paths.mldsa_public_key, ml_dsa_65.PUBLIC_KEY_SIZE)


def load_server_name(paths: CredentialPaths) -> str:
    try:
        certificate = x509.load_pem_x509_certificate(
            paths.server_certificate.read_bytes()
        )
        alternative_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (OSError, ValueError, x509.ExtensionNotFound) as error:
        raise ConfigurationError(
            f"cannot read server identity from certificate: {error}"
        ) from error
    dns_names = alternative_names.get_values_for_type(x509.DNSName)
    ip_addresses = [
        str(address)
        for address in alternative_names.get_values_for_type(x509.IPAddress)
    ]
    names = [*dns_names, *ip_addresses]
    if len(names) != 1:
        raise ConfigurationError(
            "server certificate must contain exactly one DNS/IP SAN"
        )
    return normalize_server_name(names[0])


def normalize_server_name(server_name: str) -> str:
    if not isinstance(server_name, str) or not server_name:
        raise ConfigurationError(
            "server name must be a non-empty DNS name or IP address"
        )
    if "%" in server_name:
        raise ConfigurationError("scoped IP addresses are not valid certificate names")
    try:
        return str(ipaddress.ip_address(server_name))
    except ValueError:
        pass
    try:
        canonical = idna.encode(
            server_name,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii")
    except (idna.IDNAError, UnicodeError) as error:
        raise ConfigurationError(
            f"server name is not valid IDNA2008: {error}"
        ) from error
    if canonical.endswith("."):
        canonical = canonical[:-1]
        if not canonical or canonical.endswith("."):
            raise ConfigurationError("server name has an invalid terminal root label")
        try:
            ipaddress.ip_address(canonical)
        except ValueError:
            pass
        else:
            raise ConfigurationError("IP addresses must not have a terminal root label")
    if len(canonical) > 253:
        raise ConfigurationError("server name must not exceed 253 A-label bytes")
    return canonical.lower()


def _read_exact(path: Path, expected_size: int) -> bytes:
    try:
        value = path.read_bytes()
    except OSError as error:
        raise ConfigurationError(f"cannot read {path}: {error}") from error
    if len(value) != expected_size:
        raise ConfigurationError(
            f"{path.name} is {len(value)} bytes; expected {expected_size}"
        )
    return value


def _write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(value)


def _write_public(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provision a TLS-PQC Bridge test identity"
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--server-name", default="localhost")
    arguments = parser.parse_args()
    paths = provision(arguments.directory, arguments.server_name)
    print(paths.directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
