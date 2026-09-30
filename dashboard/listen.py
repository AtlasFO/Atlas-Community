"""Listen-address, TLS material, and Host-header allowlist for the dashboard.

Kept out of serve.py so the bind/TLS policy can be unit-tested without
standing up ThreadingTCPServer. serve.py is the only runtime caller.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import socket
import ssl
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence

SYSTEM_TLS_DIR = Path("/etc/atlas/dashboard")
USER_TLS_DIR = Path(os.path.expanduser("~/.config/atlas/dashboard/tls"))

_HOSTNAME_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
_LOOPBACK_NAMES = frozenset({
    "127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1",
})


class TlsError(Exception):
    """Raised when TLS material is missing, unreadable, or too permissive."""


def is_loopback_bind(host: str) -> bool:
    value = (host or "").strip().lower()
    if value in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def tls_required(bind_host: str) -> bool:
    return not is_loopback_bind(bind_host)


def parse_bind_host(value: str) -> str:
    host = (value or "").strip()
    if not host:
        raise ValueError("bind address is empty")
    lowered = host.lower()
    if lowered == "localhost":
        return "localhost"
    if lowered == "0.0.0.0":
        return host
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if addr.version == 6:
            # _bind()'s ThreadingTCPServer is AF_INET-only; any IPv6
            # literal (including loopback ::1) would otherwise fail at
            # socket-creation with a misleading "no free port" error
            # instead of this clear one.
            raise ValueError(
                f"IPv6 bind addresses are not supported: {value!r} — "
                "use an IPv4 address or hostname")
        return host
    if _HOSTNAME_RE.match(host):
        return host
    raise ValueError(f"invalid bind address: {value!r}")


def normalize_host_header(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return raw.lower()
        return raw[1:end].lower()
    # hostname:port or ipv4:port — last colon is the port separator
    # unless this is a bare IPv6 literal (more than one colon, no brackets).
    if raw.count(":") == 1:
        host, _port = raw.rsplit(":", 1)
        return host.lower()
    return raw.lower()


def _extra_hosts(extra: str) -> list[str]:
    names: list[str] = []
    for part in (extra or "").split(","):
        name = normalize_host_header(part)
        if name:
            names.append(name)
    return names


def local_ipv4_addresses() -> list[str]:
    addrs: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in addrs:
                addrs.append(ip)
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(None, None, socket.AF_INET, socket.SOCK_DGRAM):
            ip = info[4][0]
            if ip and ip not in addrs:
                addrs.append(ip)
    except OSError:
        pass
    # Best-effort: UDP connect trick for the outbound interface.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("1.1.1.1", 80))
        ip = probe.getsockname()[0]
        probe.close()
        if ip not in addrs:
            addrs.append(ip)
    except OSError:
        pass
    return addrs


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        addr.is_global
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_unspecified
        and not addr.is_reserved
        and not addr.is_private
    )


def public_addresses(addrs: Optional[Iterable[str]] = None) -> list[str]:
    return [a for a in (addrs if addrs is not None else local_ipv4_addresses())
            if is_public_ip(a)]


def build_host_allowlist(bind_host: str, extra: str = "") -> frozenset[str]:
    names: set[str] = set(_LOOPBACK_NAMES)
    names.add("localhost")
    bind = (bind_host or "").strip().lower()
    if bind and bind not in ("0.0.0.0", "::"):
        names.add(bind)
    try:
        hn = socket.gethostname().lower()
        if hn:
            names.add(hn)
            if "." not in hn:
                # short hostname; also add FQDN when resolvable
                try:
                    fqdn = socket.getfqdn().lower()
                    if fqdn:
                        names.add(fqdn)
                except OSError:
                    pass
    except OSError:
        pass
    for ip in local_ipv4_addresses():
        names.add(ip.lower())
    names.update(_extra_hosts(extra))
    return frozenset(names)


def host_header_allowed(header: str, allowlist: frozenset[str]) -> bool:
    name = normalize_host_header(header)
    if not name:
        return False
    lowered = {n.lower() for n in allowlist}
    return name in lowered


def assert_private_key_perms(key_path: Path) -> None:
    try:
        mode = stat.S_IMODE(key_path.stat().st_mode)
    except OSError as exc:
        raise TlsError(f"cannot stat TLS key {key_path}: {exc}") from exc
    if mode & 0o077:
        raise TlsError(
            f"TLS private key {key_path} is group/world-accessible "
            f"(mode {mode:04o}); chmod 600 and retry")


def _pair_if_present(cert: Path, key: Path) -> Optional[tuple[Path, Path]]:
    if cert.is_file() and key.is_file():
        assert_private_key_perms(key)
        return cert, key
    return None


def generate_self_signed(
    dest_dir: Path,
    names: Sequence[str] | None = None,
) -> tuple[Path, Path]:
    """Write cert.pem + key.pem (0600) under dest_dir. Returns those paths."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    dest_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)  # mkdir's mode is umask-affected; force it
    cert_path = dest_dir / "cert.pem"
    key_path = dest_dir / "key.pem"

    san_names = [n for n in (names or []) if n]
    if "localhost" not in san_names:
        san_names = ["localhost", *san_names]
    if "127.0.0.1" not in san_names:
        san_names.append("127.0.0.1")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    san: list[x509.GeneralName] = []
    seen: set[str] = set()
    for raw in san_names:
        item = raw.strip()
        if not item or item.lower() in seen:
            continue
        seen.add(item.lower())
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(item)))
        except ValueError:
            san.append(x509.DNSName(item))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, san_names[0]),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        # Chrome rejects certificates whose lifetime exceeds 398 days
        # (NET::ERR_CERT_VALIDITY_TOO_LONG) — 397 keeps a self-signed
        # fallback in the "untrusted, but valid" bucket rather than invalid.
        .not_valid_after(now + timedelta(days=397))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    old_umask = os.umask(0o077)
    try:
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        os.chmod(key_path, 0o600)
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(cert_path, 0o644)
    finally:
        os.umask(old_umask)
    return cert_path, key_path


def cert_sha256_fingerprint(cert_path: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def make_tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    assert_private_key_perms(key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def resolve_tls_files(
    bind_host: str,
    *,
    env_cert: str | None = None,
    env_key: str | None = None,
    system_dir: Path | None = None,
    user_dir: Path | None = None,
    generate: bool = True,
    san_names: Sequence[str] | None = None,
) -> Optional[tuple[Path, Path, bool]]:
    """Return (cert, key, generated) or None when TLS is not required.

    Search order: env paths, system_dir/{tls.crt,tls.key},
    user_dir/{cert.pem,key.pem}, then (if generate) mint into user_dir.
    """
    if not tls_required(bind_host):
        return None
    system_dir = Path(system_dir) if system_dir is not None else SYSTEM_TLS_DIR
    user_dir = Path(user_dir) if user_dir is not None else USER_TLS_DIR

    if env_cert and env_key:
        pair = _pair_if_present(Path(env_cert).expanduser(),
                                Path(env_key).expanduser())
        if pair:
            return pair[0], pair[1], False
        raise TlsError(
            "ATLAS_DASHBOARD_TLS_CERT/KEY are set but the files are missing "
            f"or unreadable (cert={env_cert!r}, key={env_key!r})")

    pair = _pair_if_present(system_dir / "tls.crt", system_dir / "tls.key")
    if pair:
        return pair[0], pair[1], False

    pair = _pair_if_present(user_dir / "cert.pem", user_dir / "key.pem")
    if pair:
        return pair[0], pair[1], False

    if not generate:
        raise TlsError(
            "no TLS certificate found for a non-loopback dashboard bind; "
            "install files at /etc/atlas/dashboard/tls.crt+tls.key, "
            "~/.config/atlas/dashboard/tls/cert.pem+key.pem, or set "
            "ATLAS_DASHBOARD_TLS_CERT and ATLAS_DASHBOARD_TLS_KEY")

    names = list(san_names or [])
    if not names:
        names = ["localhost", "127.0.0.1", *local_ipv4_addresses()]
        try:
            names.insert(0, socket.gethostname())
        except OSError:
            pass
    cert, key = generate_self_signed(user_dir, names=names)
    return cert, key, True


def wrap_socket(httpd, cert: Path, key: Path) -> None:
    """Replace httpd.socket with a TLS-wrapped listening socket (in place)."""
    ctx = make_tls_context(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
