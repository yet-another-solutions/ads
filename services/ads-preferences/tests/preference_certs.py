from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

OPENSSL = shutil.which("openssl")


def openssl_available() -> bool:
    return OPENSSL is not None


def issue_tls(cert_dir: Path) -> tuple[Path, Path, Path]:
    if OPENSSL is None:
        raise RuntimeError("openssl is required")
    ca_key = cert_dir / "ca.key"
    ca_crt = cert_dir / "ca.crt"
    server_key = cert_dir / "tls.key"
    server_csr = cert_dir / "tls.csr"
    server_crt = cert_dir / "tls.crt"
    ext = cert_dir / "ext.cnf"
    ext.write_text(
        "[v3_req]\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "basicConstraints=CA:FALSE\n"
    )
    _openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        "1",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-subj",
        "/CN=ads-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    _openssl(
        "req",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-keyout",
        str(server_key),
        "-out",
        str(server_csr),
        "-subj",
        "/CN=127.0.0.1",
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        str(server_csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(server_crt),
        "-days",
        "1",
        "-sha256",
        "-extfile",
        str(ext),
        "-extensions",
        "v3_req",
    )
    for path in (ca_crt, server_crt, server_key):
        path.chmod(0o644)
    return ca_crt, server_crt, server_key


def _openssl(*args: str) -> None:
    if OPENSSL is None:
        raise RuntimeError("openssl is required")
    result = subprocess.run([OPENSSL, *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "openssl failed")
