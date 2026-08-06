"""OpenSSL-backed Ed25519 helpers for governance capsules."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ._contracts import CapsuleError


def _openssl() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise CapsuleError("OpenSSL executable is required for Ed25519 operations")
    return executable


def _run(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            [_openssl(), *arguments],
            check=True,
            capture_output=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise CapsuleError("OpenSSL operation timed out") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()[:1024]
        raise CapsuleError(f"OpenSSL operation failed: {detail}") from exc


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a PEM private/public Ed25519 keypair with OpenSSL."""
    with tempfile.TemporaryDirectory(prefix="liminal-ed25519-") as directory:
        root = Path(directory)
        private_path = root / "private.pem"
        public_path = root / "public.pem"
        _run(["genpkey", "-algorithm", "ED25519", "-out", str(private_path)])
        _run([
            "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)
        ])
        return private_path.read_bytes(), public_path.read_bytes()


def derive_public_key(private_key_pem: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="liminal-ed25519-") as directory:
        root = Path(directory)
        private_path = root / "private.pem"
        public_path = root / "public.pem"
        _write_private(private_path, private_key_pem)
        _run([
            "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)
        ])
        return public_path.read_bytes()


def sign_ed25519(private_key_pem: bytes, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="liminal-ed25519-") as directory:
        root = Path(directory)
        private_path = root / "private.pem"
        message_path = root / "message.bin"
        signature_path = root / "signature.bin"
        _write_private(private_path, private_key_pem)
        message_path.write_bytes(message)
        _run([
            "pkeyutl", "-sign", "-inkey", str(private_path), "-rawin",
            "-in", str(message_path), "-out", str(signature_path),
        ])
        return signature_path.read_bytes()


def verify_ed25519(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="liminal-ed25519-") as directory:
        root = Path(directory)
        public_path = root / "public.pem"
        message_path = root / "message.bin"
        signature_path = root / "signature.bin"
        public_path.write_bytes(public_key_pem)
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        try:
            _run([
                "pkeyutl", "-verify", "-pubin", "-inkey", str(public_path),
                "-rawin", "-in", str(message_path),
                "-sigfile", str(signature_path),
            ])
        except CapsuleError:
            return False
        return True


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise CapsuleError("signature_b64url is invalid") from exc
    if base64url_encode(decoded) != value:
        raise CapsuleError("signature_b64url is not canonical unpadded base64url")
    return decoded
