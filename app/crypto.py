"""Cryptographic helpers for Ed25519 license signing."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _canonical_json(data: Any) -> str:
    """Stable JSON for signing (sorted keys, no spaces, UTF-8)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_key(key_text: str) -> str:
    """SHA-256 hash of a license key string."""
    return hashlib.sha256(key_text.strip().encode("utf-8")).hexdigest()


def generate_keypair(private_path: Path, public_path: Path) -> None:
    """Generate a new Ed25519 key pair and write PEM files."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    os.chmod(private_path, 0o600)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load the Ed25519 private key from PEM."""
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Private key is not Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load the Ed25519 public key from PEM."""
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Public key is not Ed25519")
    return key


def sign_payload(private_key: Ed25519PrivateKey, payload: Any) -> str:
    """Sign a canonical JSON payload and return the hex signature."""
    canonical = _canonical_json(payload).encode("utf-8")
    return private_key.sign(canonical).hex()


def verify_payload(public_key: Ed25519PublicKey, payload: Any, signature_hex: str) -> bool:
    """Verify a hex Ed25519 signature over a canonical JSON payload."""
    try:
        sig = bytes.fromhex(signature_hex)
        canonical = _canonical_json(payload).encode("utf-8")
        public_key.verify(sig, canonical)
        return True
    except Exception:  # noqa: BLE001
        return False


def generate_unlock_code(
    private_key: Ed25519PrivateKey,
    installation_id: str,
    validity_hours: int = 48,
    offline_grace_days: int = 10,
) -> str:
    """Generate a base64url(payload).sig one-time unlock code."""
    import time

    now = time.time()
    payload = {
        "installation_id": installation_id,
        "issued_at": now,
        "expires_at": now + (validity_hours * 3600),
        "offline_grace_days": offline_grace_days,
    }
    payload_json = _canonical_json(payload)
    sig = private_key.sign(payload_json.encode("utf-8")).hex()
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode()
    return f"{payload_b64}.{sig}"
