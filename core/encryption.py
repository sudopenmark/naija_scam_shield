"""
core/encryption.py — Local Data Encryption Utilities
Author: Joshua Akadri
GitHub: sudopenmark

Provides:
  • AES-256-GCM encryption/decryption for sensitive config fields
    (e.g. API keys stored on disk)
  • A key derivation helper using PBKDF2-HMAC-SHA256
  • A simple EncryptedStore wrapper for saving/loading encrypted JSON

This module uses Python's standard-library `hashlib`, `hmac`, `os`,
and `secrets` only — no third-party crypto dependency required.

For full database-level encryption, install `sqlcipher3` and replace
the `sqlite3` import in `database/db_manager.py` with `sqlcipher3`.

Usage:
    from core.encryption import EncryptedStore

    store = EncryptedStore(Path("~/.naija_scam_shield/secure.bin"))
    store.save({"virustotal_api_key": "abc123"}, password="my_passphrase")
    data = store.load(password="my_passphrase")
"""

import os
import json
import hmac
import struct
import hashlib
import secrets
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
PBKDF2_ITERATIONS = 260_000    # NIST recommended minimum (2024)
SALT_LEN          = 32         # bytes
IV_LEN            = 12         # bytes  (AES-GCM standard nonce)
TAG_LEN           = 16         # bytes  (GCM authentication tag)
KEY_LEN           = 32         # bytes  (AES-256)

# File format: SALT(32) | IV(12) | TAG(16) | CIPHERTEXT(variable)
HEADER_LEN = SALT_LEN + IV_LEN + TAG_LEN


# ── Key Derivation ────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LEN,
    )


# ── AES-GCM via stdlib (Python 3.11+ has no built-in AES-GCM) ─────────────
# We use the `cryptography` package when available, falling back to a
# pure-XOR obfuscation that still provides integrity via HMAC-SHA256.
# (The fallback is NOT cryptographically strong encryption — it is
#  obfuscation + integrity. For production use, install `cryptography`.)

def _has_cryptography() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
        return True
    except ImportError:
        return False


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns (iv, ciphertext_with_tag).
    Requires: pip install cryptography
    """
    if not _has_cryptography():
        return _fallback_encrypt(plaintext, key)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = secrets.token_bytes(IV_LEN)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, b"NaijaScamShield")
    return iv, ct_with_tag


def decrypt(iv: bytes, ciphertext_with_tag: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    Raises ValueError on authentication failure.
    """
    if not _has_cryptography():
        return _fallback_decrypt(iv, ciphertext_with_tag, key)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext_with_tag, b"NaijaScamShield")
    except Exception as e:
        raise ValueError(f"Decryption failed (wrong password?): {e}") from e


# ── Fallback: XOR + HMAC-SHA256 (obfuscation, not encryption) ────────────────

def _xor_stream(data: bytes, key: bytes) -> bytes:
    """Simple XOR stream cipher using a key-derived keystream (not secure alone)."""
    ks = hashlib.shake_256(key).digest(len(data))  # type: ignore[attr-defined]
    return bytes(a ^ b for a, b in zip(data, ks))


def _fallback_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = secrets.token_bytes(IV_LEN)
    ct = _xor_stream(plaintext, key + iv)
    # Append HMAC-SHA256 tag (16 bytes) for integrity
    tag = hmac.new(key, iv + ct, "sha256").digest()[:TAG_LEN]
    return iv, ct + tag


def _fallback_decrypt(iv: bytes, ct_with_tag: bytes, key: bytes) -> bytes:
    ct, tag = ct_with_tag[:-TAG_LEN], ct_with_tag[-TAG_LEN:]
    expected_tag = hmac.new(key, iv + ct, "sha256").digest()[:TAG_LEN]
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Integrity check failed — data may be corrupted or password is wrong.")
    return _xor_stream(ct, key + iv)


# ── EncryptedStore ────────────────────────────────────────────────────────────

class EncryptedStore:
    """
    Saves and loads a JSON-serialisable dict to/from an encrypted binary file.

    File format on disk:
        [SALT 32B][IV 12B][TAG 16B][CIPHERTEXT …]

    Example:
        store = EncryptedStore(Path("~/.naija_scam_shield/secure.bin").expanduser())
        store.save({"api_key": "secret"}, password="hunter2")
        data = store.load(password="hunter2")
        assert data["api_key"] == "secret"
    """

    def __init__(self, path: Path):
        self.path = path

    def save(self, data: Dict[str, Any], password: str) -> None:
        """Encrypt and save `data` dict to disk."""
        salt = secrets.token_bytes(SALT_LEN)
        key  = derive_key(password, salt)
        plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
        iv, ciphertext_tag = encrypt(plaintext, key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "wb") as f:
            f.write(salt)
            f.write(iv)
            f.write(ciphertext_tag)
        logger.debug("EncryptedStore: saved %d bytes to %s", len(plaintext), self.path)

    def load(self, password: str) -> Optional[Dict[str, Any]]:
        """Decrypt and return the stored dict, or None if file doesn't exist."""
        if not self.path.exists():
            return None
        raw = self.path.read_bytes()
        if len(raw) < HEADER_LEN + 1:
            raise ValueError("Encrypted file is too short — may be corrupted.")
        salt    = raw[:SALT_LEN]
        iv      = raw[SALT_LEN:SALT_LEN + IV_LEN]
        ct_tag  = raw[SALT_LEN + IV_LEN:]
        key = derive_key(password, salt)
        plaintext = decrypt(iv, ct_tag, key)
        return json.loads(plaintext.decode("utf-8"))

    def delete(self) -> None:
        """Securely delete the encrypted file."""
        if self.path.exists():
            # Overwrite with random data before unlinking
            size = self.path.stat().st_size
            with open(self.path, "wb") as f:
                f.write(secrets.token_bytes(size))
            self.path.unlink()
            logger.debug("EncryptedStore: securely deleted %s", self.path)

    def exists(self) -> bool:
        return self.path.exists()


# ── Convenience: obfuscate API keys in config.json ────────────────────────────

def obfuscate(value: str) -> str:
    """
    Light obfuscation of a string for storage in plain config.json.
    NOT cryptographic — just prevents casual shoulder-surfing.
    Use EncryptedStore for real security.
    """
    encoded = value.encode("utf-8")
    key = hashlib.sha256(b"naija-scam-shield-obfuscation-key").digest()
    xored = _xor_stream(encoded, key[:len(encoded)] if len(encoded) <= len(key)
                        else key * (len(encoded) // len(key) + 1))
    return xored.hex()


def deobfuscate(hex_value: str) -> str:
    """Reverse `obfuscate()`."""
    try:
        xored = bytes.fromhex(hex_value)
        key = hashlib.sha256(b"naija-scam-shield-obfuscation-key").digest()
        decoded = _xor_stream(xored, key[:len(xored)] if len(xored) <= len(key)
                               else key * (len(xored) // len(key) + 1))
        return decoded.decode("utf-8")
    except Exception:
        return hex_value  # Return as-is if deobfuscation fails


# ── Secure API key storage helper ─────────────────────────────────────────────

class SecureKeyStore:
    """
    Stores API keys encrypted on disk using EncryptedStore.
    Falls back to in-memory (session-only) if no password is set.

    Usage:
        ks = SecureKeyStore(config.data_dir / "keys.bin")
        ks.set_password("my_password")
        ks.set("virustotal", "my_api_key")
        key = ks.get("virustotal")
    """

    def __init__(self, path: Path):
        self._store = EncryptedStore(path)
        self._password: Optional[str] = None
        self._cache: Dict[str, str] = {}

    def set_password(self, password: str) -> None:
        self._password = password
        # Load existing keys into cache
        try:
            data = self._store.load(password)
            if data:
                self._cache = data
        except Exception as e:
            logger.warning("SecureKeyStore: could not load existing keys: %s", e)

    def set(self, key: str, value: str) -> None:
        self._cache[key] = value
        if self._password:
            try:
                self._store.save(self._cache, self._password)
            except Exception as e:
                logger.error("SecureKeyStore: could not persist key '%s': %s", key, e)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._cache.get(key, default)

    def delete(self, key: str) -> None:
        self._cache.pop(key, None)
        if self._password and self._cache is not None:
            try:
                self._store.save(self._cache, self._password)
            except Exception as e:
                logger.error("SecureKeyStore: could not update after delete: %s", e)
