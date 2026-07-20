"""Ed25519 signer with a swap-in interface.

M0 default: a local keyfile (dev-signing-key.ed25519 + .pub) generated on first
run. GA path: Vault Transit / KMS behind the same `Signer` protocol.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Signer(Protocol):
    key_id: str

    def sign(self, message: bytes) -> bytes: ...

    def public_key_bytes(self) -> bytes: ...


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str):
        self._priv = private_key
        self.key_id = key_id

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def public_key(self) -> Ed25519PublicKey:
        return self._priv.public_key()

    def public_key_bytes(self) -> bytes:
        return self.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def load_or_create_dev_key(path: Path, key_id: str) -> Ed25519Signer:
    """Load an Ed25519 private key from `path`, creating one if absent.

    Dev-only. Production must inject a Signer backed by KMS/HSM.
    """
    if path.exists():
        raw = path.read_bytes()
        priv = serialization.load_pem_private_key(raw, password=None)
        assert isinstance(priv, Ed25519PrivateKey), "signing key must be Ed25519"
    else:
        priv = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        pub_path = path.with_suffix(path.suffix + ".pub")
        pub_path.write_bytes(
            priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
    return Ed25519Signer(priv, key_id)
