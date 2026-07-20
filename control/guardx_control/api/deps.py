from typing import Iterator

from fastapi import Depends
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..config import get_settings
from ..signing import Ed25519Signer, load_or_create_dev_key


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_signer: Ed25519Signer | None = None


def get_signer() -> Ed25519Signer:
    global _signer
    if _signer is None:
        settings = get_settings()
        _signer = load_or_create_dev_key(settings.signing_key_path, settings.signing_key_id)
    return _signer
