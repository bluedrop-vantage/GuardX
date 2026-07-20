from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _repo_env_path() -> Path:
    # control/guardx_control/config.py → repo-root/.env
    return Path(__file__).resolve().parents[2] / ".env"


def _normalize_pg_scheme(uri: str) -> str:
    """SQLAlchemy 2.x needs an explicit driver. Anything that says plain
    'postgresql://' gets rewritten to 'postgresql+psycopg://' so the same URI
    works whether it came from a Supabase console (bare scheme) or from our
    docker-compose (already qualified).
    """
    if uri.startswith("postgresql+"):
        return uri
    if uri.startswith("postgresql://"):
        return "postgresql+psycopg://" + uri[len("postgresql://"):]
    if uri.startswith("postgres://"):
        return "postgresql+psycopg://" + uri[len("postgres://"):]
    return uri


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDX_",
        env_file=str(_repo_env_path()),
        extra="ignore",
    )

    # database_url accepts either GUARDX_DATABASE_URL (canonical) or POSTGRES_URI
    # (project-wide .env convention). Both flow through _normalize_pg_scheme so
    # SQLAlchemy sees a driver-qualified URI.
    database_url: str = Field(
        default="postgresql+psycopg://guardx:guardx@localhost:5432/guardx",
        validation_alias=AliasChoices("GUARDX_DATABASE_URL", "POSTGRES_URI"),
    )
    signing_key_path: Path = Path("./dev-signing-key.ed25519")
    signing_key_id: str = "dev-local"
    api_key_admin: str = "dev-admin-key"
    api_key_service: str = "dev-service-key"
    bundle_max_age_hours: int = 72
    schemas_dir: Path = Path(__file__).resolve().parents[2] / "schemas"

    # CORS: comma-separated list of allowed origins. Empty (default) means
    # the API only serves same-origin traffic — production posture. Dev
    # docker-compose sets this to http://localhost:5173 for the Vite console.
    cors_allowed_origins: str = ""

    # --- OIDC (spec §3.3) ---------------------------------------------------
    # Enable real OIDC bearer-token auth. When off (default), the legacy
    # X-GuardX-Key path is the only supported credential. When on, EITHER
    # a Bearer JWT (users) OR X-GuardX-Key (service tokens) is accepted.
    oidc_enabled: bool = False
    oidc_issuer: str = ""                                # expected iss claim
    oidc_audience: str = ""                              # expected aud claim; "" skips
    oidc_jwks_url: str = ""                              # https://.../.well-known/jwks.json
    oidc_role_claim: str = "app_metadata.guardx_role"    # dotted path
    oidc_subject_claim: str = "sub"                      # dotted path
    oidc_leeway_seconds: int = 30
    oidc_jwks_ttl_seconds: int = 900

    def model_post_init(self, __context) -> None:  # noqa: D401
        object.__setattr__(self, "database_url", _normalize_pg_scheme(self.database_url))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
