"""Application settings, read from the environment.

Two rules shape this module:

* The JWT signing key has **no default**. A default secret is the kind of thing
  that survives into deployment and turns authentication into decoration, so the
  application refuses to start without one.
* Migrations do not need the signing key, so ``database_url()`` is available on its
  own and Alembic uses it rather than constructing the full settings object.
"""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PREFIX = "NETSENTINEL_"

#: Local development default. Deployment overrides it; nothing sensitive here.
DEFAULT_DATABASE_URL = "postgresql+psycopg://netsentinel@localhost:5432/netsentinel"


def database_url() -> str:
    """The database URL alone, for Alembic.

    Kept separate so a migration run does not need a JWT secret it will never use.
    """
    return os.environ.get(f"{ENV_PREFIX}DATABASE_URL", DEFAULT_DATABASE_URL)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX, env_file=".env", extra="ignore"
    )

    database_url: str = DEFAULT_DATABASE_URL

    # No default: see the module docstring.
    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = Field(default=30, ge=1, le=1440)

    # Shadow mode is the safe default. Flipping the system to act on its own
    # verdicts should be a deliberate, recorded change, not an omission.
    default_model_mode: str = "shadow"

    @field_validator("jwt_secret")
    @classmethod
    def _reject_weak_secret(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 32:
            raise ValueError(
                "jwt_secret must be at least 32 characters; generate one with "
                "`python -c \"import secrets; print(secrets.token_urlsafe(48))\"`"
            )
        # Checked as substrings and against low-entropy padding, because the
        # realistic failure is someone padding a placeholder out to 32 characters
        # to satisfy the length rule.
        lowered = raw.lower()
        if any(
            marker in lowered
            for marker in ("changeme", "change-me", "placeholder", "your-secret",
                           "secret-key", "insecure", "example")
        ):
            raise ValueError("jwt_secret looks like a placeholder value")
        if len(set(raw)) < 8:
            raise ValueError(
                f"jwt_secret uses only {len(set(raw))} distinct characters; "
                "it is long but not random"
            )
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def _reject_none_algorithm(cls, value: str) -> str:
        # "none" is a valid JWT algorithm and it means "unsigned".
        if value.lower() == "none":
            raise ValueError("jwt_algorithm 'none' would disable signature verification")
        return value


@lru_cache
def get_settings() -> Settings:
    """Cached settings, as a FastAPI dependency."""
    return Settings()  # type: ignore[call-arg]
