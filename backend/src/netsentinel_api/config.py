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

    # Threat intelligence and SOAR. All optional: the pipeline detects, triages and
    # alerts perfectly well without either, so an unconfigured MISP is a feature that
    # is off rather than a deployment that will not start.
    misp_url: str | None = None
    misp_api_key: SecretStr | None = None
    # On by default. MISP is commonly deployed with a self-signed certificate, which
    # is a reason to install the certificate, not to stop checking it: this channel
    # decides what the system treats as known-bad.
    misp_verify_tls: bool = True
    keep_url: str | None = None
    keep_api_key: SecretStr | None = None
    # Case management, and optional for the same reason: escalating an alert writes
    # the incident row whether or not IRIS answers, so an unconfigured IRIS costs
    # the case, not the escalation.
    iris_url: str | None = None
    iris_api_key: SecretStr | None = None
    # IRIS files every case against a customer, by id. 1 is the one every IRIS
    # installs with, which is what a single-tenant deployment wants.
    iris_customer_id: int = 1
    # On by default. IRIS is commonly deployed with a self-signed certificate, which
    # is a reason to install the certificate, not to stop checking it: this channel
    # carries the evidence an investigation is built on.
    iris_verify_tls: bool = True

    # The enforcement points. Also optional, and for a stronger reason than the two
    # above: with neither configured the approval queue still works and nothing on
    # the network can change, which is the safe way for a deployment to be
    # incomplete.
    crowdsec_url: str | None = None
    crowdsec_machine_id: str | None = None
    crowdsec_password: SecretStr | None = None
    # Bounded by default so a mistaken block expires on its own. See
    # services.enforcement.DEFAULT_BAN_DURATION.
    crowdsec_ban_duration: str = "4h"
    crowdsec_verify_tls: bool = True
    wazuh_url: str | None = None
    wazuh_user: str | None = None
    wazuh_password: SecretStr | None = None
    # The Wazuh API serves a self-signed certificate out of the box. Same position
    # as MISP: install the certificate, do not stop checking it - this channel
    # isolates hosts and disables accounts.
    wazuh_verify_tls: bool = True

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
