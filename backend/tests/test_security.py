"""Password hashing and token verification, including the attacks they must resist."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest

from netsentinel_api.config import Settings
from netsentinel_api.security import (
    MAX_PASSWORD_BYTES,
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    subject_id,
    verify_password,
)

SECRET = "K7vQp2xR9mLt4wZn6bYc3sEdJf8hGa1uNqXrVoWiTyBk5Pz0"


@pytest.fixture
def settings() -> Settings:
    return Settings(jwt_secret=SECRET)


# --- passwords -------------------------------------------------------------

def test_hash_and_verify_round_trip():
    hashed = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed)


def test_wrong_password_is_rejected():
    assert not verify_password("wrong", hash_password("right"))


def test_the_same_password_hashes_differently_each_time():
    """A per-password salt: identical passwords must not share a hash."""
    assert hash_password("same") != hash_password("same")


def test_overlong_password_is_refused_not_truncated():
    """bcrypt ignores everything past 72 bytes, so two long passwords would collide."""
    with pytest.raises(ValueError, match="silently truncated"):
        hash_password("a" * (MAX_PASSWORD_BYTES + 1))


def test_overlong_password_never_verifies():
    hashed = hash_password("a" * MAX_PASSWORD_BYTES)
    # Without the length guard bcrypt would compare only the first 72 bytes and
    # accept this.
    assert not verify_password("a" * MAX_PASSWORD_BYTES + "b", hashed)


def test_empty_password_is_refused():
    with pytest.raises(ValueError, match="must not be empty"):
        hash_password("")


def test_a_corrupt_hash_is_a_failed_login_not_a_crash():
    assert not verify_password("anything", "not-a-bcrypt-hash")
    assert not verify_password("anything", "")


def test_multibyte_password_is_measured_in_bytes():
    # Four-byte characters: 20 of them exceed the limit even though len() is 20.
    with pytest.raises(ValueError):
        hash_password("😀" * 20)


# --- tokens ----------------------------------------------------------------

def test_token_round_trip(settings):
    token = create_access_token(settings, user_id=7, role="soc_analyst")
    payload = decode_access_token(settings, token)
    assert subject_id(payload) == 7
    assert payload["role"] == "soc_analyst"
    assert "jti" in payload


def test_expired_token_is_rejected(settings):
    token = create_access_token(settings, 1, "soc_analyst", expires_in=timedelta(seconds=-1))
    with pytest.raises(TokenError, match="expired"):
        decode_access_token(settings, token)


def test_token_signed_with_another_secret_is_rejected(settings):
    other = Settings(jwt_secret="Zq8Wm3Nv6Ty1Rb5Kc9Xd2Ls7Hj4Pf0GaUeIoQrVnYtBw6M")
    token = create_access_token(other, 1, "soc_analyst")
    with pytest.raises(TokenError, match="not valid"):
        decode_access_token(settings, token)


def test_unsigned_token_is_rejected(settings):
    """The alg=none attack: a token that asks to be trusted without a signature."""
    forged = jwt.encode({"sub": "1", "role": "administrator", "exp": 9999999999},
                        key="", algorithm="none")
    with pytest.raises(TokenError, match="not valid"):
        decode_access_token(settings, forged)


def test_token_without_an_expiry_is_rejected(settings):
    """A token that never expires would be a permanent credential."""
    forever = jwt.encode({"sub": "1", "role": "administrator"},
                         SECRET, algorithm="HS256")
    with pytest.raises(TokenError, match="not valid"):
        decode_access_token(settings, forever)


def test_token_without_a_subject_is_rejected(settings):
    anonymous = jwt.encode({"role": "administrator", "exp": 9999999999},
                           SECRET, algorithm="HS256")
    with pytest.raises(TokenError, match="not valid"):
        decode_access_token(settings, anonymous)


def test_garbage_is_rejected(settings):
    with pytest.raises(TokenError):
        decode_access_token(settings, "not.a.token")


def test_non_numeric_subject_is_rejected(settings):
    payload = {"sub": "administrator", "exp": 9999999999}
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError, match="not a user id"):
        subject_id(decode_access_token(settings, token))


def test_issuing_refuses_the_none_algorithm():
    weak = Settings(jwt_secret=SECRET)
    # Bypass the field validator to prove the issuing path checks too.
    object.__setattr__(weak, "jwt_algorithm", "none")
    with pytest.raises(ValueError, match="unsigned"):
        create_access_token(weak, 1, "administrator")


# --- settings guards -------------------------------------------------------

def test_short_secret_is_refused():
    with pytest.raises(ValueError, match="at least 32 characters"):
        Settings(jwt_secret="tooshort")


def test_placeholder_padded_to_length_is_refused():
    """The realistic failure: padding a placeholder out to satisfy the length rule."""
    with pytest.raises(ValueError, match="placeholder"):
        Settings(jwt_secret="changeme-changeme-changeme-changeme")


def test_long_but_low_entropy_secret_is_refused():
    with pytest.raises(ValueError, match="not random"):
        Settings(jwt_secret="abababababababababababababababababab")


def test_a_blank_sensor_token_is_no_sensor_token():
    """Compose passes a variable missing from .env as an empty string."""
    assert Settings(jwt_secret=SECRET, sensor_token="").sensor_token is None


def test_the_sensor_token_is_held_to_the_signing_key_s_bar():
    with pytest.raises(ValueError, match="sensor_token must be at least 32 characters"):
        Settings(jwt_secret=SECRET, sensor_token="tooshort")
    with pytest.raises(ValueError, match="sensor_token looks like a placeholder"):
        Settings(jwt_secret=SECRET, sensor_token="changeme-changeme-changeme-changeme")


def test_none_algorithm_is_refused_by_settings():
    with pytest.raises(ValueError, match="disable signature verification"):
        Settings(jwt_secret=SECRET, jwt_algorithm="none")
