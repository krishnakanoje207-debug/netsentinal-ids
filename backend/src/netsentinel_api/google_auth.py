"""Google Identity verification; unverified browser profile data is never trusted."""

from __future__ import annotations

from functools import partial

from google.auth.transport.requests import Request
from google.oauth2 import id_token


def verify_google_credential(credential: str, client_id: str) -> dict:
    # The official verifier checks the signature, audience, issuer and expiry.
    # Bound certificate retrieval so an unavailable Google service fails closed.
    claims = id_token.verify_oauth2_token(
        credential, partial(Request(), timeout=5), audience=client_id
    )
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise ValueError("Google identity has no subject")
    if claims.get("email_verified") is not True:
        raise ValueError("Google identity has no verified email")
    return claims
