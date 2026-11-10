"""Tokens JWT (HS256). O token de acesso só é emitido após senha + MFA."""
from datetime import datetime, timedelta, timezone

import jwt

from ..config import settings

ISSUER = "auditoria-continua"
MFA_TOKEN_MINUTES = 5


class TokenError(Exception):
    pass


def _encode(claims: dict, minutes: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {**claims, "iat": now, "exp": now + timedelta(minutes=minutes), "iss": ISSUER}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def create_access_token(user) -> str:
    return _encode(
        {"sub": str(user.id), "role": user.role, "tv": user.token_version, "typ": "access"},
        settings.access_token_minutes,
    )


def create_mfa_token(user, stage: str) -> str:
    """Token intermediário: prova que a senha foi validada, mas ainda falta o MFA."""
    return _encode(
        {"sub": str(user.id), "tv": user.token_version, "typ": "mfa", "stage": stage},
        MFA_TOKEN_MINUTES,
    )


def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], issuer=ISSUER)
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if payload.get("typ") != expected_type:
        raise TokenError("tipo de token inválido")
    return payload
