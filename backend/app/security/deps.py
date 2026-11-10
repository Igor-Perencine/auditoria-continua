"""Dependências FastAPI: usuário autenticado e controle de acesso por perfil (RBAC)."""
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from .tokens import TokenError, decode_token

_bearer = HTTPBearer(auto_error=False)

ROLES = ("admin", "auditor", "gestor", "leitura")


def get_current_user(
    cred: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Sessão inválida ou expirada")
    if not cred:
        raise unauthorized
    try:
        payload = decode_token(cred.credentials, "access")
    except TokenError:
        raise unauthorized
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active or user.token_version != payload.get("tv"):
        raise unauthorized
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Seu perfil não permite esta ação")
        return user

    return dependency


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None
