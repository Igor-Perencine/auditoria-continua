"""Login em duas etapas: senha (Argon2id) -> MFA TOTP obrigatório (cadastro forçado no 1º acesso)."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db, utcnow
from ..models import User
from ..security.crypto import decrypt_str, encrypt_str
from ..security.deps import client_ip, get_current_user
from ..security.mfa import new_secret, provisioning_uri, qr_svg, verify_totp
from ..security.passwords import hash_password, needs_rehash, password_problems, verify_password
from ..security.tokens import TokenError, create_access_token, create_mfa_token, decode_token
from ..services.audit import append_audit

router = APIRouter(prefix="/auth", tags=["autenticação"])

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15
_DUMMY_HASH = hash_password("senha-ficticia-para-tempo-constante")
GENERIC_ERROR = "Usuário ou senha inválidos"


def user_public(u: User) -> dict:
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role,
            "mfa_enabled": u.mfa_enabled, "is_active": u.is_active,
            "locked": bool(u.locked_until and u.locked_until > utcnow()), "created_at": u.created_at}


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class MfaTokenIn(BaseModel):
    mfa_token: str


class MfaVerifyIn(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=6)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


def _register_failure(db: Session, user: User, request: Request, reason: str) -> None:
    user.failed_attempts += 1
    append_audit(db, "login_falha", user, target=user.username, details={"motivo": reason}, ip=client_ip(request))
    if user.failed_attempts >= MAX_ATTEMPTS:
        user.locked_until = utcnow() + timedelta(minutes=LOCK_MINUTES)
        user.failed_attempts = 0
        append_audit(db, "conta_bloqueada", user, target=user.username,
                     details={"minutos": LOCK_MINUTES}, ip=client_ip(request))
    db.commit()


def _check_locked(user: User) -> None:
    if user.locked_until and user.locked_until > utcnow():
        raise HTTPException(423, "Conta temporariamente bloqueada por excesso de tentativas. Tente mais tarde.")


def _user_from_mfa_token(db: Session, token: str) -> tuple[User, str]:
    try:
        payload = decode_token(token, "mfa")
    except TokenError:
        raise HTTPException(401, "Etapa de MFA expirada. Faça login novamente.")
    user = db.get(User, int(payload["sub"]))
    if not user or not user.is_active or user.token_version != payload.get("tv"):
        raise HTTPException(401, "Etapa de MFA inválida. Faça login novamente.")
    return user, payload["stage"]


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    username = body.username.strip().lower()
    user = db.scalar(select(User).where(User.username == username))
    if not user or not user.is_active:
        verify_password(_DUMMY_HASH, body.password)  # tempo constante: não revela se o usuário existe
        append_audit(db, "login_falha", None, target=username[:64],
                     details={"motivo": "usuario_inexistente_ou_inativo"}, ip=client_ip(request))
        db.commit()
        raise HTTPException(401, GENERIC_ERROR)
    _check_locked(user)
    if not verify_password(user.password_hash, body.password):
        _register_failure(db, user, request, "senha_incorreta")
        raise HTTPException(401, GENERIC_ERROR)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    stage = "mfa_verify" if user.mfa_enabled else "mfa_setup"
    db.commit()
    return {"stage": stage, "mfa_token": create_mfa_token(user, stage)}


@router.post("/mfa/setup")
def mfa_setup(body: MfaTokenIn, db: Session = Depends(get_db)):
    user, stage = _user_from_mfa_token(db, body.mfa_token)
    if stage != "mfa_setup" or user.mfa_enabled:
        raise HTTPException(400, "MFA já configurado")
    secret = new_secret()
    user.mfa_secret_enc = encrypt_str(secret, aad=f"mfa:{user.id}")
    db.commit()
    uri = provisioning_uri(secret, user.username)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}


@router.post("/mfa/verify")
def mfa_verify(body: MfaVerifyIn, request: Request, db: Session = Depends(get_db)):
    user, stage = _user_from_mfa_token(db, body.mfa_token)
    _check_locked(user)
    if not user.mfa_secret_enc:
        raise HTTPException(400, "MFA não iniciado")
    counter = verify_totp(decrypt_str(user.mfa_secret_enc, aad=f"mfa:{user.id}"), body.code, user.mfa_last_counter)
    if counter is None:
        _register_failure(db, user, request, "codigo_mfa_invalido")
        raise HTTPException(401, "Código inválido ou já utilizado")
    user.mfa_last_counter = counter
    if stage == "mfa_setup" and not user.mfa_enabled:
        user.mfa_enabled = True
        append_audit(db, "mfa_ativado", user, target=user.username, ip=client_ip(request))
    user.failed_attempts = 0
    user.locked_until = None
    append_audit(db, "login_sucesso", user, target=user.username, ip=client_ip(request))
    db.commit()
    return {"access_token": create_access_token(user), "user": user_public(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_public(user)


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(400, "Senha atual incorreta")
    problems = password_problems(body.new_password)
    if problems:
        raise HTTPException(400, "Senha fraca: " + "; ".join(problems))
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # encerra todas as sessões
    append_audit(db, "senha_alterada", user, target=user.username, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.token_version += 1
    append_audit(db, "logout", user, target=user.username, ip=client_ip(request))
    db.commit()
    return {"ok": True}
