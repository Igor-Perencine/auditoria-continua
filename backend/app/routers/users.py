from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..security.deps import ROLES, client_ip, get_current_user, require_roles
from ..security.passwords import hash_password, password_problems
from ..services.audit import append_audit
from .auth import user_public

router = APIRouter(prefix="/users", tags=["usuários"])
admin_only = require_roles("admin")


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    full_name: str = Field(default="", max_length=128)
    role: str
    password: str = Field(max_length=256)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=128)
    role: str | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    password: str = Field(max_length=256)


@router.get("")
def list_users(db: Session = Depends(get_db), _=Depends(admin_only)):
    return [user_public(u) for u in db.scalars(select(User).order_by(User.username))]


@router.get("/options")
def user_options(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Lista resumida (para escolher responsáveis por ativos)."""
    return [{"id": u.id, "username": u.username, "full_name": u.full_name, "role": u.role}
            for u in db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.username))]


@router.post("")
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db), admin=Depends(admin_only)):
    if body.role not in ROLES:
        raise HTTPException(400, "Perfil inválido")
    if db.scalar(select(User).where(User.username == body.username.lower())):
        raise HTTPException(409, "Usuário já existe")
    problems = password_problems(body.password)
    if problems:
        raise HTTPException(400, "Senha fraca: " + "; ".join(problems))
    u = User(username=body.username.lower(), full_name=body.full_name, role=body.role,
             password_hash=hash_password(body.password))
    db.add(u)
    db.flush()
    append_audit(db, "usuario_criado", admin, target=u.username, details={"perfil": u.role}, ip=client_ip(request))
    db.commit()
    return user_public(u)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, db: Session = Depends(get_db),
                admin=Depends(admin_only)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    changes = {}
    if body.role is not None and body.role != u.role:
        if body.role not in ROLES:
            raise HTTPException(400, "Perfil inválido")
        if u.id == admin.id:
            raise HTTPException(400, "Você não pode alterar o próprio perfil")
        changes["perfil"] = [u.role, body.role]
        u.role = body.role
        u.token_version += 1
    if body.is_active is not None and body.is_active != u.is_active:
        if u.id == admin.id:
            raise HTTPException(400, "Você não pode desativar a si mesmo")
        changes["ativo"] = body.is_active
        u.is_active = body.is_active
        u.token_version += 1
    if body.full_name is not None:
        u.full_name = body.full_name
    append_audit(db, "usuario_alterado", admin, target=u.username, details=changes, ip=client_ip(request))
    db.commit()
    return user_public(u)


@router.post("/{user_id}/reset-mfa")
def reset_mfa(user_id: int, request: Request, db: Session = Depends(get_db), admin=Depends(admin_only)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    u.mfa_enabled, u.mfa_secret_enc, u.mfa_last_counter = False, None, 0
    u.token_version += 1
    append_audit(db, "mfa_redefinido", admin, target=u.username, ip=client_ip(request))
    db.commit()
    return user_public(u)


@router.post("/{user_id}/unlock")
def unlock(user_id: int, request: Request, db: Session = Depends(get_db), admin=Depends(admin_only)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    u.locked_until, u.failed_attempts = None, 0
    append_audit(db, "usuario_desbloqueado", admin, target=u.username, ip=client_ip(request))
    db.commit()
    return user_public(u)


@router.post("/{user_id}/reset-password")
def reset_password(user_id: int, body: PasswordReset, request: Request, db: Session = Depends(get_db),
                   admin=Depends(admin_only)):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "Usuário não encontrado")
    problems = password_problems(body.password)
    if problems:
        raise HTTPException(400, "Senha fraca: " + "; ".join(problems))
    u.password_hash = hash_password(body.password)
    u.token_version += 1
    append_audit(db, "senha_redefinida", admin, target=u.username, ip=client_ip(request))
    db.commit()
    return user_public(u)
