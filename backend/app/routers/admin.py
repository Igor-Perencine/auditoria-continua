"""Parâmetros de política, ativos/escopo, trilha de auditoria e status da IA."""
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai.provider import get_provider
from ..db import get_db, utcnow
from ..models import Asset, AuditLog, Parameter, User
from ..security.deps import client_ip, get_current_user, require_roles
from ..services.audit import append_audit
from ..services.params import validate_param
from ..services.pipeline import classify_pending

router = APIRouter(tags=["administração"])


# ----------------------------------------------------------------- parâmetros

@router.get("/parameters")
def list_parameters(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return [{"key": p.key, "value": p.value, "description": p.description, "updated_at": p.updated_at}
            for p in db.scalars(select(Parameter).order_by(Parameter.key))]


class ParamIn(BaseModel):
    value: str = Field(max_length=512)


@router.put("/parameters/{key}")
def update_parameter(key: str, body: ParamIn, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_roles("admin"))):
    p = db.get(Parameter, key)
    if not p:
        raise HTTPException(404, "Parâmetro não encontrado")
    err = validate_param(key, body.value.strip())
    if err:
        raise HTTPException(400, err)
    old = p.value
    p.value, p.updated_at, p.updated_by = body.value.strip(), utcnow(), user.id
    append_audit(db, "parametro_alterado", user, target=key, details={"de": old, "para": p.value},
                 ip=client_ip(request))
    db.commit()
    return {"key": p.key, "value": p.value}


# ----------------------------------------------------------------- ativos

def _asset_out(a: Asset) -> dict:
    return {"id": a.id, "name": a.name, "asset_type": a.asset_type, "criticality": a.criticality,
            "in_scope": a.in_scope, "owner_id": a.owner_id, "owner": a.owner.username if a.owner else None,
            "description": a.description, "last_seen_at": a.last_seen_at}


@router.get("/assets")
def list_assets(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return [_asset_out(a) for a in db.scalars(select(Asset).order_by(Asset.name))]


class AssetIn(BaseModel):
    criticality: int | None = Field(default=None, ge=1, le=5)
    in_scope: bool | None = None
    owner_id: int | None = None
    clear_owner: bool = False
    description: str | None = Field(default=None, max_length=1000)


@router.patch("/assets/{asset_id}")
def update_asset(asset_id: int, body: AssetIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_roles("admin"))):
    a = db.get(Asset, asset_id)
    if not a:
        raise HTTPException(404, "Ativo não encontrado")
    changes = {}
    if body.criticality is not None:
        changes["criticidade"] = [a.criticality, body.criticality]
        a.criticality = body.criticality
    if body.in_scope is not None:
        changes["escopo"] = body.in_scope
        a.in_scope = body.in_scope
    if body.clear_owner:
        a.owner_id = None
        changes["responsavel"] = None
    elif body.owner_id is not None:
        if not db.get(User, body.owner_id):
            raise HTTPException(400, "Usuário inexistente")
        a.owner_id = body.owner_id
        changes["responsavel"] = body.owner_id
    if body.description is not None:
        a.description = body.description
    append_audit(db, "ativo_alterado", user, target=a.name, details=changes, ip=client_ip(request))
    db.commit()
    db.refresh(a)
    return _asset_out(a)


# ----------------------------------------------------------------- trilha de auditoria

@router.get("/audit-log")
def audit_log(limit: int = 200, action: str | None = None, db: Session = Depends(get_db),
              _=Depends(require_roles("auditor", "admin"))):
    q = select(AuditLog).order_by(AuditLog.seq.desc()).limit(min(limit, 1000))
    if action:
        q = q.where(AuditLog.action == action)
    return [{"seq": e.seq, "ts": e.ts, "username": e.username, "action": e.action, "target": e.target,
             "details": e.details, "ip": e.ip, "hash": e.hash} for e in db.scalars(q)]


# ----------------------------------------------------------------- IA

@router.get("/ai/status")
def ai_status(_=Depends(get_current_user)):
    info = get_provider().info()
    if info["provider"] == "gemini":
        info["warning"] = ("Plano gratuito do Gemini: o Google pode usar o conteúdo enviado para melhorar seus "
                           "produtos. Use dados de laboratório e mantenha a pseudonimização ativa.")
    return info


@router.post("/ai/classify-pending")
def ai_classify_pending(request: Request, db: Session = Depends(get_db),
                        user: User = Depends(require_roles("auditor", "admin"))):
    if not get_provider().enabled:
        raise HTTPException(400, "IA desabilitada. Configure AI_PROVIDER no arquivo .env")
    append_audit(db, "ia_triagem_solicitada", user, ip=client_ip(request))
    db.commit()
    threading.Thread(target=classify_pending, daemon=True).start()
    return {"started": True}
