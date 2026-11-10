"""Exceções formais (risco aceito). Quem solicita não pode aprovar (segregação de funções)."""
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Asset, RiskException, User
from ..security.deps import client_ip, get_current_user, require_roles
from ..services.audit import append_audit
from ..services.rules import get_rule

router = APIRouter(prefix="/exceptions", tags=["exceções"])


def _out(e: RiskException) -> dict:
    return {"id": e.id, "rule_id": e.rule_id, "control_id": e.control_id, "asset": e.asset.name if e.asset else None,
            "subject": e.subject, "justification": e.justification, "reference": e.reference, "status": e.status,
            "requested_by": e.requester.username, "approved_by": e.approver.username if e.approver else None,
            "expires_at": e.expires_at, "expired": e.expires_at < date.today(), "created_at": e.created_at}


class ExceptionIn(BaseModel):
    rule_id: str
    asset_id: int | None = None
    subject: str | None = Field(default=None, max_length=128)
    justification: str = Field(min_length=10, max_length=3000)
    reference: str = Field(default="", max_length=128)
    expires_at: date


@router.get("")
def list_exceptions(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return [_out(e) for e in db.scalars(select(RiskException).order_by(RiskException.created_at.desc()))]


@router.post("")
def request_exception(body: ExceptionIn, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_roles("auditor", "gestor", "admin"))):
    rule = get_rule(body.rule_id)
    if not rule:
        raise HTTPException(400, "Regra inexistente")
    if body.expires_at <= date.today():
        raise HTTPException(400, "A validade deve ser uma data futura")
    if body.asset_id is not None and not db.get(Asset, body.asset_id):
        raise HTTPException(400, "Ativo inexistente")
    e = RiskException(rule_id=rule.rule_id, control_id=rule.control_id, asset_id=body.asset_id,
                      subject=body.subject or None, justification=body.justification, reference=body.reference,
                      expires_at=body.expires_at, requested_by=user.id)
    db.add(e)
    db.flush()
    append_audit(db, "excecao_solicitada", user, target=f"exceção #{e.id}",
                 details={"regra": e.rule_id, "ativo_id": e.asset_id, "validade": str(e.expires_at)},
                 ip=client_ip(request))
    db.commit()
    db.refresh(e)
    return _out(e)


@router.post("/{exc_id}/approve")
def approve(exc_id: int, request: Request, db: Session = Depends(get_db),
            user: User = Depends(require_roles("auditor"))):
    e = db.get(RiskException, exc_id)
    if not e or e.status != "solicitada":
        raise HTTPException(400, "Exceção inexistente ou já tratada")
    if e.requested_by == user.id:
        raise HTTPException(403, "Segregação de funções: quem solicita não pode aprovar a própria exceção")
    e.status, e.approved_by = "aprovada", user.id
    append_audit(db, "excecao_aprovada", user, target=f"exceção #{e.id}", ip=client_ip(request))
    db.commit()
    db.refresh(e)
    return _out(e)


@router.post("/{exc_id}/revoke")
def revoke(exc_id: int, request: Request, db: Session = Depends(get_db),
           user: User = Depends(require_roles("auditor", "admin"))):
    e = db.get(RiskException, exc_id)
    if not e or e.status == "revogada":
        raise HTTPException(400, "Exceção inexistente ou já revogada")
    e.status = "revogada"
    append_audit(db, "excecao_revogada", user, target=f"exceção #{e.id}", ip=client_ip(request))
    db.commit()
    db.refresh(e)
    return _out(e)
