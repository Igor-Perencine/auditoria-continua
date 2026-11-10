from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Evidence, User
from ..security.deps import client_ip, require_roles
from ..services.audit import append_audit, verify_audit_chain
from ..services.evidence import decrypt_evidence, verify_evidence_chain

router = APIRouter(tags=["evidências e integridade"])
auditor_admin = require_roles("auditor", "admin")


@router.get("/evidence")
def list_evidence(limit: int = 100, asset: str | None = None, db: Session = Depends(get_db), _=Depends(auditor_admin)):
    q = select(Evidence).order_by(Evidence.seq.desc()).limit(min(limit, 500))
    items = []
    for ev in db.scalars(q):
        if asset and ev.asset.name != asset:
            continue
        items.append({"id": ev.id, "seq": ev.seq, "asset": ev.asset.name, "kind": ev.kind, "collector": ev.collector,
                      "source": ev.source, "control_ids": ev.control_ids, "collected_at": ev.collected_at,
                      "hash": ev.hash, "prev_hash": ev.prev_hash, "run_id": ev.run_id})
    return items


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(auditor_admin)):
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidência não encontrada")
    payload = decrypt_evidence(ev)
    # o acesso ao conteúdo sensível também fica registrado
    append_audit(db, "evidencia_visualizada", user, target=f"evidência #{ev.seq}", ip=client_ip(request))
    db.commit()
    return {"id": ev.id, "seq": ev.seq, "asset": ev.asset.name, "kind": ev.kind, "source": ev.source,
            "collector": ev.collector, "control_ids": ev.control_ids, "collected_at": ev.collected_at,
            "hash": ev.hash, "prev_hash": ev.prev_hash, "key_version": ev.key_version, "payload": payload}


@router.post("/integrity/verify")
def verify(request: Request, db: Session = Depends(get_db), user: User = Depends(auditor_admin)):
    result = {"evidence": verify_evidence_chain(db), "audit_log": verify_audit_chain(db)}
    append_audit(db, "integridade_verificada", user, details={
        "evidencias_ok": result["evidence"]["ok"], "trilha_ok": result["audit_log"]["ok"]}, ip=client_ip(request))
    db.commit()
    return result
