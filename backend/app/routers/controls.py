from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Control, ControlAssessment, Finding, PolicyChunk
from ..security.deps import get_current_user
from ..services.params import load_params
from ..services.rules import RULES

router = APIRouter(tags=["controles"])


@router.get("/controls")
def list_controls(db: Session = Depends(get_db), _=Depends(get_current_user)):
    assessments = {a.control_id: a for a in db.scalars(select(ControlAssessment))}
    open_counts = dict(db.execute(select(Finding.control_id, func.count()).where(
        Finding.is_open.is_(True), Finding.review_state != "falso_positivo").group_by(Finding.control_id)).all())
    rules_by_control: dict[str, int] = {}
    for r in RULES:
        rules_by_control[r.control_id] = rules_by_control.get(r.control_id, 0) + 1
    out = []
    for c in db.scalars(select(Control).order_by(Control.sort_order)):
        a = assessments.get(c.id)
        out.append({"id": c.id, "theme": c.theme, "title": c.title, "automation": c.automation,
                    "frequency": c.frequency, "status": a.status if a else "nao_avaliado",
                    "status_detail": a.detail if a else "", "evaluated_at": a.evaluated_at if a else None,
                    "open_findings": open_counts.get(c.id, 0), "rules": rules_by_control.get(c.id, 0)})
    return out


@router.get("/controls/{control_id}")
def control_detail(control_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    c = db.get(Control, control_id)
    if not c:
        raise HTTPException(404, "Controle não encontrado")
    params = load_params(db)
    findings = db.scalars(select(Finding).where(Finding.control_id == control_id, Finding.is_open.is_(True))
                          .order_by(Finding.first_detected_at.desc()))
    chunks = db.scalars(select(PolicyChunk).where(PolicyChunk.control_ids.any(control_id)).limit(10))
    return {
        "id": c.id, "title": c.title, "theme": c.theme, "automation": c.automation, "frequency": c.frequency,
        "rules": [{"rule_id": r.rule_id, "title": r.title, "criterion": r.criterion_text(params)}
                  for r in RULES if r.control_id == control_id],
        "open_findings": [{"id": f.id, "asset": f.asset.name, "condition": f.condition, "severity": f.severity,
                           "status": f.status, "review_state": f.review_state} for f in findings],
        "policies": [{"chunk_id": ch.id, "code": ch.document.code, "document": ch.document.title,
                      "text": ch.text[:600]} for ch in chunks],
    }


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), _=Depends(get_current_user)):
    params = load_params(db)
    return [{"rule_id": r.rule_id, "control_id": r.control_id, "kind": r.kind, "title": r.title,
             "criterion": r.criterion_text(params), "version": r.version_id(params)} for r in RULES]
