"""Laboratório de cenários controlados (injeção de falhas) — avaliação do protótipo."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..collectors.simulator import SCENARIOS, apply_scenario, get_state, reset_state, revert_scenario
from ..db import get_db, utcnow
from ..models import ScenarioRun, User
from ..security.deps import client_ip, require_roles
from ..services.audit import append_audit

router = APIRouter(prefix="/lab", tags=["laboratório"])
lab_roles = require_roles("admin", "auditor")


def _run_out(sr: ScenarioRun | None) -> dict | None:
    if not sr:
        return None
    det = (sr.detected_at - sr.injected_at).total_seconds() if sr.detected_at else None
    return {"id": sr.id, "injected_at": sr.injected_at, "detected_at": sr.detected_at,
            "reverted_at": sr.reverted_at, "detection_seconds": det, "finding_id": sr.detected_finding_id}


@router.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db), _=Depends(lab_roles)):
    out = []
    for key, sc in SCENARIOS.items():
        last = db.scalar(select(ScenarioRun).where(ScenarioRun.scenario_key == key)
                         .order_by(ScenarioRun.injected_at.desc()).limit(1))
        out.append({"key": key, "title": sc["title"], "control": sc["control"], "rules": sc["rules"],
                    "active": bool(last and last.reverted_at is None), "last_run": _run_out(last)})
    return out


@router.get("/state")
def lab_state(db: Session = Depends(get_db), _=Depends(lab_roles)):
    return get_state(db)


@router.post("/scenarios/{key}/inject")
def inject(key: str, request: Request, db: Session = Depends(get_db), user: User = Depends(lab_roles)):
    if key not in SCENARIOS:
        raise HTTPException(404, "Cenário inexistente")
    active = db.scalar(select(ScenarioRun).where(ScenarioRun.scenario_key == key, ScenarioRun.reverted_at.is_(None)))
    if active:
        raise HTTPException(400, "Cenário já está ativo")
    apply_scenario(db, key)
    db.add(ScenarioRun(scenario_key=key, injected_at=utcnow(), injected_by=user.id))
    append_audit(db, "cenario_injetado", user, target=key, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/scenarios/{key}/revert")
def revert(key: str, request: Request, db: Session = Depends(get_db), user: User = Depends(lab_roles)):
    if key not in SCENARIOS:
        raise HTTPException(404, "Cenário inexistente")
    revert_scenario(db, key)
    for sr in db.scalars(select(ScenarioRun).where(ScenarioRun.scenario_key == key, ScenarioRun.reverted_at.is_(None))):
        sr.reverted_at = utcnow()
    append_audit(db, "cenario_revertido", user, target=key, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/reset")
def reset(request: Request, db: Session = Depends(get_db), user: User = Depends(lab_roles)):
    reset_state(db)
    for sr in db.scalars(select(ScenarioRun).where(ScenarioRun.reverted_at.is_(None))):
        sr.reverted_at = utcnow()
    append_audit(db, "laboratorio_restaurado", user, ip=client_ip(request))
    db.commit()
    return {"ok": True}
