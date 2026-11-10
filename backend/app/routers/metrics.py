"""Painel geral e indicadores da pesquisa (objetivo específico "e" e seção 2.9 do TCC):
cobertura, tempo de detecção, reprodutibilidade, falsos positivos e concordância IA x auditor."""
from collections import Counter

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..ai.provider import get_provider
from ..collectors.base import Observation
from ..collectors.simulator import SCENARIOS
from ..db import get_db
from ..models import (CollectionRun, Control, ControlAssessment, Decision, Evidence, Finding, RiskException,
                      ScenarioRun, User)
from ..security.deps import client_ip, get_current_user, require_roles
from ..services.audit import append_audit
from ..services.evidence import decrypt_evidence
from ..services.params import load_params
from ..services.rules import evaluate

router = APIRouter(tags=["métricas"])


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), _=Depends(get_current_user)):
    controls = list(db.scalars(select(Control)))
    assessments = {a.control_id: a.status for a in db.scalars(select(ControlAssessment))}
    by_theme: dict[str, Counter] = {}
    for c in controls:
        by_theme.setdefault(c.theme, Counter())[assessments.get(c.id, "nao_avaliado")] += 1
    status_counts = Counter(assessments.get(c.id, "nao_avaliado") for c in controls)
    open_f = list(db.scalars(select(Finding).where(Finding.is_open.is_(True))))
    active = [f for f in open_f if f.review_state != "falso_positivo"]
    sev = Counter(f.final_severity or f.severity for f in active)
    evaluated = status_counts["conforme"] + status_counts["nao_conforme"]
    last_runs = db.scalars(select(CollectionRun).order_by(CollectionRun.id.desc()).limit(5))
    return {
        "total_controls": len(controls),
        "status_counts": dict(status_counts),
        "automation_counts": dict(Counter(c.automation for c in controls)),
        "by_theme": [{"theme": t, "counts": dict(cnt)} for t, cnt in by_theme.items()],
        "conformity_pct": round(100 * status_counts["conforme"] / evaluated, 1) if evaluated else None,
        "open_findings": len(active),
        "open_by_severity": dict(sev),
        "pending_review": sum(1 for f in open_f if f.review_state == "pendente"),
        "mandatory_review": sum(1 for f in open_f if f.review_state == "pendente" and f.requires_human_review),
        "ai": get_provider().info(),
        "last_runs": [{"id": r.id, "status": r.status, "trigger": r.trigger, "started_at": r.started_at,
                       "finished_at": r.finished_at, "evidence_count": r.evidence_count,
                       "findings_new": r.findings_new, "findings_resolved": r.findings_resolved} for r in last_runs],
    }


def _kappa(pairs: list[tuple[bool, bool]]) -> dict:
    n = len(pairs)
    if n == 0:
        return {"n": 0, "kappa": None, "agreement": None, "matrix": None}
    a = sum(1 for ai, hu in pairs if ai and hu)
    b = sum(1 for ai, hu in pairs if ai and not hu)
    c = sum(1 for ai, hu in pairs if not ai and hu)
    d = n - a - b - c
    po = (a + d) / n
    pe = ((a + b) * (a + c) + (c + d) * (b + d)) / (n * n)
    kappa = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return {"n": n, "kappa": round(kappa, 3), "agreement": round(po, 3),
            "matrix": {"ia_nc_auditor_nc": a, "ia_nc_auditor_nao": b, "ia_nao_auditor_nc": c, "ia_nao_auditor_nao": d}}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db), _=Depends(get_current_user)):
    controls = list(db.scalars(select(Control)))
    automation = Counter(c.automation for c in controls)
    assessments = Counter(db.scalars(select(ControlAssessment.status)))
    evaluated = assessments["conforme"] + assessments["nao_conforme"] + assessments["impossivel_avaliar"]

    # tempo de detecção dos cenários injetados
    detections = []
    for sr in db.scalars(select(ScenarioRun).order_by(ScenarioRun.injected_at.desc()).limit(200)):
        detections.append({"scenario": sr.scenario_key, "title": SCENARIOS.get(sr.scenario_key, {}).get("title"),
                           "injected_at": sr.injected_at, "detected_at": sr.detected_at,
                           "seconds": (sr.detected_at - sr.injected_at).total_seconds() if sr.detected_at else None})
    secs = [d["seconds"] for d in detections if d["seconds"] is not None]

    # decisões humanas (última por achado)
    latest: dict[int, Decision] = {}
    for d in db.scalars(select(Decision).order_by(Decision.created_at)):
        latest[d.finding_id] = d
    decisions = list(latest.values())
    fp = sum(1 for d in decisions if d.final_status == "falso_positivo")
    pairs = [(d.ai_status_suggested == "nao_conforme", d.final_status == "nao_conforme")
             for d in decisions if d.ai_status_suggested]
    findings = {f.id: f for f in db.scalars(select(Finding).where(Finding.id.in_(list(latest.keys()))))} \
        if latest else {}
    triage = [(d.created_at - findings[d.finding_id].first_detected_at).total_seconds()
              for d in decisions if d.finding_id in findings]
    resolved = list(db.scalars(select(Finding).where(Finding.resolved_at.is_not(None))))
    mttr = [(f.resolved_at - f.first_detected_at).total_seconds() for f in resolved]

    return {
        "coverage": {
            "total_controls": len(controls), "by_automation": dict(automation),
            "automatable_pct": round(100 * (automation["automatizavel"] + automation["parcial"]) / len(controls), 1),
            "evaluated_automatically": evaluated,
            "evaluated_pct": round(100 * evaluated / len(controls), 1),
            "status": dict(assessments),
        },
        "detection": {"items": detections, "count": len(secs),
                      "avg_seconds": round(sum(secs) / len(secs), 1) if secs else None,
                      "max_seconds": max(secs) if secs else None},
        "human_review": {
            "decisions": len(decisions), "false_positives": fp,
            "false_positive_rate": round(fp / len(decisions), 3) if decisions else None,
            "avg_seconds_to_decision": round(sum(triage) / len(triage), 1) if triage else None,
        },
        "ai_agreement": _kappa(pairs),
        "remediation": {"resolved": len(resolved),
                        "avg_seconds_to_resolution": round(sum(mttr) / len(mttr), 1) if mttr else None,
                        "top_controls": Counter(f.control_id for f in db.scalars(select(Finding))).most_common(5)},
        "runs": db.scalar(select(func.count()).select_from(CollectionRun)),
    }


@router.post("/metrics/reproducibility")
def reproducibility(request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_roles("auditor", "admin"))):
    """Reexecuta as regras sobre as evidências GRAVADAS da última execução e compara com os
    achados registrados. Mesmas evidências + mesmos critérios => mesmo resultado."""
    run = db.scalar(select(CollectionRun).where(CollectionRun.status.like("concluido%"))
                    .order_by(CollectionRun.id.desc()).limit(1))
    if not run:
        return {"ok": False, "message": "Nenhuma execução concluída ainda"}
    params = load_params(db)
    excepted = {(e.rule_id, e.asset_id, (e.subject or "").lower()) for e in
                db.scalars(select(RiskException).where(RiskException.status == "aprovada"))}
    recomputed, ev_ids = set(), []
    for ev in db.scalars(select(Evidence).where(Evidence.run_id == run.id)):
        if not ev.asset.in_scope:
            continue
        ev_ids.append(ev.id)
        payload = decrypt_evidence(ev)
        obs = Observation(ev.collector, ev.source, ev.kind, ev.asset.name, ev.asset.asset_type, ev.asset.criticality,
                          payload["data"], ev.control_ids, payload.get("reachable", True))
        for r in evaluate(obs, params):
            if r.status == "conforme":
                continue
            if any(rid == r.rule_id and (aid is None or aid == ev.asset_id) and (not s or s == (r.subject or "").lower())
                   for rid, aid, s in excepted):
                continue
            recomputed.add(f"{r.rule_id}|{ev.asset_id}|{r.subject or ''}")
    recorded = set(db.scalars(select(Finding.dedupe_key).where(Finding.evidence_id.in_(ev_ids)))) if ev_ids else set()
    union = recomputed | recorded
    result = {"ok": recomputed == recorded, "run_id": run.id, "evidence": len(ev_ids),
              "recomputed": len(recomputed), "recorded": len(recorded),
              "jaccard": round(len(recomputed & recorded) / len(union), 3) if union else 1.0,
              "only_recomputed": sorted(recomputed - recorded), "only_recorded": sorted(recorded - recomputed),
              "note": "Se os parâmetros de política mudaram após a execução, divergências são esperadas."}
    append_audit(db, "teste_reprodutibilidade", user, details={"ok": result["ok"], "jaccard": result["jaccard"]},
                 ip=client_ip(request))
    db.commit()
    return result
