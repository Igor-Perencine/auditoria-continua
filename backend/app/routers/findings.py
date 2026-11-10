"""Painel do auditor: fila de triagem, detalhe rastreável e decisão humana final."""
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai.provider import get_provider
from ..ai.rag import classify_finding
from ..db import get_db, utcnow
from ..models import Decision, Evidence, Finding, User
from ..security.crypto import decrypt_str
from ..security.deps import client_ip, get_current_user, require_roles
from ..services.audit import append_audit
from ..services.findings_logic import refresh_review_flags
from ..services.rules import SEV_ORDER

router = APIRouter(prefix="/findings", tags=["achados"])


def finding_summary(f: Finding) -> dict:
    return {
        "id": f.id, "rule_id": f.rule_id, "control_id": f.control_id, "control_title": f.control.title,
        "asset": f.asset.name, "asset_criticality": f.asset.criticality, "subject": f.subject,
        "status": f.status, "condition": f.condition, "severity": f.final_severity or f.severity,
        "is_open": f.is_open, "review_state": f.review_state, "requires_human_review": f.requires_human_review,
        "review_reasons": f.review_reasons or [], "ai_status_suggested": f.ai_status_suggested,
        "ai_confidence": f.ai_confidence, "first_detected_at": f.first_detected_at, "last_seen_at": f.last_seen_at,
        "resolved_at": f.resolved_at, "occurrences": f.occurrences,
    }


def _visible(query, user: User):
    """Gestor só enxerga achados dos ativos sob sua responsabilidade."""
    if user.role == "gestor":
        from ..models import Asset
        query = query.join(Asset, Asset.id == Finding.asset_id).where(Asset.owner_id == user.id)
    return query


@router.get("")
def list_findings(open: bool = True, review_state: str | None = None, severity: str | None = None,
                  control_id: str | None = None, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    q = select(Finding).where(Finding.is_open.is_(open))
    if review_state:
        q = q.where(Finding.review_state == review_state)
    if control_id:
        q = q.where(Finding.control_id == control_id)
    q = _visible(q, user).order_by(Finding.last_seen_at.desc()).limit(500)
    items = [finding_summary(f) for f in db.scalars(q)]
    if severity:
        items = [i for i in items if i["severity"] == severity]
    # prioridade: revisão obrigatória > severidade > mais antigo
    items.sort(key=lambda i: (i["review_state"] != "pendente", not i["requires_human_review"],
                              -SEV_ORDER.get(i["severity"], 0), i["first_detected_at"]))
    return items


def _get_finding(db: Session, finding_id: int, user: User) -> Finding:
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Achado não encontrado")
    if user.role == "gestor" and f.asset.owner_id != user.id:
        raise HTTPException(403, "Achado fora dos seus ativos")
    return f


def _sod_block(f: Finding, user: User) -> str | None:
    if user.role != "auditor":
        return "Somente o perfil auditor pode decidir sobre achados."
    if f.asset.owner_id == user.id:
        return "Segregação de funções: você é o responsável pelo ativo e não pode avaliar a própria conformidade."
    return None


@router.get("/{finding_id}")
def finding_detail(finding_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    f = _get_finding(db, finding_id, user)
    ev = db.get(Evidence, f.evidence_id)
    details = json.loads(decrypt_str(f.details_enc, aad=f"finding:{f.dedupe_key}")) if f.details_enc else {}
    decisions = db.scalars(select(Decision).where(Decision.finding_id == f.id).order_by(Decision.created_at))
    block = _sod_block(f, user)
    return {
        **finding_summary(f),
        "criterion": f.criterion, "rule_version": f.rule_version, "base_severity": f.base_severity,
        "calculated_severity": f.severity, "final_status": f.final_status, "resolution": f.resolution,
        "asset_type": f.asset.asset_type, "asset_owner": f.asset.owner.username if f.asset.owner else None,
        "details": details,
        "evidence": {"id": ev.id, "seq": ev.seq, "hash": ev.hash, "prev_hash": ev.prev_hash, "source": ev.source,
                     "collector": ev.collector, "collected_at": ev.collected_at, "key_version": ev.key_version},
        "ai": {"status_suggested": f.ai_status_suggested, "severity": f.ai_severity, "confidence": f.ai_confidence,
               "justification": f.ai_justification, "citations": f.ai_citations or [],
               "citations_valid": f.ai_citations_valid, "model": f.ai_model, "classified_at": f.ai_classified_at,
               "prompt_sha256": f.ai_prompt_sha256, "error": f.ai_error, "provider": get_provider().info()},
        "decisions": [{"id": d.id, "user": d.user.username, "action": d.action, "note": d.note,
                       "final_status": d.final_status, "final_severity": d.final_severity,
                       "ai_status_suggested": d.ai_status_suggested, "created_at": d.created_at} for d in decisions],
        "can_decide": block is None and f.is_open, "decide_block_reason": block,
    }


class DecisionIn(BaseModel):
    action: Literal["aprovar", "rejeitar", "alterar"]
    note: str = Field(min_length=5, max_length=2000)
    severity: Literal["baixa", "media", "alta", "critica"] | None = None
    status: Literal["nao_conforme", "impossivel_avaliar"] | None = None


@router.post("/{finding_id}/decision")
def decide(finding_id: int, body: DecisionIn, request: Request, db: Session = Depends(get_db),
           user: User = Depends(require_roles("auditor"))):
    f = _get_finding(db, finding_id, user)
    block = _sod_block(f, user)
    if block:
        raise HTTPException(403, block)
    if not f.is_open:
        raise HTTPException(400, "Achado já encerrado")
    if body.action == "aprovar":
        final_status, final_sev, state = f.status, f.severity, "confirmado"
    elif body.action == "rejeitar":
        final_status, final_sev, state = "falso_positivo", f.severity, "falso_positivo"
    else:
        if not body.severity and not body.status:
            raise HTTPException(400, "Informe a nova severidade e/ou o novo status")
        final_status, final_sev, state = body.status or f.status, body.severity or f.severity, "confirmado"
    db.add(Decision(finding_id=f.id, user_id=user.id, action=body.action, note=body.note, rule_status=f.status,
                    ai_status_suggested=f.ai_status_suggested, ai_severity=f.ai_severity,
                    final_status=final_status, final_severity=final_sev, created_at=utcnow()))
    f.review_state, f.final_status, f.final_severity = state, final_status, final_sev
    refresh_review_flags(f)
    append_audit(db, "decisao_achado", user, target=f"achado #{f.id}", details={
        "acao": body.action, "status_final": final_status, "severidade_final": final_sev,
        "sugestao_ia": f.ai_status_suggested, "nota": body.note[:500]}, ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/{finding_id}/classify")
def reclassify(finding_id: int, request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_roles("auditor", "admin"))):
    f = _get_finding(db, finding_id, user)
    if not get_provider().enabled:
        raise HTTPException(400, "IA desabilitada. Configure AI_PROVIDER no arquivo .env")
    f.ai_attempts = 0
    classify_finding(db, f)
    append_audit(db, "ia_reclassificacao_solicitada", user, target=f"achado #{f.id}", ip=client_ip(request))
    db.commit()
    if f.ai_error:
        raise HTTPException(502, f.ai_error)
    return {"ok": True}
