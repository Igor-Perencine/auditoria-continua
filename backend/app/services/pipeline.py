"""Ciclo de auditoria contínua: coleta -> evidência cifrada/encadeada -> regras -> achados ->
encerramento automático do que foi corrigido -> status dos 93 controles -> triagem por IA."""
import logging
import threading
from datetime import date

from sqlalchemy import func, select

from ..collectors import get_collectors
from ..config import settings
from ..db import SessionLocal, utcnow
from ..models import (Asset, CollectionRun, Control, ControlAssessment, Finding, PolicyChunk, RiskException,
                      ScenarioRun)
from ..security.crypto import canonical, encrypt_str
from .audit import append_audit
from .evidence import store_evidence
from .findings_logic import refresh_review_flags
from .params import load_params
from .rules import SEV_ORDER, compute_severity, evaluate

log = logging.getLogger(__name__)
_run_lock = threading.Lock()
_ai_lock = threading.Lock()


def _get_or_create_asset(db, obs) -> Asset:
    asset = db.scalar(select(Asset).where(Asset.name == obs.asset))
    if asset is None:
        asset = Asset(name=obs.asset, asset_type=obs.asset_type, criticality=obs.criticality)
        db.add(asset)
        db.flush()
    asset.last_seen_at = utcnow()
    return asset


def _active_exceptions(db) -> list[RiskException]:
    return list(db.scalars(select(RiskException).where(RiskException.status == "aprovada",
                                                       RiskException.expires_at >= date.today())))


def _match_exception(exceptions, res, asset) -> RiskException | None:
    for e in exceptions:
        if e.rule_id == res.rule_id and (e.asset_id is None or e.asset_id == asset.id) \
                and (not e.subject or (res.subject or "").lower() == e.subject.lower()):
            return e
    return None


def _upsert_finding(db, res, asset, ev, key, exc, now) -> int:
    f = db.scalar(select(Finding).where(Finding.dedupe_key == key, Finding.is_open.is_(True)))
    if exc:
        if f:
            f.is_open = False
            f.resolved_at = now
            f.resolution = f"Coberto pela exceção aprovada #{exc.id}"
        return 0
    severity = compute_severity(res.base_severity, asset.criticality)
    details = encrypt_str(canonical(res.excerpt), aad=f"finding:{key}")
    if f:
        if f.status != res.status:  # mudou a natureza do achado: reclassificar
            f.ai_classified_at = None
            f.ai_attempts = 0
        f.status = res.status
        f.condition = res.condition
        f.criterion = res.criterion
        f.rule_version = res.rule_version
        f.evidence_id = ev.id
        f.details_enc = details
        f.base_severity = res.base_severity
        f.severity = severity
        f.last_seen_at = now
        f.occurrences += 1
        refresh_review_flags(f)
        return 0
    f = Finding(
        dedupe_key=key, rule_id=res.rule_id, rule_version=res.rule_version, control_id=res.control_id,
        asset_id=asset.id, evidence_id=ev.id, subject=res.subject, status=res.status, criterion=res.criterion,
        condition=res.condition, details_enc=details, base_severity=res.base_severity, severity=severity,
        first_detected_at=utcnow(), last_seen_at=now, review_state="pendente", ai_citations=[], review_reasons=[],
    )
    refresh_review_flags(f)
    db.add(f)
    db.flush()
    return 1


def _resolve(db, evaluated: set, seen: set, now) -> int:
    """Reexecução do teste: o que não se repetiu é encerrado automaticamente (seção 2.7)."""
    count = 0
    for f in db.scalars(select(Finding).where(Finding.is_open.is_(True))):
        if (f.rule_id, f.asset_id) in evaluated and f.dedupe_key not in seen:
            f.is_open = False
            f.resolved_at = now
            f.resolution = "Condição não observada na reexecução do teste (corrigido)"
            count += 1
    return count


def update_assessments(db, evaluated_controls: set, now) -> None:
    open_rows = db.execute(
        select(Finding.control_id, Finding.status).where(Finding.is_open.is_(True),
                                                         Finding.review_state != "falso_positivo")).all()
    nc = {c for c, s in open_rows if s == "nao_conforme"}
    ia = {c for c, s in open_rows if s == "impossivel_avaliar"}
    documented = set(db.scalars(select(func.unnest(PolicyChunk.control_ids)).distinct()))
    for c in db.scalars(select(Control)):
        if c.id in nc:
            status, detail = "nao_conforme", "Há não conformidades abertas"
        elif c.id in ia:
            status, detail = "impossivel_avaliar", "Fonte de evidência indisponível"
        elif c.id in evaluated_controls:
            status, detail = "conforme", "Todos os testes automatizados passaram"
        elif c.automation == "manual":
            status, detail = "manual", "Requer inspeção presencial do auditor"
        elif c.id in documented:
            status, detail = "documentado", "Política vinculada — aguarda análise do auditor"
        else:
            status, detail = "sem_evidencia", "Nenhum teste ou política vinculada"
        row = db.get(ControlAssessment, c.id)
        if row is None:
            db.add(ControlAssessment(control_id=c.id, status=status, detail=detail, evaluated_at=now))
        elif row.status != status or c.id in evaluated_controls:
            row.status, row.detail, row.evaluated_at = status, detail, now


def _detect_scenarios(db) -> None:
    from ..collectors.simulator import SCENARIOS

    for sr in db.scalars(select(ScenarioRun).where(ScenarioRun.detected_at.is_(None),
                                                   ScenarioRun.reverted_at.is_(None))):
        rules = SCENARIOS.get(sr.scenario_key, {}).get("rules", [])
        f = db.scalar(select(Finding).where(Finding.rule_id.in_(rules), Finding.first_detected_at >= sr.injected_at)
                      .order_by(Finding.first_detected_at).limit(1))
        if f:
            sr.detected_at = f.first_detected_at
            sr.detected_finding_id = f.id


def _collect_and_evaluate(trigger: str, user_id: int | None) -> int:
    with SessionLocal() as db:
        run = CollectionRun(trigger=trigger, triggered_by=user_id, started_at=utcnow(), status="executando",
                            errors=[])
        db.add(run)
        db.commit()
        run_id = run.id
        try:
            params = load_params(db)
            exceptions = _active_exceptions(db)
            now = utcnow()
            evaluated, seen, evaluated_controls, errors = set(), set(), set(), []
            ev_count = new_count = 0
            for collector in get_collectors(db):
                try:
                    observations = collector.collect()
                except Exception as exc:
                    log.exception("Coletor %s falhou", collector.name)
                    errors.append(f"{collector.name}: {exc}")
                    continue
                for obs in observations:
                    asset = _get_or_create_asset(db, obs)
                    if not asset.in_scope:
                        continue
                    ev = store_evidence(db, obs, asset, run_id)
                    ev_count += 1
                    for res in evaluate(obs, params):
                        evaluated_controls.add(res.control_id)
                        if res.evaluated_ok:
                            evaluated.add((res.rule_id, asset.id))
                        if res.status == "conforme":
                            continue
                        key = f"{res.rule_id}|{asset.id}|{res.subject or ''}"
                        seen.add(key)
                        new_count += _upsert_finding(db, res, asset, ev, key,
                                                     _match_exception(exceptions, res, asset), now)
            resolved = _resolve(db, evaluated, seen, now)
            update_assessments(db, evaluated_controls, now)
            _detect_scenarios(db)
            run.status = "concluido_com_erros" if errors else "concluido"
            run.errors = errors
            run.evidence_count, run.findings_new, run.findings_resolved = ev_count, new_count, resolved
            run.finished_at = utcnow()
            append_audit(db, "ciclo_auditoria", None, target=f"execução #{run_id}", details={
                "gatilho": trigger, "evidencias": ev_count, "novos": new_count, "encerrados": resolved})
            db.commit()
        except Exception as exc:
            log.exception("Falha no ciclo de auditoria")
            db.rollback()
            run = db.get(CollectionRun, run_id)
            run.status, run.errors, run.finished_at = "falhou", [str(exc)], utcnow()
            db.commit()
        return run_id


def classify_pending(limit: int | None = None) -> int:
    from ..ai.provider import get_provider
    from ..ai.rag import classify_finding

    if not get_provider().enabled or not _ai_lock.acquire(blocking=False):
        return 0
    done = 0
    try:
        with SessionLocal() as db:
            pending = list(db.scalars(select(Finding).where(
                Finding.is_open.is_(True), Finding.ai_classified_at.is_(None), Finding.ai_attempts < 3,
                Finding.review_state == "pendente")))
            pending.sort(key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.first_detected_at))
            for f in pending[: limit or settings.ai_max_per_cycle]:
                classify_finding(db, f)
                db.commit()
                done += 1
    finally:
        _ai_lock.release()
    return done


def run_cycle(trigger: str = "agendado", user_id: int | None = None) -> int | None:
    if not _run_lock.acquire(blocking=False):
        log.info("Ciclo já em execução; ignorando novo gatilho")
        return None
    try:
        run_id = _collect_and_evaluate(trigger, user_id)
    finally:
        _run_lock.release()
    try:
        classify_pending()
    except Exception:
        log.exception("Falha na triagem por IA")
    return run_id


def is_running() -> bool:
    return _run_lock.locked()
