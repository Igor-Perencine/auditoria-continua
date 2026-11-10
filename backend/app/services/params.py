"""Parâmetros de política (estado esperado). Editáveis pelo administrador; cada alteração
muda a 'versão do critério' registrada nos achados (rastreabilidade)."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Parameter

DEFAULTS: dict[str, tuple[object, str]] = {
    "max_inactive_days": (90, "Dias sem logon para considerar uma conta inativa (A.5.18)"),
    "privilegiados_aprovados": ("admin.ti,svc.backup", "Contas privilegiadas formalmente aprovadas, separadas por vírgula (A.8.2)"),
    "password_min_length": (12, "Tamanho mínimo de senha exigido pela política (A.5.17)"),
    "lockout_max": (10, "Máximo de tentativas antes do bloqueio de conta (A.5.17)"),
    "av_signature_max_days": (3, "Idade máxima das assinaturas do antimalware em dias (A.8.7)"),
    "vuln_critical_sla_days": (15, "Prazo para corrigir vulnerabilidade crítica, CVSS >= 9 (A.8.8)"),
    "vuln_high_sla_days": (30, "Prazo para corrigir vulnerabilidade alta, CVSS >= 7 (A.8.8)"),
    "patch_max_days": (45, "Dias máximos desde a última atualização do sistema (A.8.8)"),
    "sca_min_score": (70, "Pontuação mínima de conformidade de configuração SCA/CIS (A.8.9)"),
    "log_silence_minutes": (60, "Minutos sem eventos para considerar uma fonte de log silenciosa (A.8.15)"),
    "clock_max_drift_seconds": (60, "Desvio máximo de relógio em segundos (A.8.17)"),
    "backup_max_age_hours": (26, "Horas máximas desde o último backup bem-sucedido (A.8.13)"),
    "restore_test_max_days": (90, "Dias máximos desde o último teste de restauração (A.8.13)"),
    "policy_review_max_days": (365, "Dias máximos desde a aprovação/revisão de uma política (A.5.1)"),
}


def seed_params(db: Session) -> None:
    existing = set(db.scalars(select(Parameter.key)))
    for key, (value, desc) in DEFAULTS.items():
        if key not in existing:
            db.add(Parameter(key=key, value=str(value), description=desc))


def _convert(key: str, raw: str):
    default = DEFAULTS.get(key, (raw,))[0]
    try:
        if isinstance(default, bool):
            return raw.lower() in ("1", "true", "sim")
        if isinstance(default, int):
            return int(raw)
        if isinstance(default, float):
            return float(raw)
    except ValueError:
        return default
    return raw


def load_params(db: Session) -> dict:
    values = {k: v[0] for k, v in DEFAULTS.items()}
    for p in db.scalars(select(Parameter)):
        values[p.key] = _convert(p.key, p.value)
    return values


def validate_param(key: str, raw: str) -> str | None:
    if key not in DEFAULTS:
        return "Parâmetro desconhecido"
    default = DEFAULTS[key][0]
    if isinstance(default, int) and not isinstance(default, bool):
        try:
            if int(raw) < 0:
                return "Valor deve ser positivo"
        except ValueError:
            return "Valor deve ser um número inteiro"
    return None
