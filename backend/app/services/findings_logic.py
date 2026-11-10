"""Regras de encaminhamento à revisão humana (seção 2.7 do TCC): alto impacto, baixa confiança
da IA ou ausência de política/exceção documentada exigem revisão obrigatória."""
from ..config import settings


def refresh_review_flags(f) -> None:
    reasons = []
    sev = f.final_severity or f.severity
    if sev in ("alta", "critica"):
        reasons.append("Alto impacto")
    if f.status == "impossivel_avaliar":
        reasons.append("Evidência indisponível")
    if f.ai_classified_at is None:
        reasons.append("Sem pré-classificação da IA")
    else:
        if (f.ai_confidence or 0) < settings.ai_confidence_threshold:
            reasons.append("Baixa confiança da IA")
        if not f.ai_citations:
            reasons.append("Sem política correspondente (possível exceção não documentada)")
        elif f.ai_citations_valid is False:
            reasons.append("Citações da IA não verificadas")
        if f.ai_status_suggested and f.ai_status_suggested != f.status:
            reasons.append("IA diverge do resultado da regra")
    f.review_reasons = reasons
    f.requires_human_review = bool(reasons)
