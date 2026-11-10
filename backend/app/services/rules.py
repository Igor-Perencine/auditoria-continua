"""Motor de regras determinísticas (testes de controle).

Cada regra compara o ESTADO OBSERVADO (evidência normalizada) com o ESTADO ESPERADO
(parâmetros de política) e produz: conforme | nao_conforme | impossivel_avaliar.
A IA nunca substitui estas regras — ela atua depois, na triagem (seção 2.8 do TCC).
"""
from dataclasses import dataclass, field
from typing import Callable, NamedTuple

from ..security.crypto import canonical, sha256_hex

SEV_ORDER = {"baixa": 1, "media": 2, "alta": 3, "critica": 4}


class NC(NamedTuple):
    subject: str | None
    condition: str
    base_severity: str
    excerpt: dict


@dataclass
class Rule:
    rule_id: str
    control_id: str
    kind: str
    title: str
    criterion: str  # texto com {placeholders} dos parâmetros
    params: tuple[str, ...]
    fn: Callable[[dict, dict], list[NC]]
    version: str = "1.0"

    def criterion_text(self, p: dict) -> str:
        return self.criterion.format(**p)

    def version_id(self, p: dict) -> str:
        used = {k: p.get(k) for k in self.params}
        return f"{self.version}#{sha256_hex(canonical(used))[:10]}"


@dataclass
class RuleResult:
    rule_id: str
    rule_version: str
    control_id: str
    status: str
    subject: str | None
    condition: str
    criterion: str
    base_severity: str
    excerpt: dict = field(default_factory=dict)
    evaluated_ok: bool = True


RULES: list[Rule] = []


def rule(rule_id, control_id, kind, title, criterion, params=(), version="1.0"):
    def deco(fn):
        RULES.append(Rule(rule_id, control_id, kind, title, criterion, tuple(params), fn, version))
        return fn
    return deco


def compute_severity(base: str, criticality: int) -> str:
    """Severidade = impacto da regra x criticidade do ativo (seção 2.7)."""
    score = SEV_ORDER.get(base, 2) * max(1, min(5, criticality))
    if score >= 15:
        return "critica"
    if score >= 8:
        return "alta"
    if score >= 4:
        return "media"
    return "baixa"


# ----------------------------------------------------------------- identidades

@rule("R-A5.18-01", "A.5.18", "identidades", "Contas ativas sem uso",
      "Contas de usuário sem logon há mais de {max_inactive_days} dias devem ser desabilitadas.",
      params=("max_inactive_days",))
def _inactive(d, p):
    out = []
    for u, a in d.get("accounts", {}).items():
        days = a.get("last_logon_days")
        if a.get("enabled") and not a.get("service") and days is not None and days > p["max_inactive_days"]:
            out.append(NC(u, f"Conta '{u}' habilitada e sem logon há {days} dias.", "media", {"conta": u, **a}))
    return out


@rule("R-A5.18-02", "A.5.18", "identidades", "Contas de colaboradores desligados",
      "Acessos de colaboradores desligados devem ser revogados no desligamento.")
def _terminated(d, p):
    out = []
    hr = d.get("hr", {})
    for u, a in d.get("accounts", {}).items():
        emp = a.get("employee_id")
        if emp and hr.get(emp) == "desligado" and a.get("enabled"):
            out.append(NC(u, f"Conta '{u}' continua habilitada, mas o colaborador {emp} consta como desligado no RH.",
                          "alta", {"conta": u, "status_rh": "desligado", **a}))
    return out


@rule("R-A8.2-01", "A.8.2", "identidades", "Privilégio administrativo não aprovado",
      "Somente contas formalmente aprovadas ({privilegiados_aprovados}) podem ter privilégio administrativo.",
      params=("privilegiados_aprovados",))
def _privileged(d, p):
    approved = {x.strip().lower() for x in str(p["privilegiados_aprovados"]).split(",") if x.strip()}
    out = []
    for u, a in d.get("accounts", {}).items():
        if a.get("enabled") and a.get("privileged") and u.lower() not in approved:
            out.append(NC(u, f"Conta '{u}' possui privilégio administrativo sem aprovação registrada.",
                          "alta", {"conta": u, **a}))
    return out


@rule("R-A8.5-01", "A.8.5", "identidades", "Administrador sem MFA",
      "Contas privilegiadas de pessoas devem usar autenticação multifator.")
def _admin_mfa(d, p):
    out = []
    for u, a in d.get("accounts", {}).items():
        if a.get("enabled") and a.get("privileged") and not a.get("service") and a.get("mfa") is False:
            out.append(NC(u, f"Conta privilegiada '{u}' sem MFA habilitado.", "alta", {"conta": u, **a}))
    return out


# ----------------------------------------------------------------- política de senha

@rule("R-A5.17-01", "A.5.17", "politica_senha", "Política de senha do domínio",
      "Senhas devem ter no mínimo {password_min_length} caracteres, complexidade habilitada e bloqueio "
      "após no máximo {lockout_max} tentativas.", params=("password_min_length", "lockout_max"))
def _password_policy(d, p):
    problems = []
    if d.get("min_length") is not None and d["min_length"] < p["password_min_length"]:
        problems.append(f"tamanho mínimo {d['min_length']} (exigido {p['password_min_length']})")
    if d.get("complexity") is False:
        problems.append("complexidade desabilitada")
    lt = d.get("lockout_threshold")
    if lt is not None and (lt == 0 or lt > p["lockout_max"]):
        problems.append(f"bloqueio após {lt or 'nunca'} tentativas")
    if problems:
        return [NC(None, "Política de senha fora do padrão: " + "; ".join(problems) + ".", "media", d)]
    return []


# ----------------------------------------------------------------- hosts

@rule("R-A8.7-01", "A.8.7", "host", "Proteção antimalware",
      "O antimalware deve estar ativo e com assinaturas de no máximo {av_signature_max_days} dias.",
      params=("av_signature_max_days",))
def _antimalware(d, p):
    if d.get("av_enabled") is False:
        return [NC(None, "Proteção antimalware desabilitada.", "alta", {"av_enabled": False})]
    age = d.get("av_signature_age_days")
    if age is not None and age > p["av_signature_max_days"]:
        return [NC(None, f"Assinaturas do antimalware com {age} dias.", "media", {"av_signature_age_days": age})]
    return []


@rule("R-A8.8-01", "A.8.8", "host", "Vulnerabilidades fora do prazo",
      "Vulnerabilidades críticas (CVSS>=9) devem ser corrigidas em {vuln_critical_sla_days} dias e altas "
      "(CVSS>=7) em {vuln_high_sla_days} dias.", params=("vuln_critical_sla_days", "vuln_high_sla_days"))
def _vulns(d, p):
    out = []
    for v in d.get("vulns") or []:
        cvss = float(v.get("cvss", 0))
        sla = p["vuln_critical_sla_days"] if cvss >= 9 else p["vuln_high_sla_days"] if cvss >= 7 else None
        if sla is not None and v.get("age_days", 0) > sla:
            out.append(NC(v.get("cve"), f"{v.get('cve')} (CVSS {cvss}) em '{v.get('package')}' aberta há "
                                        f"{v.get('age_days')} dias (prazo: {sla}).",
                          "critica" if cvss >= 9 else "alta", v))
    return out


@rule("R-A8.8-02", "A.8.8", "host", "Atualizações do sistema",
      "Sistemas devem receber atualizações em no máximo {patch_max_days} dias.", params=("patch_max_days",))
def _patches(d, p):
    days = d.get("last_patch_days")
    if days is not None and days > p["patch_max_days"]:
        return [NC(None, f"Última atualização aplicada há {days} dias.", "media", {"last_patch_days": days})]
    return []


@rule("R-A8.9-01", "A.8.9", "host", "Desvio do baseline de configuração",
      "Baseline aprovado: firewall de host ativo, SMBv1 desabilitado e RDP com NLA.")
def _baseline(d, p):
    out = []
    if d.get("firewall") is False:
        out.append(NC("firewall", "Firewall de host desligado.", "media", {"firewall": False}))
    if d.get("smbv1") is True:
        out.append(NC("smbv1", "Protocolo SMBv1 habilitado.", "media", {"smbv1": True}))
    if d.get("rdp_nla") is False:
        out.append(NC("rdp_nla", "RDP aceitando conexões sem NLA.", "media", {"rdp_nla": False}))
    return out


@rule("R-A8.9-02", "A.8.9", "host", "Pontuação de hardening (SCA/CIS)",
      "A pontuação de conformidade com o benchmark CIS deve ser no mínimo {sca_min_score}%.",
      params=("sca_min_score",))
def _sca(d, p):
    score = d.get("sca_score")
    if score is not None and score < p["sca_min_score"]:
        return [NC(None, f"Pontuação SCA de {score}%.", "media", {"sca_score": score})]
    return []


@rule("R-A8.15-01", "A.8.15", "host", "Fonte de log silenciosa",
      "Cada ativo deve enviar eventos ao repositório central; silêncio máximo de {log_silence_minutes} minutos.",
      params=("log_silence_minutes",))
def _logs(d, p):
    m = d.get("log_last_event_minutes")
    if m is not None and m > p["log_silence_minutes"]:
        return [NC(None, f"Nenhum evento recebido há {m} minutos.", "alta", {"log_last_event_minutes": m})]
    return []


@rule("R-A8.17-01", "A.8.17", "host", "Sincronização de relógio",
      "Relógios devem estar sincronizados via NTP com desvio máximo de {clock_max_drift_seconds} s.",
      params=("clock_max_drift_seconds",))
def _clock(d, p):
    drift = d.get("clock_drift_s")
    if drift is not None and abs(drift) > p["clock_max_drift_seconds"]:
        return [NC(None, f"Relógio com desvio de {drift} s.", "baixa", {"clock_drift_s": drift})]
    return []


# ----------------------------------------------------------------- backup

@rule("R-A8.13-01", "A.8.13", "backup", "Backup recente",
      "Deve existir backup bem-sucedido nas últimas {backup_max_age_hours} horas.",
      params=("backup_max_age_hours",))
def _backup(d, p):
    h = d.get("last_success_hours")
    if h is not None and h > p["backup_max_age_hours"]:
        return [NC(None, f"Último backup bem-sucedido há {h} horas.", "alta", d)]
    return []


@rule("R-A8.13-02", "A.8.13", "backup", "Teste de restauração",
      "A restauração deve ser testada a cada {restore_test_max_days} dias (sucesso do job não prova recuperabilidade).",
      params=("restore_test_max_days",))
def _restore(d, p):
    days = d.get("last_restore_test_days")
    if days is not None and days > p["restore_test_max_days"]:
        return [NC(None, f"Último teste de restauração há {days} dias.", "media", d)]
    return []


# ----------------------------------------------------------------- documentos

@rule("R-A5.1-01", "A.5.1", "documentos", "Políticas aprovadas e revisadas",
      "Deve existir política de SI aprovada, e cada política deve ser revisada em até {policy_review_max_days} dias.",
      params=("policy_review_max_days",))
def _policies(d, p):
    docs = d.get("documents", [])
    if not docs:
        return [NC(None, "Nenhuma política de segurança da informação cadastrada na plataforma.", "alta", {})]
    out = []
    for doc in docs:
        if doc.get("age_days") is None:
            out.append(NC(doc["code"], f"Política {doc['code']} sem data de aprovação registrada.", "baixa", doc))
        elif doc["age_days"] > p["policy_review_max_days"]:
            out.append(NC(doc["code"], f"Política {doc['code']} ('{doc['title']}') sem revisão há "
                                       f"{doc['age_days']} dias.", "media", doc))
    return out


# ----------------------------------------------------------------- avaliação

def rules_for_kind(kind: str) -> list[Rule]:
    return [r for r in RULES if r.kind == kind]


def get_rule(rule_id: str) -> Rule | None:
    return next((r for r in RULES if r.rule_id == rule_id), None)


def evaluate(obs, params: dict) -> list[RuleResult]:
    results = []
    for r in rules_for_kind(obs.kind):
        base = dict(rule_id=r.rule_id, rule_version=r.version_id(params), control_id=r.control_id,
                    criterion=r.criterion_text(params))
        if not obs.reachable:
            results.append(RuleResult(**base, status="impossivel_avaliar", subject=None,
                                      condition=f"Fonte de evidência indisponível ({obs.source}): "
                                                f"{obs.data.get('erro', 'sem resposta')}",
                                      base_severity="media", evaluated_ok=False))
            continue
        try:
            ncs = r.fn(obs.data, params)
        except Exception as exc:  # dado malformado não pode virar 'conforme'
            results.append(RuleResult(**base, status="impossivel_avaliar", subject=None,
                                      condition=f"Erro ao avaliar a evidência: {exc}", base_severity="media",
                                      evaluated_ok=False))
            continue
        if not ncs:
            results.append(RuleResult(**base, status="conforme", subject=None, condition="", base_severity="baixa"))
        for nc in ncs:
            results.append(RuleResult(**base, status="nao_conforme", subject=nc.subject, condition=nc.condition,
                                      base_severity=nc.base_severity, excerpt=nc.excerpt))
    return results
