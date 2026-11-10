"""Laboratório simulado: um ambiente corporativo fictício com AD, servidores, estações e backup.

Serve para a avaliação em 'cenários controlados' (objetivo específico "e"): o pesquisador injeta
uma falha conhecida (ex.: conta de ex-colaborador ativa) e a plataforma mede quanto tempo leva
para detectá-la. Tudo é determinístico — essencial para medir reprodutibilidade.
"""
import copy

from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import LabState
from .base import KIND_CONTROLS, Collector, Observation


def _host(type_, crit, os_, **kw):
    base = {
        "type": type_, "criticality": crit, "reachable": True, "os": os_, "av_enabled": True,
        "av_signature_age_days": 0, "last_patch_days": 12, "firewall": True, "smbv1": False,
        "rdp_nla": True, "clock_drift_s": 0.4, "log_last_event_minutes": 2, "vulns": [],
    }
    base.update(kw)
    return base


BASE_STATE = {
    "accounts": {
        "admin.ti": {"enabled": True, "last_logon_days": 1, "privileged": True, "mfa": True, "service": False, "employee_id": "E001"},
        "ana.souza": {"enabled": True, "last_logon_days": 2, "privileged": False, "mfa": True, "service": False, "employee_id": "E002"},
        "bruno.lima": {"enabled": True, "last_logon_days": 3, "privileged": False, "mfa": True, "service": False, "employee_id": "E003"},
        "carla.mendes": {"enabled": True, "last_logon_days": 1, "privileged": False, "mfa": True, "service": False, "employee_id": "E004"},
        "diego.rocha": {"enabled": True, "last_logon_days": 8, "privileged": False, "mfa": True, "service": False, "employee_id": "E005"},
        "svc.backup": {"enabled": True, "last_logon_days": 0, "privileged": True, "mfa": False, "service": True, "employee_id": None},
    },
    "hr": {"E001": "ativo", "E002": "ativo", "E003": "ativo", "E004": "ativo", "E005": "ativo"},
    "password_policy": {"min_length": 14, "complexity": True, "lockout_threshold": 5, "max_age_days": 90},
    "hosts": {
        "DC01": _host("servidor", 5, "Windows Server 2022"),
        "SRV-DB01": _host("servidor", 5, "Ubuntu 22.04 LTS", rdp_nla=None),
        "SRV-WEB01": _host("servidor", 4, "Ubuntu 24.04 LTS", rdp_nla=None),
        # Servidor legado com SMBv1 ligado: há exceção documentada na política POL-SI-003,
        # mas não cadastrada na plataforma -> demonstra a IA sugerindo 'falso_positivo'.
        "SRV-LEGADO01": _host("servidor", 3, "Windows Server 2012 R2", smbv1=True, last_patch_days=20),
        "WS-001": _host("estacao", 2, "Windows 11 23H2"),
        "WS-002": _host("estacao", 2, "Windows 11 23H2"),
        "WS-003": _host("estacao", 2, "Windows 11 23H2"),
    },
    "backups": {
        "DC01": {"last_success_hours": 5, "last_restore_test_days": 40},
        "SRV-DB01": {"last_success_hours": 4, "last_restore_test_days": 35},
        "SRV-WEB01": {"last_success_hours": 6, "last_restore_test_days": 60},
    },
}

# Cenários de injeção de falhas. 'patch' = lista de (caminho, valor injetado).
SCENARIOS = {
    "conta_inativa": {
        "title": "Conta de usuário sem uso há 120 dias", "control": "A.5.18", "rules": ["R-A5.18-01"],
        "patch": [(("accounts", "bruno.lima", "last_logon_days"), 120)],
    },
    "ex_colaborador": {
        "title": "Colaborador desligado no RH com conta ainda ativa", "control": "A.5.18", "rules": ["R-A5.18-02"],
        "patch": [(("hr", "E004"), "desligado")],
    },
    "privilegio_nao_aprovado": {
        "title": "Usuário comum adicionado ao grupo de administradores", "control": "A.8.2", "rules": ["R-A8.2-01"],
        "patch": [(("accounts", "ana.souza", "privileged"), True)],
    },
    "admin_sem_mfa": {
        "title": "Administrador com MFA desativado", "control": "A.8.5", "rules": ["R-A8.5-01"],
        "patch": [(("accounts", "admin.ti", "mfa"), False)],
    },
    "politica_senha_fraca": {
        "title": "Política de senha do domínio reduzida para 6 caracteres", "control": "A.5.17", "rules": ["R-A5.17-01"],
        "patch": [(("password_policy", "min_length"), 6)],
    },
    "antivirus_desligado": {
        "title": "Antimalware desabilitado em estação", "control": "A.8.7", "rules": ["R-A8.7-01"],
        "patch": [(("hosts", "WS-002", "av_enabled"), False)],
    },
    "vulnerabilidade_critica": {
        "title": "Vulnerabilidade crítica aberta há 40 dias no servidor web", "control": "A.8.8", "rules": ["R-A8.8-01"],
        "patch": [(("hosts", "SRV-WEB01", "vulns"), [
            {"cve": "CVE-2024-6387", "cvss": 9.8, "age_days": 40, "package": "openssh-server"}])],
    },
    "patch_atrasado": {
        "title": "Estação sem atualizações há 75 dias", "control": "A.8.8", "rules": ["R-A8.8-02"],
        "patch": [(("hosts", "WS-003", "last_patch_days"), 75)],
    },
    "firewall_desligado": {
        "title": "Firewall de host desligado no servidor web", "control": "A.8.9", "rules": ["R-A8.9-01"],
        "patch": [(("hosts", "SRV-WEB01", "firewall"), False)],
    },
    "backup_falhou": {
        "title": "Backup do banco de dados falhando há 3 dias", "control": "A.8.13", "rules": ["R-A8.13-01"],
        "patch": [(("backups", "SRV-DB01", "last_success_hours"), 72)],
    },
    "restauracao_nao_testada": {
        "title": "Teste de restauração não realizado há 200 dias", "control": "A.8.13", "rules": ["R-A8.13-02"],
        "patch": [(("backups", "DC01", "last_restore_test_days"), 200)],
    },
    "log_silencioso": {
        "title": "Servidor de banco parou de enviar logs", "control": "A.8.15", "rules": ["R-A8.15-01"],
        "patch": [(("hosts", "SRV-DB01", "log_last_event_minutes"), 600)],
    },
    "relogio_dessincronizado": {
        "title": "Estação com relógio 5 minutos adiantado", "control": "A.8.17", "rules": ["R-A8.17-01"],
        "patch": [(("hosts", "WS-001", "clock_drift_s"), 300)],
    },
    "fonte_indisponivel": {
        "title": "Agente de coleta do servidor web sem resposta", "control": "A.8.8",
        "rules": ["R-A8.7-01", "R-A8.8-01", "R-A8.8-02", "R-A8.9-01", "R-A8.15-01", "R-A8.17-01"],
        "patch": [(("hosts", "SRV-WEB01", "reachable"), False)],
    },
}


def _get(obj, path):
    for p in path:
        obj = obj[p]
    return obj


def _set(obj, path, value):
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = copy.deepcopy(value)


def get_state(db: Session) -> dict:
    row = db.get(LabState, 1)
    if row is None:
        row = LabState(id=1, state=copy.deepcopy(BASE_STATE))
        db.add(row)
        db.flush()
    return copy.deepcopy(row.state)


def save_state(db: Session, state: dict) -> None:
    row = db.get(LabState, 1)
    row.state = state  # reatribuição garante que o JSONB seja persistido
    row.updated_at = utcnow()


def apply_scenario(db: Session, key: str) -> None:
    state = get_state(db)
    for path, value in SCENARIOS[key]["patch"]:
        _set(state, path, value)
    save_state(db, state)


def revert_scenario(db: Session, key: str) -> None:
    state = get_state(db)
    for path, _ in SCENARIOS[key]["patch"]:
        _set(state, path, _get(BASE_STATE, path))
    save_state(db, state)


def reset_state(db: Session) -> None:
    get_state(db)
    save_state(db, copy.deepcopy(BASE_STATE))


class SimulatorCollector(Collector):
    name = "simulador"

    def collect(self) -> list[Observation]:
        st = get_state(self.db)
        obs = [
            Observation(
                collector=self.name, source="Active Directory + sistema de RH (simulados)", kind="identidades",
                asset="DC01", asset_type="servidor", criticality=5, control_ids=KIND_CONTROLS["identidades"],
                data={"accounts": st["accounts"], "hr": st["hr"]},
            ),
            Observation(
                collector=self.name, source="GPO de domínio (simulada)", kind="politica_senha", asset="DC01",
                asset_type="servidor", criticality=5, control_ids=KIND_CONTROLS["politica_senha"],
                data=st["password_policy"],
            ),
        ]
        for name, h in st["hosts"].items():
            reachable = h.get("reachable", True)
            data = {k: v for k, v in h.items() if k not in ("type", "criticality", "reachable")}
            if not reachable:
                data = {"erro": "Agente de endpoint não respondeu (timeout após 30 s)"}
            obs.append(Observation(
                collector=self.name, source="Agente de endpoint (simulado)", kind="host", asset=name,
                asset_type=h["type"], criticality=h["criticality"], control_ids=KIND_CONTROLS["host"],
                data=data, reachable=reachable,
            ))
        for name, b in st["backups"].items():
            obs.append(Observation(
                collector=self.name, source="Servidor de backup (simulado)", kind="backup", asset=name,
                asset_type=st["hosts"][name]["type"], criticality=st["hosts"][name]["criticality"],
                control_ids=KIND_CONTROLS["backup"], data=b,
            ))
        return obs
