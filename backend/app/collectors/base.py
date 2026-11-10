"""Contrato comum dos coletores (camada de integração de fontes + normalização).

Todo coletor devolve Observations num formato normalizado por 'kind'. As regras
(services/rules.py) só conhecem esse formato — por isso trocar o simulador por uma fonte
real (AD, Wazuh, etc.) não exige mudar as regras.

Formatos ('kind'):
  identidades    {"accounts": {username: {enabled, last_logon_days, privileged, mfa, service, employee_id}},
                  "hr": {employee_id: "ativo"|"desligado"}}
  politica_senha {"min_length", "complexity", "lockout_threshold", "max_age_days"}
  host           {"os", "av_enabled", "av_signature_age_days", "last_patch_days", "firewall", "smbv1",
                  "rdp_nla", "clock_drift_s", "log_last_event_minutes", "sca_score",
                  "vulns": [{"cve", "cvss", "age_days", "package"}]}   (campos ausentes = não avaliados)
  backup         {"last_success_hours", "last_restore_test_days"}
  documentos     {"documents": [{"code", "title", "version", "approved_at", "age_days"}]}
"""
from dataclasses import dataclass, field


@dataclass
class Observation:
    collector: str
    source: str
    kind: str
    asset: str
    asset_type: str
    criticality: int
    data: dict
    control_ids: list[str] = field(default_factory=list)
    reachable: bool = True


KIND_CONTROLS = {
    "identidades": ["A.5.16", "A.5.18", "A.8.2", "A.8.5"],
    "politica_senha": ["A.5.17"],
    "host": ["A.8.7", "A.8.8", "A.8.9", "A.8.15", "A.8.17"],
    "backup": ["A.8.13"],
    "documentos": ["A.5.1"],
}


class Collector:
    name = "base"

    def __init__(self, db):
        self.db = db

    def collect(self) -> list[Observation]:
        raise NotImplementedError
