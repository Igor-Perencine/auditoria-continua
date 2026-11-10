"""Registro dos coletores (camada de integração de fontes).

O coletor de políticas (base documental da própria plataforma) roda sempre; os demais são
ligados pela variável ENABLED_COLLECTORS do .env (simulador, active_directory, wazuh).
"""
import logging

from ..config import settings
from .base import Collector
from .policies import PoliciesCollector
from .simulator import SimulatorCollector

log = logging.getLogger(__name__)


def _registry() -> dict[str, type[Collector]]:
    registry: dict[str, type[Collector]] = {"simulador": SimulatorCollector}
    # Coletores reais são importados sob demanda (dependências opcionais / experimentais).
    try:
        from .active_directory import ActiveDirectoryCollector
        registry["active_directory"] = ActiveDirectoryCollector
    except Exception:  # pragma: no cover
        log.warning("Coletor active_directory indisponível (ldap3 não instalado?)")
    try:
        from .wazuh import WazuhCollector
        registry["wazuh"] = WazuhCollector
    except Exception:  # pragma: no cover
        log.warning("Coletor wazuh indisponível")
    return registry


def enabled_collector_names() -> list[str]:
    return [n.strip().lower() for n in settings.enabled_collectors.split(",") if n.strip()]


def get_collectors(db) -> list[Collector]:
    registry = _registry()
    collectors: list[Collector] = [PoliciesCollector(db)]
    for name in enabled_collector_names():
        cls = registry.get(name)
        if cls is None:
            log.warning("Coletor desconhecido em ENABLED_COLLECTORS: %s", name)
            continue
        collectors.append(cls(db))
    return collectors
