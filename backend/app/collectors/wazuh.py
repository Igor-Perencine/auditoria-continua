"""Coletor real (EXPERIMENTAL) para Wazuh (SIEM/XDR open source e gratuito).

Usa a API REST do Wazuh Manager (porta 55000):
  * /agents       -> último keep-alive do agente (detecta fontes silenciosas, A.8.15)
  * /sca/{agent}  -> pontuação de conformidade com benchmarks CIS (A.8.9)
Configure no .env: ENABLED_COLLECTORS=simulador,wazuh  WAZUH_URL=https://wazuh:55000 ...
"""
from datetime import datetime, timezone

import httpx

from ..config import settings
from .base import KIND_CONTROLS, Collector, Observation


class WazuhCollector(Collector):
    name = "wazuh"

    def _client(self) -> httpx.Client:
        auth = httpx.post(f"{settings.wazuh_url}/security/user/authenticate",
                          auth=(settings.wazuh_user, settings.wazuh_password),
                          verify=settings.wazuh_verify_tls, timeout=20)
        auth.raise_for_status()
        token = auth.json()["data"]["token"]
        return httpx.Client(base_url=settings.wazuh_url, headers={"Authorization": f"Bearer {token}"},
                            verify=settings.wazuh_verify_tls, timeout=30)

    def collect(self) -> list[Observation]:
        try:
            client = self._client()
        except Exception as exc:
            return [Observation(self.name, "Wazuh Manager", "host", "wazuh-manager", "servidor", 4,
                                {"erro": f"Falha ao autenticar na API do Wazuh: {exc}"},
                                KIND_CONTROLS["host"], False)]
        result = []
        with client:
            agents = client.get("/agents", params={"limit": 500}).json()["data"]["affected_items"]
            for ag in agents:
                if ag.get("id") == "000":  # o próprio manager
                    continue
                data: dict = {"os": (ag.get("os") or {}).get("name", "desconhecido")}
                keep = ag.get("lastKeepAlive")
                if keep:
                    ts = datetime.fromisoformat(keep.replace("Z", "+00:00"))
                    data["log_last_event_minutes"] = int((datetime.now(timezone.utc) - ts).total_seconds() // 60)
                try:
                    sca = client.get(f"/sca/{ag['id']}").json()["data"]["affected_items"]
                    if sca:
                        data["sca_score"] = min(int(s.get("score", 100)) for s in sca)
                except Exception:
                    pass
                result.append(Observation(self.name, "Wazuh (agente + SCA)", "host", ag.get("name", ag["id"]),
                                          "servidor", 3, data, KIND_CONTROLS["host"]))
        return result
