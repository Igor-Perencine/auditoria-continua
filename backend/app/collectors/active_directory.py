"""Coletor real (EXPERIMENTAL) para Active Directory via LDAP(S) — gratuito, usa a biblioteca ldap3.

Use uma conta de serviço SOMENTE LEITURA. Configure no .env:
  ENABLED_COLLECTORS=simulador,active_directory
  AD_SERVER=dc01.empresa.local   AD_USE_SSL=true
  AD_USER=EMPRESA\\svc.auditoria  AD_PASSWORD=...   AD_BASE_DN=DC=empresa,DC=local
"""
from datetime import datetime, timezone

from ldap3 import BASE, SUBTREE, Connection, Server

from ..config import settings
from .base import KIND_CONTROLS, Collector, Observation

UAC_DISABLED = 0x2
PRIV_GROUPS = ("cn=domain admins,", "cn=admins. do domínio,", "cn=enterprise admins,", "cn=administrators,",
               "cn=administradores,")
FILETIME_EPOCH = 116444736000000000


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _filetime_days(value) -> int | None:
    value = _first(value)
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, datetime):
        ts = value
    else:
        ts = datetime.fromtimestamp((int(value) - FILETIME_EPOCH) / 10_000_000, tz=timezone.utc)
    return (datetime.now(timezone.utc) - ts).days


class ActiveDirectoryCollector(Collector):
    name = "active_directory"

    def collect(self) -> list[Observation]:
        dc = settings.ad_server or "AD"
        try:
            server = Server(settings.ad_server, use_ssl=settings.ad_use_ssl, connect_timeout=10)
            conn = Connection(server, user=settings.ad_user, password=settings.ad_password, auto_bind=True,
                              receive_timeout=30)
        except Exception as exc:  # fonte indisponível -> 'impossível avaliar'
            return [Observation(self.name, "Active Directory (LDAP)", "identidades", dc, "servidor", 5,
                                {"erro": f"Falha de conexão LDAP: {exc}"}, KIND_CONTROLS["identidades"], False)]

        accounts = {}
        entries = conn.extend.standard.paged_search(
            settings.ad_base_dn, "(&(objectCategory=person)(objectClass=user))", SUBTREE,
            attributes=["sAMAccountName", "userAccountControl", "lastLogonTimestamp", "memberOf", "employeeID"],
            paged_size=500, generator=True,
        )
        for e in entries:
            if e.get("type") != "searchResEntry":
                continue
            a = e["attributes"]
            username = str(_first(a.get("sAMAccountName")) or "").lower()
            if not username:
                continue
            uac = int(_first(a.get("userAccountControl")) or 0)
            groups = [str(g).lower() for g in (a.get("memberOf") or [])]
            accounts[username] = {
                "enabled": not (uac & UAC_DISABLED),
                "last_logon_days": _filetime_days(a.get("lastLogonTimestamp")),
                "privileged": any(g.startswith(PRIV_GROUPS) for g in groups),
                "mfa": None,  # o AD não informa MFA; integrar com o IdP (ex.: Entra ID) se houver
                "service": username.startswith("svc"),
                "employee_id": _first(a.get("employeeID")),
            }

        policy = {}
        conn.search(settings.ad_base_dn, "(objectClass=*)", BASE,
                    attributes=["minPwdLength", "lockoutThreshold", "pwdProperties"])
        if conn.entries:
            raw = conn.entries[0].entry_attributes_as_dict
            policy = {
                "min_length": int(_first(raw.get("minPwdLength")) or 0),
                "complexity": bool(int(_first(raw.get("pwdProperties")) or 0) & 1),
                "lockout_threshold": int(_first(raw.get("lockoutThreshold")) or 0),
            }
        conn.unbind()

        result = [Observation(self.name, "Active Directory (LDAP)", "identidades", dc, "servidor", 5,
                              {"accounts": accounts, "hr": {}}, KIND_CONTROLS["identidades"])]
        if policy:
            result.append(Observation(self.name, "Active Directory (Default Domain Policy)", "politica_senha", dc,
                                      "servidor", 5, policy, KIND_CONTROLS["politica_senha"]))
        return result
