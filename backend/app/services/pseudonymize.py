"""Pseudonimização antes de enviar dados à IA externa (minimização de dados — LGPD / NIST AI 600-1).

Nomes de usuários, hosts, e-mails e IPs são trocados por marcadores (USUARIO_01, HOST_02...)
de forma CONSISTENTE no prompt inteiro (evidência + trechos de política), e a resposta da IA
é revertida localmente. O provedor de IA nunca vê os identificadores reais.
"""
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
TOKEN_RE = re.compile(r"\b(USUARIO|HOST|IP|EMAIL)_\d{2,}\b")


class Pseudonymizer:
    def __init__(self, entities: dict[str, str] | None = None):
        """entities: {valor_real: tipo}, tipo em USUARIO|HOST."""
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        for value, kind in (entities or {}).items():
            if value and len(value) >= 3:
                self._token(value, kind)

    def _token(self, value: str, kind: str) -> str:
        key = value.lower()
        if key not in self.forward:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            tok = f"{kind}_{self.counters[kind]:02d}"
            self.forward[key] = tok
            self.reverse[tok] = value
        return self.forward[key]

    def apply(self, text: str) -> str:
        if not text:
            return text
        text = EMAIL_RE.sub(lambda m: self._token(m.group(0), "EMAIL"), text)
        text = IP_RE.sub(lambda m: self._token(m.group(0), "IP"), text)
        for real in sorted(self.forward, key=len, reverse=True):
            if self.forward[real].startswith(("EMAIL_", "IP_")):
                continue
            pattern = re.compile(r"(?<![\w.-])" + re.escape(real) + r"(?![\w-])", re.IGNORECASE)
            text = pattern.sub(self.forward[real], text)
        return text

    def revert(self, text: str) -> str:
        if not text:
            return text
        return TOKEN_RE.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)
