"""Provedores de IA plugáveis (todos gratuitos):

  * gemini -> Google Gemini API (plano gratuito). ATENÇÃO: no plano gratuito o Google pode usar
              o conteúdo enviado para melhorar seus produtos — por isso a pseudonimização é ligada
              por padrão e recomenda-se usar apenas dados de laboratório.
  * ollama -> modelo local (Llama, Qwen, Gemma...) rodando na sua máquina. Nada sai da rede.
  * none   -> sem IA: regras determinísticas + busca textual nas políticas.
"""
import json
import threading
import time
from functools import lru_cache

import httpx

from ..config import settings
from ..models import EMBED_DIM


class AIError(Exception):
    pass


class _RateLimiter:
    """Respeita o limite de requisições por minuto do plano gratuito."""

    def __init__(self, interval: float):
        self.interval = interval
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            delta = time.monotonic() - self.last
            if delta < self.interval:
                time.sleep(self.interval - delta)
            self.last = time.monotonic()


def _parse_json(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        return json.loads(text[start:end])
    except ValueError as exc:
        raise AIError(f"A IA não retornou JSON válido: {text[:200]}") from exc


class BaseProvider:
    name = "none"
    enabled = False
    model = ""
    embedding_model = ""

    @property
    def embedding_id(self) -> str:
        return f"{self.name}:{self.embedding_model}:{EMBED_DIM}"

    def info(self) -> dict:
        return {"provider": self.name, "enabled": self.enabled, "model": self.model,
                "embedding_model": self.embedding_model, "pseudonymize": settings.ai_pseudonymize}

    def generate_json(self, system: str, prompt: str, schema: dict) -> dict:
        raise AIError("IA desabilitada (AI_PROVIDER=none)")

    def embed(self, texts: list[str], task: str) -> list[list[float]]:
        raise AIError("IA desabilitada (AI_PROVIDER=none)")


class GeminiProvider(BaseProvider):
    name = "gemini"
    BASE = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self):
        self.enabled = bool(settings.gemini_api_key)
        self.model = settings.gemini_model
        self.embedding_model = settings.gemini_embedding_model
        self.limiter = _RateLimiter(settings.ai_min_interval_seconds)

    def _post(self, path: str, payload: dict) -> dict:
        if not self.enabled:
            raise AIError("GEMINI_API_KEY não configurada")
        self.limiter.wait()
        try:
            r = httpx.post(f"{self.BASE}/{path}", json=payload, timeout=90,
                           headers={"x-goog-api-key": settings.gemini_api_key})
        except httpx.HTTPError as exc:
            raise AIError(f"Falha de comunicação com o Gemini: {exc}") from exc
        if r.status_code == 429:
            raise AIError("Limite do plano gratuito do Gemini atingido (HTTP 429). Será tentado novamente depois.")
        if r.status_code >= 400:
            raise AIError(f"Gemini retornou HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def generate_json(self, system, prompt, schema):
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json",
                                 "responseSchema": schema},
        }
        data = self._post(f"models/{self.model}:generateContent", payload)
        try:
            parts = data["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError) as exc:
            raise AIError(f"Resposta inesperada do Gemini: {str(data)[:300]}") from exc
        return _parse_json("".join(p.get("text", "") for p in parts if not p.get("thought")))

    def embed(self, texts, task):
        vectors = []
        for i in range(0, len(texts), 50):
            batch = texts[i:i + 50]
            payload = {"requests": [{
                "model": f"models/{self.embedding_model}",
                "content": {"parts": [{"text": t}]},
                "taskType": task,
                "outputDimensionality": EMBED_DIM,
            } for t in batch]}
            data = self._post(f"models/{self.embedding_model}:batchEmbedContents", payload)
            vectors.extend(e["values"] for e in data["embeddings"])
        return vectors


def _lower_schema(schema):
    """Converte o schema estilo Gemini (tipos em MAIÚSCULAS) para JSON Schema padrão (Ollama)."""
    if isinstance(schema, dict):
        out = {}
        for k, v in schema.items():
            if k == "propertyOrdering":
                continue
            out[k] = v.lower() if k == "type" and isinstance(v, str) else _lower_schema(v)
        return out
    if isinstance(schema, list):
        return [_lower_schema(x) for x in schema]
    return schema


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self):
        self.enabled = True
        self.model = settings.ollama_model
        self.embedding_model = settings.ollama_embedding_model

    def _post(self, path, payload):
        try:
            r = httpx.post(f"{settings.ollama_url}{path}", json=payload, timeout=300)
        except httpx.HTTPError as exc:
            raise AIError(f"Falha de comunicação com o Ollama: {exc}") from exc
        if r.status_code >= 400:
            raise AIError(f"Ollama retornou HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def generate_json(self, system, prompt, schema):
        data = self._post("/api/chat", {
            "model": self.model, "stream": False, "format": _lower_schema(schema),
            "options": {"temperature": 0.1},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        })
        return _parse_json(data.get("message", {}).get("content", ""))

    def embed(self, texts, task):
        prefix = "search_query: " if task == "RETRIEVAL_QUERY" else "search_document: "
        data = self._post("/api/embed", {"model": self.embedding_model, "input": [prefix + t for t in texts]})
        vectors = data.get("embeddings", [])
        if vectors and len(vectors[0]) != EMBED_DIM:
            raise AIError(f"O modelo de embedding gera {len(vectors[0])} dimensões; o banco espera {EMBED_DIM}. "
                          "Use nomic-embed-text.")
        return vectors


@lru_cache
def get_provider() -> BaseProvider:
    name = settings.ai_provider.lower().strip()
    if name == "gemini":
        return GeminiProvider()
    if name == "ollama":
        return OllamaProvider()
    return BaseProvider()
