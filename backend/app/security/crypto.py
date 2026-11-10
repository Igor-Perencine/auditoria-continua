"""Criptografia de dados sensíveis no banco.

Envelope encryption:
  * cada registro recebe uma chave de dados aleatória (DEK, AES-256-GCM);
  * a DEK é cifrada ("embrulhada") pela chave mestra (KEK), que fica FORA do banco
    (variável de ambiente MASTER_KEY; em produção, um cofre como HashiCorp Vault/KMS).
Quem obtiver apenas o dump do banco não consegue ler as evidências.
O AAD (dados associados) amarra o texto cifrado ao ID do registro, impedindo troca de
conteúdo cifrado entre linhas.
"""
import base64
import hashlib
import json
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import settings


@lru_cache
def _kek() -> bytes:
    key = base64.b64decode(settings.master_key)
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY deve conter exatamente 32 bytes codificados em base64")
    return key


def encrypt_bytes(plaintext: bytes, aad: bytes) -> dict:
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(_kek()).encrypt(wrap_nonce, dek, b"dek-wrap")
    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "wrapped_dek": wrap_nonce + wrapped,
        "key_version": settings.master_key_version,
    }


def decrypt_bytes(ciphertext: bytes, nonce: bytes, wrapped_dek: bytes, aad: bytes) -> bytes:
    dek = AESGCM(_kek()).decrypt(wrapped_dek[:12], wrapped_dek[12:], b"dek-wrap")
    return AESGCM(dek).decrypt(nonce, ciphertext, aad)


def encrypt_str(value: str, aad: str = "campo") -> str:
    """Cifra um campo de texto curto (ex.: segredo MFA). Formato: base64(nonce || ct)."""
    nonce = os.urandom(12)
    ct = AESGCM(_kek()).encrypt(nonce, value.encode("utf-8"), aad.encode())
    return base64.b64encode(nonce + ct).decode()


def decrypt_str(token: str, aad: str = "campo") -> str:
    raw = base64.b64decode(token)
    return AESGCM(_kek()).decrypt(raw[:12], raw[12:], aad.encode()).decode("utf-8")


def canonical(obj) -> str:
    """JSON canônico (chaves ordenadas) — base dos hashes de integridade."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
