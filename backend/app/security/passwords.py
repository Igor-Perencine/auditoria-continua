"""Hash de senhas com Argon2id (vencedor da Password Hashing Competition)."""
import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()  # parâmetros padrão do argon2-cffi (Argon2id, RFC 9106)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _ph.check_needs_rehash(password_hash)


def password_problems(password: str) -> list[str]:
    """Política mínima de senha da própria plataforma."""
    problems = []
    if len(password) < 12:
        problems.append("mínimo de 12 caracteres")
    classes = sum(
        bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    if classes < 3:
        problems.append("use ao menos 3 tipos: minúsculas, maiúsculas, números, símbolos")
    return problems
