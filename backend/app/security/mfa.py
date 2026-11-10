"""MFA via TOTP (RFC 6238) — compatível com Google Authenticator, Microsoft Authenticator, Aegis etc."""
import hmac
import io
import time

import pyotp
import qrcode
import qrcode.image.svg

ISSUER_NAME = "Auditoria Continua"


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER_NAME)


def qr_svg(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def verify_totp(secret: str, code: str, last_counter: int) -> int | None:
    """Valida o código aceitando ±1 janela de 30 s e impede reutilização (anti-replay).
    Retorna o contador usado (a ser salvo) ou None se inválido."""
    code = (code or "").strip()
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    now_counter = int(time.time()) // 30
    for counter in (now_counter - 1, now_counter, now_counter + 1):
        if counter <= last_counter:
            continue
        if hmac.compare_digest(totp.at(counter * 30), code):
            return counter
    return None
