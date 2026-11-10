"""Trilha de auditoria imutável (encadeada por hash, no estilo de um 'blockchain' leve).

Cada entrada guarda hash = SHA256(hash_anterior + SHA256(conteúdo canônico)).
Qualquer alteração ou exclusão de uma linha quebra a cadeia e é detectada em verify_audit_chain.
"""
import json

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import AuditLog
from ..security.crypto import canonical, sha256_hex

GENESIS = "0" * 64
AUDIT_LOCK = 7002


def append_audit(db: Session, action: str, user=None, target: str = "", details: dict | None = None,
                 ip: str | None = None) -> AuditLog:
    # trava transacional: garante a ordem da cadeia mesmo com requisições concorrentes
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": AUDIT_LOCK})
    last = db.scalar(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1))
    seq = (last.seq + 1) if last else 1
    prev = last.hash if last else GENESIS
    now = utcnow()
    norm_details = json.loads(canonical(details or {}))
    content = {
        "seq": seq,
        "ts": now.isoformat(),
        "user_id": user.id if user else None,
        "username": user.username if user else "sistema",
        "action": action,
        "target": target or "",
        "details": norm_details,
        "ip": ip,
    }
    entry = AuditLog(
        seq=seq, ts=now, ts_iso=content["ts"], user_id=content["user_id"], username=content["username"],
        action=action, target=content["target"], details=norm_details, ip=ip, prev_hash=prev,
        hash=sha256_hex(prev + sha256_hex(canonical(content))),
    )
    db.add(entry)
    db.flush()
    return entry


def verify_audit_chain(db: Session) -> dict:
    prev = GENESIS
    expected_seq = 1
    count = 0
    for entry in db.scalars(select(AuditLog).order_by(AuditLog.seq)).yield_per(500):
        content = {
            "seq": entry.seq, "ts": entry.ts_iso, "user_id": entry.user_id, "username": entry.username,
            "action": entry.action, "target": entry.target, "details": entry.details, "ip": entry.ip,
        }
        if entry.seq != expected_seq:
            return {"ok": False, "count": count, "broken_at": entry.seq,
                    "reason": f"Sequência interrompida: esperado {expected_seq} (registro removido?)"}
        if entry.prev_hash != prev:
            return {"ok": False, "count": count, "broken_at": entry.seq, "reason": "Hash anterior não confere"}
        if sha256_hex(prev + sha256_hex(canonical(content))) != entry.hash:
            return {"ok": False, "count": count, "broken_at": entry.seq, "reason": "Conteúdo alterado"}
        prev = entry.hash
        expected_seq += 1
        count += 1
    return {"ok": True, "count": count, "last_hash": prev}
