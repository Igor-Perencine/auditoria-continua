"""Armazenamento de evidências: cifradas (AES-256-GCM) e encadeadas por hash."""
import json
import uuid

from cryptography.exceptions import InvalidTag
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import Asset, Evidence
from ..security.crypto import canonical, decrypt_bytes, encrypt_bytes, sha256_hex

GENESIS = "0" * 64
EVIDENCE_LOCK = 7001


def _content(ev_id: str, seq: int, asset_name: str, kind: str, collector: str, source: str,
             control_ids: list[str], payload_sha: str) -> dict:
    return {
        "id": ev_id, "seq": seq, "asset": asset_name, "kind": kind, "collector": collector,
        "source": source, "control_ids": sorted(control_ids), "payload_sha256": payload_sha,
    }


def store_evidence(db: Session, obs, asset: Asset, run_id: int | None) -> Evidence:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": EVIDENCE_LOCK})
    last = db.scalar(select(Evidence).order_by(Evidence.seq.desc()).limit(1))
    seq = (last.seq + 1) if last else 1
    prev = last.hash if last else GENESIS
    ev_id = str(uuid.uuid4())
    now = utcnow()
    payload = {"collected_at": now.isoformat(), "reachable": obs.reachable, "data": obs.data}
    plaintext = canonical(payload).encode("utf-8")
    enc = encrypt_bytes(plaintext, aad=ev_id.encode())
    content = _content(ev_id, seq, asset.name, obs.kind, obs.collector, obs.source, obs.control_ids,
                       sha256_hex(plaintext))
    ev = Evidence(
        id=ev_id, seq=seq, run_id=run_id, asset_id=asset.id, control_ids=sorted(obs.control_ids),
        kind=obs.kind, collector=obs.collector, source=obs.source, collected_at=now,
        ciphertext=enc["ciphertext"], nonce=enc["nonce"], wrapped_dek=enc["wrapped_dek"],
        key_version=enc["key_version"], prev_hash=prev,
        hash=sha256_hex(prev + sha256_hex(canonical(content))),
    )
    db.add(ev)
    db.flush()
    return ev


def decrypt_evidence(ev: Evidence) -> dict:
    plaintext = decrypt_bytes(ev.ciphertext, ev.nonce, ev.wrapped_dek, aad=ev.id.encode())
    return json.loads(plaintext)


def verify_evidence_chain(db: Session) -> dict:
    prev = GENESIS
    expected_seq = 1
    count = 0
    for ev in db.scalars(select(Evidence).order_by(Evidence.seq)).yield_per(200):
        if ev.seq != expected_seq:
            return {"ok": False, "count": count, "broken_at": ev.seq,
                    "reason": f"Sequência interrompida: esperado {expected_seq} (evidência removida?)"}
        if ev.prev_hash != prev:
            return {"ok": False, "count": count, "broken_at": ev.seq, "reason": "Hash anterior não confere"}
        try:
            plaintext = decrypt_bytes(ev.ciphertext, ev.nonce, ev.wrapped_dek, aad=ev.id.encode())
        except InvalidTag:
            return {"ok": False, "count": count, "broken_at": ev.seq,
                    "reason": "Falha na autenticação AES-GCM (conteúdo cifrado adulterado)"}
        content = _content(ev.id, ev.seq, ev.asset.name, ev.kind, ev.collector, ev.source, ev.control_ids,
                           sha256_hex(plaintext))
        if sha256_hex(prev + sha256_hex(canonical(content))) != ev.hash:
            return {"ok": False, "count": count, "broken_at": ev.seq, "reason": "Metadados alterados"}
        prev = ev.hash
        expected_seq += 1
        count += 1
    return {"ok": True, "count": count, "last_hash": prev}
