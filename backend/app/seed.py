"""Carga inicial: 93 controles, parâmetros, usuários, laboratório e políticas de exemplo."""
import logging
from datetime import date
from pathlib import Path

from sqlalchemy import func, select

from .ai.rag import ingest_document, parse_front_matter
from .collectors.simulator import get_state
from .config import settings
from .data.controls import AUTOMATION, CONTROLS, FREQUENCY, THEMES
from .db import SessionLocal
from .models import Control, PolicyDocument, User
from .security.passwords import hash_password
from .services.audit import append_audit
from .services.params import seed_params

log = logging.getLogger(__name__)
SAMPLES = Path(__file__).parent / "data" / "politicas_exemplo"


def _seed_controls(db) -> None:
    existing = {c.id: c for c in db.scalars(select(Control))}
    for i, (cid, title, auto) in enumerate(CONTROLS):
        automation = AUTOMATION[auto]
        c = existing.get(cid) or Control(id=cid)
        c.sort_order, c.theme, c.title = i, THEMES[cid.split(".")[1]], title
        c.automation, c.frequency = automation, FREQUENCY[automation]
        db.add(c)


def _seed_users(db) -> None:
    if db.scalar(select(func.count()).select_from(User)):
        return
    db.add(User(username=settings.admin_username.lower(), full_name="Administrador da Plataforma",
                password_hash=hash_password(settings.admin_password), role="admin"))
    if settings.seed_demo_users and settings.demo_password:
        for username, name, role in [("auditor", "Auditor(a) Responsável", "auditor"),
                                     ("gestor", "Gestor(a) de TI", "gestor"),
                                     ("leitura", "Consulta / Diretoria", "leitura")]:
            db.add(User(username=username, full_name=name, password_hash=hash_password(settings.demo_password),
                        role=role))
    db.flush()
    append_audit(db, "carga_inicial_usuarios", None, details={"demo": settings.seed_demo_users})


def _seed_policies(db) -> None:
    if db.scalar(select(func.count()).select_from(PolicyDocument)):
        return
    for path in sorted(SAMPLES.glob("*.md")):
        meta, body = parse_front_matter(path.read_text(encoding="utf-8"))
        approved = meta.get("aprovada_em")
        ingest_document(
            db, title=meta.get("titulo", path.stem), code=meta.get("codigo", path.stem),
            version=meta.get("versao", "1.0"), approved_at=date.fromisoformat(approved) if approved else None,
            filename=path.name, text=body,
            explicit_controls=[c.strip() for c in meta.get("controles", "").split(",") if c.strip()],
        )
    append_audit(db, "carga_politicas_exemplo", None, details={"arquivos": len(list(SAMPLES.glob('*.md')))})


def seed_all() -> None:
    with SessionLocal() as db:
        _seed_controls(db)
        seed_params(db)
        db.flush()
        _seed_users(db)
        get_state(db)  # cria o estado do laboratório
        db.commit()
        try:
            _seed_policies(db)
            db.commit()
        except Exception:
            db.rollback()
            log.exception("Falha ao carregar políticas de exemplo")
