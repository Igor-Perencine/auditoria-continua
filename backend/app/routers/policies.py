"""Base de políticas internas (fonte autorizada do RAG)."""
from datetime import date

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai.rag import embed_missing, extract_text, ingest_document, parse_front_matter, search
from ..db import get_db
from ..models import PolicyChunk, PolicyDocument, User
from ..security.deps import client_ip, get_current_user, require_roles
from ..services.audit import append_audit

router = APIRouter(prefix="/policies", tags=["políticas"])
MAX_BYTES = 10 * 1024 * 1024


def _out(d: PolicyDocument, db: Session) -> dict:
    controls = sorted({c for ch in db.scalars(select(PolicyChunk.control_ids).where(PolicyChunk.document_id == d.id))
                       for c in (ch or [])})
    embedded = db.scalar(select(PolicyChunk.id).where(PolicyChunk.document_id == d.id,
                                                      PolicyChunk.embedding_model.is_not(None)).limit(1))
    return {"id": d.id, "code": d.code, "title": d.title, "version": d.version, "approved_at": d.approved_at,
            "age_days": (date.today() - d.approved_at).days if d.approved_at else None, "filename": d.filename,
            "sha256": d.sha256, "uploaded_at": d.uploaded_at, "n_chunks": d.n_chunks, "controls": controls,
            "embedded": embedded is not None}


@router.get("")
def list_policies(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return [_out(d, db) for d in db.scalars(select(PolicyDocument).order_by(PolicyDocument.code))]


@router.post("")
def upload_policy(request: Request, file: UploadFile = File(...), title: str = Form(""), code: str = Form(""),
                  version: str = Form("1.0"), approved_at: str = Form(""), controls: str = Form(""),
                  db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "auditor"))):
    data = file.file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "Arquivo maior que 10 MB")
    try:
        text = extract_text(file.filename or "", data)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(400, f"Não foi possível ler o arquivo: {exc}")
    meta, body = parse_front_matter(text)
    if len(body.strip()) < 50:
        raise HTTPException(400, "Documento sem texto extraível (PDF escaneado? use OCR antes).")
    approved_raw = approved_at or meta.get("aprovada_em", "")
    try:
        approved = date.fromisoformat(approved_raw) if approved_raw else None
    except ValueError:
        raise HTTPException(400, "Data de aprovação inválida (use AAAA-MM-DD)")
    explicit = []
    for c in (controls or meta.get("controles", "")).split(","):
        c = c.strip().upper()
        if c:
            explicit.append(c if c.startswith("A.") else f"A.{c}")
    doc = ingest_document(db, title=title or meta.get("titulo") or (file.filename or "Documento"),
                          code=(code or meta.get("codigo") or "SEM-CODIGO")[:32],
                          version=(version or meta.get("versao") or "1.0")[:16], approved_at=approved,
                          filename=file.filename or "arquivo", text=body, explicit_controls=explicit, user=user)
    append_audit(db, "politica_carregada", user, target=doc.code, details={
        "titulo": doc.title, "versao": doc.version, "sha256": doc.sha256, "trechos": doc.n_chunks},
        ip=client_ip(request))
    db.commit()
    return _out(doc, db)


@router.delete("/{doc_id}")
def delete_policy(doc_id: int, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_roles("admin"))):
    d = db.get(PolicyDocument, doc_id)
    if not d:
        raise HTTPException(404, "Documento não encontrado")
    for ch in db.scalars(select(PolicyChunk).where(PolicyChunk.document_id == d.id)):
        db.delete(ch)
    append_audit(db, "politica_removida", user, target=d.code, details={"sha256": d.sha256}, ip=client_ip(request))
    db.delete(d)
    db.commit()
    return {"ok": True}


@router.post("/reindex")
def reindex(request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles("admin"))):
    n = embed_missing(db)
    append_audit(db, "politicas_reindexadas", user, details={"trechos": n}, ip=client_ip(request))
    db.commit()
    return {"embedded": n}


@router.get("/search")
def search_policies(q: str, control_id: str | None = None, db: Session = Depends(get_db),
                    _=Depends(get_current_user)):
    return [{"chunk_id": c.id, "code": c.document.code, "document": c.document.title, "version": c.document.version,
             "controls": c.control_ids, "text": c.text} for c in search(db, q[:500], control_id or None, k=6)]
