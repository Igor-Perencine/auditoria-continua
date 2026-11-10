"""Modelo de dados da plataforma.

Rastreabilidade (seção 2.6 do TCC): critério (Control/Rule) -> evidência (Evidence, cifrada e
encadeada por hash) -> resultado (Finding) -> decisão humana (Decision) -> ação/encerramento.
"""
from datetime import date, datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow

EMBED_DIM = 768


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # admin | auditor | gestor | leitura
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)  # cifrado (AES-GCM)
    mfa_last_counter: Mapped[int] = mapped_column(BigInteger, default=0)  # anti-replay TOTP
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)  # revogação de sessões
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Control(Base):
    """Os 93 controles do Anexo A da ISO/IEC 27001:2022."""

    __tablename__ = "controls"
    id: Mapped[str] = mapped_column(String(8), primary_key=True)  # ex.: A.8.13
    sort_order: Mapped[int] = mapped_column(Integer)
    theme: Mapped[str] = mapped_column(String(32))  # Organizacional | Pessoas | Físico | Tecnológico
    title: Mapped[str] = mapped_column(String(255))
    automation: Mapped[str] = mapped_column(String(16))  # automatizavel | parcial | documental | manual
    frequency: Mapped[str] = mapped_column(String(64))


class ControlAssessment(Base):
    __tablename__ = "control_assessments"
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.id"), primary_key=True)
    status: Mapped[str] = mapped_column(String(24))
    detail: Mapped[str] = mapped_column(Text, default="")
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(32), default="servidor")
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1..5
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", lazy="joined")


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    trigger: Mapped[str] = mapped_column(String(32))
    triggered_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="executando")
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_new: Mapped[int] = mapped_column(Integer, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSONB, default=list)


class Evidence(Base):
    """Evidência coletada. Conteúdo cifrado com envelope encryption (AES-256-GCM) e
    encadeado por hash SHA-256 (cada registro inclui o hash do anterior)."""

    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("collection_runs.id"), nullable=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    control_ids: Mapped[list[str]] = mapped_column(ARRAY(String(8)), default=list)
    kind: Mapped[str] = mapped_column(String(32))
    collector: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(128))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))

    asset = relationship("Asset", lazy="joined")


class Finding(Base):
    """Achado (não conformidade ou impossibilidade de avaliação)."""

    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_version: Mapped[str] = mapped_column(String(64))
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"))
    subject: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(24))  # nao_conforme | impossivel_avaliar
    criterion: Mapped[str] = mapped_column(Text)
    condition: Mapped[str] = mapped_column(Text)
    details_enc: Mapped[str] = mapped_column(Text, default="")  # trecho da evidência, cifrado
    base_severity: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    is_open: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)

    # Revisão humana
    review_state: Mapped[str] = mapped_column(String(24), default="pendente")  # pendente|confirmado|falso_positivo
    final_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    final_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, default=True)
    review_reasons: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)

    # Pré-classificação da IA (RAG)
    ai_status_suggested: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ai_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_citations: Mapped[list] = mapped_column(JSONB, default=list)
    ai_citations_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ai_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ai_prompt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ai_classified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ai_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_attempts: Mapped[int] = mapped_column(Integer, default=0)

    asset = relationship("Asset", lazy="joined")
    control = relationship("Control", lazy="joined")


class Decision(Base):
    __tablename__ = "decisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(16))  # aprovar | rejeitar | alterar
    note: Mapped[str] = mapped_column(Text)
    rule_status: Mapped[str] = mapped_column(String(24))
    ai_status_suggested: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ai_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    final_status: Mapped[str] = mapped_column(String(24))
    final_severity: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user = relationship("User", lazy="joined")


class RiskException(Base):
    """Exceção formal (risco aceito) — evita que o auditor reavalie falsos positivos."""

    __tablename__ = "risk_exceptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32))
    control_id: Mapped[str] = mapped_column(ForeignKey("controls.id"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(128), nullable=True)
    justification: Mapped[str] = mapped_column(Text)
    reference: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="solicitada")  # solicitada|aprovada|revogada
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    expires_at: Mapped[date] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", lazy="joined")
    requester = relationship("User", foreign_keys=[requested_by], lazy="joined")
    approver = relationship("User", foreign_keys=[approved_by], lazy="joined")


class PolicyDocument(Base):
    __tablename__ = "policy_documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(16), default="1.0")
    approved_at: Mapped[date | None] = mapped_column(Date, nullable=True)
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    n_chunks: Mapped[int] = mapped_column(Integer, default=0)


class PolicyChunk(Base):
    __tablename__ = "policy_chunks"
    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("policy_documents.id", ondelete="CASCADE"), index=True)
    chunk_index: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    control_ids: Mapped[list[str]] = mapped_column(ARRAY(String(8)), default=list)
    embedding = mapped_column(Vector(EMBED_DIM), nullable=True)
    embedding_model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    document = relationship("PolicyDocument", lazy="joined")


class Parameter(Base):
    """Parâmetros de política usados pelas regras (o 'estado esperado')."""

    __tablename__ = "parameters"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class AuditLog(Base):
    """Trilha de auditoria da própria plataforma, encadeada por hash."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ts_iso: Mapped[str] = mapped_column(String(40))
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class LabState(Base):
    """Estado do ambiente de laboratório simulado (para os cenários controlados)."""

    __tablename__ = "lab_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    state: Mapped[dict] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScenarioRun(Base):
    """Injeção de falha controlada — base do indicador 'tempo de detecção'."""

    __tablename__ = "scenario_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_key: Mapped[str] = mapped_column(String(64), index=True)
    injected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    injected_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reverted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
