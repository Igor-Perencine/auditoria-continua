"""Coletor interno: avalia a base documental (políticas cadastradas na plataforma)."""
from datetime import date

from sqlalchemy import select

from ..models import PolicyDocument
from .base import KIND_CONTROLS, Collector, Observation


class PoliciesCollector(Collector):
    name = "politicas"

    def collect(self) -> list[Observation]:
        today = date.today()
        docs = []
        for d in self.db.scalars(select(PolicyDocument).order_by(PolicyDocument.code)):
            docs.append({
                "code": d.code, "title": d.title, "version": d.version,
                "approved_at": d.approved_at.isoformat() if d.approved_at else None,
                "age_days": (today - d.approved_at).days if d.approved_at else None,
            })
        return [Observation(
            collector=self.name, source="Repositório de políticas da plataforma", kind="documentos",
            asset="SGSI", asset_type="processo", criticality=4, control_ids=KIND_CONTROLS["documentos"],
            data={"documents": docs},
        )]
