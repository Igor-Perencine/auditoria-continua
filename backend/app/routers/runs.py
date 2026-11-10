import threading

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import CollectionRun, User
from ..security.deps import client_ip, get_current_user, require_roles
from ..services.audit import append_audit
from ..services.pipeline import is_running, run_cycle

router = APIRouter(prefix="/runs", tags=["execuções"])


@router.get("")
def list_runs(limit: int = 20, db: Session = Depends(get_db), _=Depends(get_current_user)):
    runs = db.scalars(select(CollectionRun).order_by(CollectionRun.id.desc()).limit(min(limit, 200)))
    return {"running": is_running(), "runs": [{
        "id": r.id, "trigger": r.trigger, "status": r.status, "started_at": r.started_at,
        "finished_at": r.finished_at, "evidence_count": r.evidence_count, "findings_new": r.findings_new,
        "findings_resolved": r.findings_resolved, "errors": r.errors} for r in runs]}


@router.post("")
def trigger_run(request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_roles("auditor", "admin"))):
    if is_running():
        return {"started": False, "message": "Já existe um ciclo em execução"}
    append_audit(db, "ciclo_solicitado", user, ip=client_ip(request))
    db.commit()
    threading.Thread(target=run_cycle, kwargs={"trigger": "manual", "user_id": user.id}, daemon=True).start()
    return {"started": True}
