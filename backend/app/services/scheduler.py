from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from ..config import settings
from .pipeline import run_cycle

_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> None:
    global _scheduler
    if settings.collect_interval_minutes <= 0:
        return
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(run_cycle, "interval", minutes=settings.collect_interval_minutes,
                       kwargs={"trigger": "agendado"}, id="ciclo_auditoria", max_instances=1, coalesce=True,
                       next_run_time=datetime.now(timezone.utc) + timedelta(seconds=20))
    _scheduler.start()


def stop_scheduler() -> None:
    if _scheduler:
        _scheduler.shutdown(wait=False)
