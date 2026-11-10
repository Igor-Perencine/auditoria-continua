import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import text

from .db import engine, init_db
from .routers import admin, auth, controls, evidence, exceptions, findings, lab, metrics, policies, runs, users
from .seed import seed_all
from .services.scheduler import start_scheduler, stop_scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("auditoria")


def wait_for_db(retries: int = 30) -> None:
    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception:
            log.info("Aguardando o banco de dados (%s/%s)...", attempt + 1, retries)
            time.sleep(2)
    raise RuntimeError("Banco de dados indisponível")


@asynccontextmanager
async def lifespan(app: FastAPI):
    wait_for_db()
    init_db()
    seed_all()
    start_scheduler()
    log.info("Plataforma de auditoria contínua iniciada")
    yield
    stop_scheduler()


app = FastAPI(
    title="Plataforma de Auditoria Contínua — ISO/IEC 27001:2022",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


for module in (auth, users, controls, findings, exceptions, policies, evidence, runs, lab, metrics, admin):
    app.include_router(module.router, prefix="/api")


@app.get("/api/health", tags=["saúde"])
def health():
    return {"status": "ok"}
