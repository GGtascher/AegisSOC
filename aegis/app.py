from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from aegis.api.routes import build_router
from aegis.api.websocket import build_websocket_router
from aegis.config import DB_PATH, FRONTEND_DIST, ensure_runtime_dirs
from aegis.database.db import Database
from aegis.detection.baseline import BaselineStore
from aegis.detection.correlation import IncidentCorrelator
from aegis.detection.engine import DetectionEngine
from aegis.detection.rules import RuleStore
from aegis.logging_config import configure_logging
from aegis.runtime import Runtime

log = logging.getLogger(__name__)


def create_app(demo_mode: bool = False, database_path=None) -> FastAPI:
    ensure_runtime_dirs()
    configure_logging()
    database = Database(database_path or DB_PATH)
    database.initialize()
    settings = database.settings()
    database.cleanup_events(settings.get("event_retention_days", 7))
    rules = RuleStore(database)
    rules.load()
    baselines = BaselineStore(database)
    correlator = IncidentCorrelator(database)
    runtime_ref: dict[str, Runtime] = {}
    engine = DetectionEngine(database, rules, correlator, lambda kind, payload: runtime_ref["runtime"].publish(kind, payload) if "runtime" in runtime_ref else None)
    runtime = Runtime(database, engine, baselines, demo_mode)
    runtime_ref["runtime"] = runtime

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        log.info("AegisSOC starting in %s mode", "demo" if demo_mode else "live")
        runtime.start(asyncio.get_running_loop())
        yield
        runtime.stop()
        log.info("AegisSOC stopped")

    app = FastAPI(title="AegisSOC", version="1.0.0", lifespan=lifespan)
    app.state.database = database
    app.state.runtime = runtime
    app.state.engine = engine
    app.state.rules = rules
    app.include_router(build_router(database, runtime, rules, engine))
    app.include_router(build_websocket_router(runtime))

    if FRONTEND_DIST.exists():
        assets = FRONTEND_DIST / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{full_path:path}")
        async def frontend(full_path: str):
            requested = FRONTEND_DIST / full_path
            if full_path and requested.is_file() and requested.resolve().is_relative_to(FRONTEND_DIST.resolve()):
                return FileResponse(requested)
            return FileResponse(FRONTEND_DIST / "index.html")
    else:
        @app.get("/")
        async def no_frontend():
            return JSONResponse({"status": "AegisSOC API is running", "frontend": "Build the frontend with npm run build"})
    return app
