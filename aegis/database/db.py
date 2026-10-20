from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, delete, event as sql_event, select
from sqlalchemy.orm import Session, sessionmaker

from aegis.config import DB_PATH, DEFAULTS, default_fim_paths, ensure_runtime_dirs
from aegis.database.models import Base, Event, Setting

log = logging.getLogger(__name__)


class Database:
    def __init__(self, path: Path | str = DB_PATH):
        ensure_runtime_dirs()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{self.path.as_posix()}",
            connect_args={"check_same_thread": False, "timeout": 15},
            pool_pre_ping=True,
        )
        sql_event.listen(self.engine, "connect", self._configure_sqlite)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    @staticmethod
    def _configure_sqlite(connection, _record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=15000")
        cursor.close()

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)
        defaults = {
            "process_monitor": DEFAULTS.process_monitor,
            "network_monitor": DEFAULTS.network_monitor,
            "file_monitor": DEFAULTS.file_monitor,
            "windows_events": DEFAULTS.windows_events,
            "process_interval": DEFAULTS.process_interval,
            "network_interval": DEFAULTS.network_interval,
            "device_interval": DEFAULTS.device_interval,
            "event_retention_days": DEFAULTS.event_retention_days,
            "max_hash_mb": DEFAULTS.max_hash_mb,
            "fim_paths": default_fim_paths(),
        }
        with self.session() as session:
            for key, value in defaults.items():
                if session.get(Setting, key) is None:
                    session.add(Setting(key=key, value=json.dumps(value)))

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            log.exception("Database transaction failed")
            raise
        finally:
            session.close()

    def settings(self) -> dict:
        with self.session() as session:
            return {item.key: json.loads(item.value) for item in session.scalars(select(Setting))}

    def update_settings(self, values: dict) -> dict:
        allowed = set(self.settings())
        with self.session() as session:
            for key, value in values.items():
                if key in allowed:
                    session.merge(Setting(key=key, value=json.dumps(value)))
        return self.settings()

    def cleanup_events(self, retention_days: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))
        with self.session() as session:
            result = session.execute(delete(Event).where(Event.timestamp < cutoff, Event.severity.in_(["INFO", "LOW"])))
            return int(result.rowcount or 0)
