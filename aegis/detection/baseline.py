from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select

from aegis.database.models import Baseline


class BaselineStore:
    def __init__(self, database):
        self.database = database

    def get(self, kind: str, key: str, default=None):
        full_key = f"{kind}:{key}"
        with self.database.session() as session:
            item = session.get(Baseline, full_key)
            return json.loads(item.value) if item else default

    def put(self, kind: str, key: str, value) -> None:
        full_key = f"{kind}:{key}"
        now = datetime.now(timezone.utc)
        with self.database.session() as session:
            item = session.get(Baseline, full_key)
            if item:
                item.value = json.dumps(value)
                item.updated_at = now
            else:
                session.add(Baseline(key=full_key, kind=kind, value=json.dumps(value)))

    def keys(self, kind: str) -> set[str]:
        with self.database.session() as session:
            rows = session.scalars(select(Baseline).where(Baseline.kind == kind)).all()
            return {row.key.split(":", 1)[1] for row in rows}
