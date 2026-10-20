from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from aegis.database.models import Alert, Incident
from aegis.detection.scoring import highest_severity, system_risk


class IncidentCorrelator:
    def __init__(self, database, window_minutes: int = 10):
        self.database = database
        self.window_minutes = window_minutes

    def correlate(self, alert: Alert) -> Incident | None:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes)
        with self.database.session() as session:
            attached_alert = session.get(Alert, alert.id)
            if attached_alert is None:
                return None
            incoming = json.loads(attached_alert.evidence or "{}")
            candidates = session.scalars(
                select(Alert).where(Alert.timestamp >= cutoff, Alert.id != alert.id, Alert.status != "FALSE_POSITIVE")
            ).all()
            candidates = [item for item in candidates if item.simulated == attached_alert.simulated]
            related = [item for item in candidates if self._related(incoming, json.loads(item.evidence or "{}"), alert, item)]
            combined = sorted(
                {item.id: item for item in [*related, attached_alert]}.values(),
                key=lambda item: item.timestamp.timestamp(),
            )
            if len(combined) < 3:
                return None
            existing = next((inc for item in combined for inc in item.incidents if inc.status not in {"RESOLVED", "FALSE_POSITIVE"}), None)
            severity = highest_severity(item.severity for item in combined)
            if alert.simulated and len(combined) >= 4:
                severity = "CRITICAL"
            score = system_risk(item.severity for item in combined)
            entities = self._entities(combined)
            if existing:
                for item in combined:
                    if item not in existing.alerts:
                        existing.alerts.append(item)
                existing.updated_at = datetime.now(timezone.utc)
                existing.severity = severity
                existing.risk_score = score
                existing.entities = json.dumps(entities)
                return existing
            title = "Possible Execution and Persistence Chain" if alert.simulated else "Correlated Security Activity"
            incident = Incident(
                title=title,
                severity=severity,
                risk_score=score,
                summary=f"{len(combined)} related alerts occurred within {self.window_minutes} minutes.",
                entities=json.dumps(entities),
            )
            incident.alerts.extend(combined)
            session.add(incident)
            session.flush()
            return incident

    @staticmethod
    def _related(left: dict, right: dict, new_alert: Alert, old_alert: Alert) -> bool:
        keys = ("pid", "ppid", "user", "path", "file", "remote_ip", "host", "correlation_id")
        return any(left.get(key) and left.get(key) == right.get(key) for key in keys)

    @staticmethod
    def _entities(alerts: list[Alert]) -> dict:
        result: dict[str, list] = {}
        for alert in alerts:
            for key, value in json.loads(alert.evidence or "{}").items():
                if key in {"user", "process", "pid", "ppid", "file", "path", "remote_ip", "host"} and value is not None:
                    result.setdefault(key, [])
                    if value not in result[key]:
                        result[key].append(value)
        return result
