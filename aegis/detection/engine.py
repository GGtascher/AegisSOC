from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from aegis.database.models import Alert, Event
from aegis.detection.scoring import alert_risk

log = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, database, rules, correlator, publish=None):
        self.database = database
        self.rules = rules
        self.correlator = correlator
        self.publish = publish

    def ingest(self, source: str, category: str, event_type: str, data: dict[str, Any], *, severity="INFO", simulated=False) -> Event:
        event = Event(
            source=source,
            category=category,
            event_type=event_type,
            host=socket.gethostname(),
            severity=severity,
            data=json.dumps(data, default=str),
            simulated=simulated,
        )
        with self.database.session() as session:
            session.add(event)
            session.flush()
        self._publish("event", self.event_dict(event))
        if not simulated:
            for match in self.detect(event):
                self.create_alert(**match)
        return event

    def detect(self, event: Event) -> list[dict]:
        data = json.loads(event.data)
        process_name = str(data.get("name", "")).lower()
        command = str(data.get("command_line", "")).lower()
        path = str(data.get("path", "")).lower()
        matches = []
        for rule in self.rules.rules.values():
            if not rule.enabled or rule.category not in {event.category, event.source}:
                continue
            if rule.event_type and rule.event_type != event.event_type:
                continue
            if rule.process_name and process_name != rule.process_name.lower():
                continue
            if rule.command_contains and not any(token.lower() in command for token in rule.command_contains):
                continue
            if rule.extensions and not any(path.endswith(ext.lower()) for ext in rule.extensions):
                continue
            matches.append({
                "severity": rule.severity,
                "category": rule.category,
                "title": rule.name,
                "description": rule.description,
                "source": event.source,
                "confidence": 82,
                "evidence": data,
                "recommendation": rule.recommendation,
                "mitre_technique": rule.mitre.get("technique"),
                "simulated": False,
            })
        if event.event_type == "process_start":
            parent = str(data.get("parent", "")).lower()
            if process_name in {"powershell.exe", "pwsh.exe", "cmd.exe"} and parent in {"winword.exe", "excel.exe", "powerpnt.exe"}:
                matches.append(self._behavior("HIGH", "Office Application Spawned a Shell", data, "T1059.001", 90))
            if process_name in {"powershell.exe", "pwsh.exe"} and len(command) > 1000:
                matches.append(self._behavior("MEDIUM", "Very Long PowerShell Command", data, "T1059.001", 76))
            if "\\appdata\\local\\temp\\" in path or "\\temp\\" in path:
                matches.append(self._behavior("MEDIUM", "Executable Started from a Temporary Directory", data, "T1204", 70))
        return matches

    @staticmethod
    def _behavior(severity: str, title: str, evidence: dict, mitre: str, confidence: int) -> dict:
        return {
            "severity": severity,
            "category": "endpoint",
            "title": title,
            "description": "Suspicious behavior was detected. This heuristic does not prove compromise.",
            "source": "endpoint",
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": "Validate the process tree, command line, file origin, and user context.",
            "mitre_technique": mitre,
            "simulated": False,
        }

    def create_alert(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        source: str,
        confidence: int = 70,
        evidence: dict | None = None,
        recommendation: str = "Review the related activity.",
        mitre_technique: str | None = None,
        simulated: bool = False,
    ) -> Alert:
        alert = Alert(
            severity=severity.upper(),
            category=category,
            title=title,
            description=description,
            source=source,
            risk_score=alert_risk(severity, confidence),
            confidence=confidence,
            evidence=json.dumps(evidence or {}, default=str),
            recommendation=recommendation,
            mitre_technique=mitre_technique,
            simulated=simulated,
        )
        with self.database.session() as session:
            session.add(alert)
            session.flush()
        incident = self.correlator.correlate(alert)
        payload = self.alert_dict(alert)
        if incident:
            payload["incident_id"] = incident.id
            self._publish("incident", {"id": incident.id, "title": incident.title, "severity": incident.severity})
        self._publish("alert", payload)
        return alert

    def update_alert(self, alert_id: int, status: str) -> Alert | None:
        if status not in {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}:
            raise ValueError("Invalid alert status")
        with self.database.session() as session:
            alert = session.get(Alert, alert_id)
            if alert:
                alert.status = status
            return alert

    def _publish(self, kind: str, payload: dict) -> None:
        if self.publish:
            self.publish(kind, payload)

    @staticmethod
    def event_dict(event: Event) -> dict:
        return {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "category": event.category,
            "event_type": event.event_type,
            "host": event.host,
            "severity": event.severity,
            "data": json.loads(event.data),
            "simulated": event.simulated,
        }

    @staticmethod
    def alert_dict(alert: Alert) -> dict:
        return {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity,
            "category": alert.category,
            "title": alert.title,
            "description": alert.description,
            "source": alert.source,
            "risk_score": alert.risk_score,
            "confidence": alert.confidence,
            "status": alert.status,
            "evidence": json.loads(alert.evidence or "{}"),
            "recommendation": alert.recommendation,
            "mitre_technique": alert.mitre_technique,
            "simulated": alert.simulated,
            "incident_id": None,
        }
