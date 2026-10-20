from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import selectinload

from aegis.audit.windows_audit import WindowsAuditor
from aegis.collectors.system import system_snapshot
from aegis.database.models import Alert, Device, Event, Incident, SecurityFinding
from aegis.detection.engine import DetectionEngine
from aegis.detection.scoring import system_risk


class StatusPatch(BaseModel):
    status: str


class RulePatch(BaseModel):
    enabled: bool


class MonitoringPatch(BaseModel):
    active: bool


class SettingsPatch(BaseModel):
    process_monitor: bool | None = None
    network_monitor: bool | None = None
    file_monitor: bool | None = None
    windows_events: bool | None = None
    process_interval: int | None = Field(None, ge=1, le=300)
    network_interval: int | None = Field(None, ge=1, le=300)
    device_interval: int | None = Field(None, ge=5, le=3600)
    event_retention_days: int | None = Field(None, ge=1, le=365)
    max_hash_mb: int | None = Field(None, ge=1, le=2048)
    fim_paths: list[str] | None = None


def incident_dict(incident: Incident, details: bool = False) -> dict:
    data = {
        "id": incident.id,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "summary": incident.summary,
        "entities": json.loads(incident.entities or "{}"),
    }
    if details:
        data["alerts"] = [DetectionEngine.alert_dict(alert) for alert in incident.alerts]
        for item in data["alerts"]:
            item["incident_id"] = incident.id
        data["timeline"] = [
            {"timestamp": alert.timestamp.isoformat(), "type": "alert", "title": alert.title, "severity": alert.severity, "simulated": alert.simulated}
            for alert in incident.alerts
        ]
        data["mitre_techniques"] = sorted({alert.mitre_technique for alert in incident.alerts if alert.mitre_technique})
        data["investigation_steps"] = [
            "Validate the user and process tree shown in the evidence.",
            "Review file paths, hashes, and remote destinations.",
            "Compare persistence entries with the known baseline.",
            "Contain only after confirming the activity is unwanted.",
        ]
    return data


def build_router(database, runtime, rules, engine) -> APIRouter:
    router = APIRouter(prefix="/api")

    @router.get("/health")
    def health():
        database_status = "ok"
        try:
            with database.engine.connect() as connection:
                connection.exec_driver_sql("SELECT 1")
        except Exception:
            database_status = "error"
        return {"status": "ok" if database_status == "ok" else "degraded", "monitoring": runtime.monitoring, "database": database_status, "mode": "demo" if runtime.demo_mode else "live", "collectors": {"errors": runtime.last_errors, "windows_events_limited": runtime.event_collector.limited_permissions}}

    @router.get("/dashboard")
    def dashboard():
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        with database.session() as session:
            active_alerts = session.scalars(select(Alert).where(Alert.status.in_(["NEW", "INVESTIGATING"]))).all()
            incidents = session.scalars(select(Incident).where(Incident.status.in_(["NEW", "INVESTIGATING"]))).all()
            findings = session.scalars(select(SecurityFinding).where(SecurityFinding.status == "OPEN")).all()
            recent_alerts = session.scalars(select(Alert).order_by(desc(Alert.timestamp)).limit(8)).all()
            recent_incidents = session.scalars(select(Incident).order_by(desc(Incident.updated_at)).limit(6)).all()
            alert_rows = session.scalars(select(Alert).where(Alert.timestamp >= since)).all()
            severities = Counter(item.severity for item in alert_rows)
            hourly = Counter(item.timestamp.astimezone(timezone.utc).strftime("%H:00") for item in alert_rows)
            return {
                "monitoring": runtime.monitoring,
                "risk_score": system_risk(item.severity for item in active_alerts),
                "counts": {
                    "active_alerts": len(active_alerts),
                    "critical_alerts": sum(item.severity == "CRITICAL" for item in active_alerts),
                    "incidents": len(incidents),
                    "processes": len(runtime.processes),
                    "connections": len(runtime.connections),
                    "devices": len(runtime.devices),
                    "findings": len(findings),
                },
                "system": system_snapshot(),
                "alerts_by_severity": [{"name": key, "value": severities.get(key, 0)} for key in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]],
                "alerts_over_time": [{"time": key, "alerts": value} for key, value in sorted(hourly.items())],
                "network_activity": len(runtime.connections),
                "recent_alerts": [DetectionEngine.alert_dict(item) for item in recent_alerts],
                "recent_incidents": [incident_dict(item) for item in recent_incidents],
                "disclaimer": "Risk Score is heuristic and does not prove compromise.",
            }

    @router.get("/processes")
    def processes(search: str = ""):
        needle = search.lower().strip()
        rows = runtime.processes
        if needle:
            rows = [item for item in rows if needle in json.dumps(item).lower()]
        return {"items": rows, "count": len(rows), "system": system_snapshot()}

    @router.get("/processes/{pid}/hash")
    def process_hash(pid: int):
        item = next((row for row in runtime.processes if row["pid"] == pid), None)
        if not item:
            raise HTTPException(404, "Process not found")
        return {"pid": pid, "path": item.get("path"), "sha256": runtime.process_collector.hash_executable(item.get("path") or "")}

    @router.get("/connections")
    def connections():
        return {"items": runtime.connections, "listening": runtime.listeners, "count": len(runtime.connections)}

    @router.get("/network")
    def network():
        return {"information": runtime.network_info, "devices": runtime.devices, "connections": runtime.connections, "listening": runtime.listeners}

    @router.get("/devices")
    def devices():
        with database.session() as session:
            rows = session.scalars(select(Device).order_by(desc(Device.last_seen))).all()
            return [{"id": row.id, "ip": row.ip, "mac": row.mac, "state": row.state, "vendor": row.vendor, "first_seen": row.first_seen.isoformat(), "last_seen": row.last_seen.isoformat()} for row in rows]

    @router.get("/alerts")
    def alerts(severity: str | None = None, status: str | None = None, category: str | None = None, search: str = "", limit: int = Query(200, ge=1, le=1000)):
        query = select(Alert).options(selectinload(Alert.incidents)).order_by(desc(Alert.timestamp)).limit(limit)
        if severity:
            query = query.where(Alert.severity == severity.upper())
        if status:
            query = query.where(Alert.status == status.upper())
        if category:
            query = query.where(Alert.category == category)
        if search:
            query = query.where(Alert.title.ilike(f"%{search}%"))
        with database.session() as session:
            rows = session.scalars(query).all()
            output = []
            for row in rows:
                item = DetectionEngine.alert_dict(row)
                item["incident_id"] = row.incidents[0].id if row.incidents else None
                output.append(item)
            return output

    @router.get("/alerts/{alert_id}")
    def alert_detail(alert_id: int):
        with database.session() as session:
            row = session.scalar(select(Alert).options(selectinload(Alert.incidents)).where(Alert.id == alert_id))
            if not row:
                raise HTTPException(404, "Alert not found")
            item = DetectionEngine.alert_dict(row)
            item["incident_id"] = row.incidents[0].id if row.incidents else None
            return item

    @router.patch("/alerts/{alert_id}")
    def update_alert(alert_id: int, patch: StatusPatch):
        try:
            row = engine.update_alert(alert_id, patch.status.upper())
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not row:
            raise HTTPException(404, "Alert not found")
        return DetectionEngine.alert_dict(row)

    @router.get("/incidents")
    def incidents():
        with database.session() as session:
            rows = session.scalars(select(Incident).order_by(desc(Incident.updated_at))).all()
            return [incident_dict(row) for row in rows]

    @router.get("/incidents/{incident_id}")
    def incident_detail(incident_id: int):
        with database.session() as session:
            row = session.scalar(select(Incident).options(selectinload(Incident.alerts)).where(Incident.id == incident_id))
            if not row:
                raise HTTPException(404, "Incident not found")
            return incident_dict(row, True)

    @router.patch("/incidents/{incident_id}")
    def update_incident(incident_id: int, patch: StatusPatch):
        status = patch.status.upper()
        if status not in {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}:
            raise HTTPException(400, "Invalid incident status")
        with database.session() as session:
            row = session.get(Incident, incident_id)
            if not row:
                raise HTTPException(404, "Incident not found")
            row.status = status
            row.updated_at = datetime.now(timezone.utc)
            return incident_dict(row)

    @router.get("/timeline")
    def timeline(limit: int = Query(300, ge=1, le=1000), category: str | None = None, severity: str | None = None):
        query = select(Event).order_by(desc(Event.timestamp)).limit(limit)
        if category:
            query = query.where(Event.category == category)
        if severity:
            query = query.where(Event.severity == severity.upper())
        with database.session() as session:
            return [DetectionEngine.event_dict(row) for row in session.scalars(query)]

    @router.post("/audit")
    def audit():
        rows = WindowsAuditor().run()
        with database.session() as session:
            session.query(SecurityFinding).delete()
            for item in rows:
                session.add(SecurityFinding(**item))
        for item in rows:
            engine.ingest("audit", "audit", "audit_finding", item, severity=item["severity"])
        return {"findings": rows, "summary": dict(Counter(item["severity"] for item in rows)), "risk_score": system_risk(item["severity"] for item in rows if item["status"] == "OPEN")}

    @router.get("/audit")
    def audit_results():
        with database.session() as session:
            rows = session.scalars(select(SecurityFinding).order_by(desc(SecurityFinding.timestamp))).all()
            return [{"id": row.id, "check_id": row.check_id, "timestamp": row.timestamp.isoformat(), "title": row.title, "severity": row.severity, "status": row.status, "details": row.details, "recommendation": row.recommendation} for row in rows]

    @router.get("/rules")
    def list_rules():
        return [rule.public() for rule in rules.rules.values()]

    @router.patch("/rules/{rule_id}")
    def patch_rule(rule_id: str, patch: RulePatch):
        rule = rules.set_enabled(rule_id, patch.enabled)
        if not rule:
            raise HTTPException(404, "Rule not found")
        return rule.public()

    @router.get("/settings")
    def settings():
        return database.settings()

    @router.patch("/settings")
    def patch_settings(patch: SettingsPatch):
        values = patch.model_dump(exclude_none=True)
        updated = database.update_settings(values)
        runtime.reconfigure_files()
        return updated

    @router.patch("/monitoring")
    def monitoring(patch: MonitoringPatch):
        runtime.set_monitoring(patch.active)
        runtime.reconfigure_files()
        return {"monitoring": runtime.monitoring}

    @router.post("/demo/alert")
    def demo_alert():
        row = runtime.test_alert()
        return DetectionEngine.alert_dict(row)

    @router.post("/demo/attack")
    def demo_attack():
        runtime.start_demo()
        return {"started": True, "safe": True, "message": "Safe simulated events are being generated. No malicious command is executed."}

    return router
