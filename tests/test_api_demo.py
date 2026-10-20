from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.app import create_app
from aegis.database.models import Alert, Incident, SecurityFinding


def test_api_health_endpoint(tmp_path):
    app = create_app(database_path=tmp_path / "api.db")
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["database"] == "ok"


def test_demo_alert_endpoint(tmp_path):
    app = create_app(database_path=tmp_path / "alert.db")
    with TestClient(app) as client:
        result = client.post("/api/demo/alert")
        assert result.status_code == 200
        assert result.json()["simulated"] is True
        alert_id = result.json()["id"]
        changed = client.patch(f"/api/alerts/{alert_id}", json={"status":"RESOLVED"})
        assert changed.json()["status"] == "RESOLVED"


def test_demo_attack_creates_incident(tmp_path):
    app = create_app(database_path=tmp_path / "demo.db")
    app.state.runtime.run_demo(delay=0)
    with app.state.database.session() as session:
        assert len(session.scalars(select(Alert)).all()) == 5
        incidents = session.scalars(select(Incident)).all()
        assert incidents
        assert incidents[0].severity == "CRITICAL"
        assert len(incidents[0].alerts) == 5


def test_audit_result_handling(tmp_path, monkeypatch):
    app = create_app(database_path=tmp_path / "audit.db")
    sample = [{"check_id":"TEST-1","title":"Test check","severity":"LOW","status":"OPEN","details":"Safe test","recommendation":"Review"}]
    monkeypatch.setattr("aegis.api.routes.WindowsAuditor.run", lambda _self: sample)
    with TestClient(app) as client:
        result = client.post("/api/audit")
        assert result.status_code == 200
        assert result.json()["findings"][0]["check_id"] == "TEST-1"
        saved = client.get("/api/audit").json()
        assert saved[0]["title"] == "Test check"
