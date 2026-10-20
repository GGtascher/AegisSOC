from __future__ import annotations

import json

from sqlalchemy import select

from aegis.collectors.connections import detect_dns_change, detect_gateway_change, is_external
from aegis.database.models import Alert, Base, Incident
from aegis.detection.scoring import alert_risk, system_risk


def test_database_initialization(stack):
    database, *_ = stack
    assert database.path.exists()
    assert "alerts" in Base.metadata.tables
    assert database.settings()["process_interval"] == 3


def test_alert_creation_and_state_change(stack):
    database, _, _, engine = stack
    alert = engine.create_alert("HIGH", "endpoint", "Test", "Description", "endpoint", 80, {"pid": 7})
    assert alert.id
    assert alert.risk_score > 0
    changed = engine.update_alert(alert.id, "INVESTIGATING")
    assert changed and changed.status == "INVESTIGATING"
    with database.session() as session:
        assert session.get(Alert, alert.id).status == "INVESTIGATING"


def test_risk_scoring_is_bounded_and_normalized():
    assert alert_risk("CRITICAL", 100) <= 100
    assert system_risk(["HIGH"]) < system_risk(["HIGH", "HIGH", "CRITICAL"])
    assert system_risk(["CRITICAL"] * 50) == 100


def test_yaml_rules_load(stack):
    _, rules, _, _ = stack
    assert "ENDPOINT-001" in rules.rules
    assert len(rules.rules) >= 6


def test_process_detection_logic(stack):
    _, _, _, engine = stack
    event = engine.ingest("endpoint", "endpoint", "process_start", {
        "name": "powershell.exe", "parent": "WINWORD.EXE", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ZABlAG0AbwA=", "pid": 50,
    })
    with engine.database.session() as session:
        alerts = session.scalars(select(Alert)).all()
    titles = {item.title for item in alerts}
    assert "Encoded PowerShell Command" in titles
    assert "Office Application Spawned a Shell" in titles


def test_network_detection_logic():
    assert is_external("8.8.8.8")
    assert not is_external("192.168.1.10")
    assert not is_external("127.0.0.1")


def test_gateway_mac_change_detection():
    assert detect_gateway_change({"ip":"192.168.1.1","mac":"aa-bb"},{"ip":"192.168.1.1","mac":"cc-dd"})
    assert not detect_gateway_change({"ip":"192.168.1.1","mac":"aa-bb"},{"ip":"10.0.0.1","mac":"cc-dd"})


def test_dns_change_detection():
    assert detect_dns_change(["1.1.1.1"], ["8.8.8.8"])
    assert not detect_dns_change(["8.8.8.8", "1.1.1.1"], ["1.1.1.1", "8.8.8.8"])


def test_incident_correlation(stack):
    database, _, _, engine = stack
    for title in ["PowerShell", "Connection", "Persistence"]:
        engine.create_alert("HIGH", "endpoint", title, "test", "test", 90, {"pid": 1234, "user":"tester"})
    with database.session() as session:
        incidents = session.scalars(select(Incident)).all()
        assert len(incidents) == 1
        assert len(incidents[0].alerts) == 3


def test_simulated_and_live_alerts_do_not_mix(stack):
    database, _, _, engine = stack
    for number in range(3):
        engine.create_alert("HIGH", "endpoint", f"Demo {number}", "test", "test", 90, {"pid": 444}, simulated=True)
    engine.create_alert("HIGH", "endpoint", "Live alert", "test", "test", 90, {"pid": 444}, simulated=False)
    with database.session() as session:
        incident = session.scalars(select(Incident)).one()
        assert all(alert.simulated for alert in incident.alerts)


def test_rule_state_persists(stack):
    database, rules, _, _ = stack
    rules.set_enabled("ENDPOINT-001", False)
    replacement = type(rules)(database)
    replacement.load()
    assert replacement.rules["ENDPOINT-001"].enabled is False
