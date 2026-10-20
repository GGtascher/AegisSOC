from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timezone

from aegis.collectors.connections import ConnectionCollector
from aegis.collectors.devices import DeviceCollector
from aegis.collectors.files import FileIntegrityCollector
from aegis.collectors.persistence import PersistenceCollector
from aegis.collectors.processes import ProcessCollector
from aegis.collectors.system import system_snapshot
from aegis.collectors.windows_events import WindowsEventCollector

log = logging.getLogger(__name__)


class Runtime:
    def __init__(self, database, engine, baselines, demo_mode: bool = False):
        self.database = database
        self.engine = engine
        self.baselines = baselines
        self.demo_mode = demo_mode
        self.monitoring = True
        self.started_at = datetime.now(timezone.utc)
        self.processes: list[dict] = []
        self.connections: list[dict] = []
        self.listeners: list[dict] = []
        self.devices: list[dict] = []
        self.network_info: dict = {}
        self.persistence: list[dict] = []
        self.last_errors: dict[str, str] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: set[asyncio.Queue] = set()
        settings = database.settings()
        self.process_collector = ProcessCollector(engine, baselines, settings["max_hash_mb"])
        self.connection_collector = ConnectionCollector(engine, baselines)
        self.device_collector = DeviceCollector(database, engine, baselines)
        self.persistence_collector = PersistenceCollector(engine, baselines)
        self.event_collector = WindowsEventCollector(engine)
        self.file_collector = FileIntegrityCollector(engine)

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._stop.clear()
        settings = self.database.settings()
        if settings.get("file_monitor"):
            self.file_collector.start(settings.get("fim_paths", []), settings.get("max_hash_mb", 100))
        self._thread = threading.Thread(target=self._run, name="aegis-collectors", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.file_collector.stop()
        if self._thread:
            self._thread.join(timeout=8)

    def set_monitoring(self, value: bool) -> None:
        self.monitoring = value
        log.info("Monitoring %s", "resumed" if value else "paused")
        self.publish("monitoring", {"active": value})

    def reconfigure_files(self) -> None:
        settings = self.database.settings()
        if self.monitoring and settings.get("file_monitor"):
            self.file_collector.start(settings.get("fim_paths", []), settings.get("max_hash_mb", 100))
        else:
            self.file_collector.stop()

    def _run(self) -> None:
        last = {"process": 0.0, "network": 0.0, "device": 0.0, "persistence": 0.0, "events": 0.0}
        while not self._stop.wait(0.5):
            if not self.monitoring:
                continue
            settings = self.database.settings()
            now = time.monotonic()
            jobs = [
                ("process", settings.get("process_monitor"), settings.get("process_interval", 3), self._collect_processes),
                ("network", settings.get("network_monitor"), settings.get("network_interval", 5), self._collect_connections),
                ("device", settings.get("network_monitor"), settings.get("device_interval", 30), self._collect_devices),
                ("persistence", True, 60, self._collect_persistence),
                ("events", settings.get("windows_events"), 10, self.event_collector.collect),
            ]
            for name, enabled, interval, job in jobs:
                if enabled and now - last[name] >= max(1, int(interval)):
                    try:
                        job()
                        self.last_errors.pop(name, None)
                    except Exception as exc:
                        self.last_errors[name] = str(exc)
                        log.exception("Collector %s failed", name)
                    last[name] = now

    def _collect_processes(self):
        self.processes = self.process_collector.collect()

    def _collect_connections(self):
        self.connections, self.listeners = self.connection_collector.collect()

    def _collect_devices(self):
        self.devices, self.network_info = self.device_collector.collect()

    def _collect_persistence(self):
        self.persistence = self.persistence_collector.collect()

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, kind: str, payload: dict) -> None:
        if not self._loop or self._loop.is_closed():
            return
        message = {"type": kind, "payload": payload, "timestamp": datetime.now(timezone.utc).isoformat()}
        def put_messages():
            for queue in list(self._subscribers):
                if not queue.full():
                    queue.put_nowait(message)
        self._loop.call_soon_threadsafe(put_messages)

    def run_demo(self, delay: float = 1.2) -> None:
        correlation_id = f"demo-{int(time.time())}"
        steps = [
            ("endpoint", "endpoint", "process_start", "HIGH", "Office Application Spawned Suspicious PowerShell", "A simulated office process launched PowerShell.", {"process": "powershell.exe", "pid": 42420, "ppid": 41110, "parent": "WINWORD.EXE", "user": "demo-user", "correlation_id": correlation_id}, "T1059.001"),
            ("endpoint", "endpoint", "encoded_powershell", "HIGH", "Encoded PowerShell Detected", "A simulated encoded command was observed.", {"process": "powershell.exe", "pid": 42420, "command_line": "[SIMULATED] powershell -EncodedCommand REDACTED", "correlation_id": correlation_id}, "T1059.001"),
            ("network", "network", "connection_open", "HIGH", "Suspicious External Connection", "A simulated process opened an external connection.", {"process": "powershell.exe", "pid": 42420, "remote_ip": "203.0.113.42", "remote_port": 443, "correlation_id": correlation_id}, "T1071.001"),
            ("file", "file", "file_created", "HIGH", "Executable Appeared in Temp", "A simulated executable appeared in a temporary directory.", {"file": "C:\\Users\\demo\\AppData\\Local\\Temp\\update-demo.exe", "pid": 42420, "correlation_id": correlation_id}, "T1204"),
            ("persistence", "persistence", "persistence_added", "CRITICAL", "Startup Persistence Entry", "A simulated startup registry value was added.", {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "process": "update-demo.exe", "pid": 42420, "correlation_id": correlation_id}, "T1547.001"),
        ]
        for source, category, event_type, severity, title, description, evidence, mitre in steps:
            if delay:
                time.sleep(delay)
            self.engine.ingest(source, category, event_type, evidence, severity=severity, simulated=True)
            self.engine.create_alert(severity, category, title, description, source, 95, evidence, "Open the incident and review the simulated timeline.", mitre, True)

    def start_demo(self) -> bool:
        thread = threading.Thread(target=self.run_demo, name="aegis-demo", daemon=True)
        thread.start()
        return True

    def test_alert(self):
        evidence = {"kind": "internal_test", "message": "No command was executed"}
        self.engine.ingest("system", "system", "test_alert", evidence, severity="LOW", simulated=True)
        return self.engine.create_alert("LOW", "system", "AegisSOC Test Alert", "This harmless alert confirms that storage, API, and realtime delivery are working.", "system", 100, evidence, "Resolve the alert after the test.", None, True)
