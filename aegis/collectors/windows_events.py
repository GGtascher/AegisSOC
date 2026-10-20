from __future__ import annotations

import logging
import time

log = logging.getLogger(__name__)

EVENTS = {
    4624: ("successful_login", "INFO", "Successful Login", "T1078"),
    4625: ("failed_login", "MEDIUM", "Failed Login", "T1110"),
    4720: ("account_created", "HIGH", "Local Account Created", "T1136"),
    7045: ("service_installed", "HIGH", "Service Installed", "T1543.003"),
    1116: ("defender_detection", "CRITICAL", "Microsoft Defender Detection", None),
}


class WindowsEventCollector:
    def __init__(self, engine):
        self.engine = engine
        self.handles: dict[str, object] = {}
        self.limited_permissions = False
        self.available = False

    def collect(self) -> list[dict]:
        try:
            import win32evtlog
        except ImportError:
            self.limited_permissions = True
            return []
        logs = ["System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational"]
        collected = []
        for log_name in logs:
            try:
                handle = self.handles.get(log_name) or win32evtlog.OpenEventLog(None, log_name)
                self.handles[log_name] = handle
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                records = win32evtlog.ReadEventLog(handle, flags, 0) or []
                cutoff = time.time() - 30
                for record in records[:100]:
                    created = record.TimeGenerated.timestamp()
                    if created < cutoff:
                        continue
                    event_id = record.EventID & 0xFFFF
                    if event_id not in EVENTS:
                        continue
                    event_type, severity, title, mitre = EVENTS[event_id]
                    data = {"event_id": event_id, "log": log_name, "source_name": record.SourceName, "record_number": record.RecordNumber}
                    self.engine.ingest("windows", "windows", event_type, data, severity=severity)
                    if severity != "INFO":
                        self.engine.create_alert(severity, "windows", title, f"Windows event {event_id} was recorded in {log_name}.", "windows", 78, data, "Review the full event in Windows Event Viewer and validate the account or service involved.", mitre)
                    collected.append(data)
                self.available = True
            except Exception as exc:
                if log_name == "Security":
                    self.limited_permissions = True
                log.debug("Event log %s unavailable: %s", log_name, exc)
        return collected
