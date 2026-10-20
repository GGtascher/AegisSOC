from __future__ import annotations

import ipaddress
import logging
import time
from collections import Counter

import psutil

log = logging.getLogger(__name__)


def is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast)
    except ValueError:
        return False


class ConnectionCollector:
    def __init__(self, engine, baselines):
        self.engine = engine
        self.baselines = baselines
        self.previous: set[tuple] = set()
        self.initialized = False
        self.last_burst: dict[str, float] = {}

    @staticmethod
    def _endpoint(address) -> tuple[str | None, int | None]:
        if not address:
            return None, None
        return address.ip, address.port

    def collect(self) -> tuple[list[dict], list[dict]]:
        items: list[dict] = []
        listeners: list[dict] = []
        current: set[tuple] = set()
        names: dict[int, str] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            log.warning("Network connections are unavailable with current permissions")
            return items, listeners
        for connection in connections:
            local_ip, local_port = self._endpoint(connection.laddr)
            remote_ip, remote_port = self._endpoint(connection.raddr)
            pid = connection.pid
            if pid and pid not in names:
                try:
                    names[pid] = psutil.Process(pid).name()
                except psutil.Error:
                    names[pid] = "Unknown"
            proto = "TCP" if connection.type == 1 else "UDP"
            item = {
                "pid": pid,
                "process": names.get(pid, "System" if pid == 0 else "Unknown"),
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": proto,
                "state": connection.status or "NONE",
            }
            key = (pid, local_ip, local_port, remote_ip, remote_port, proto, item["state"])
            current.add(key)
            items.append(item)
            if item["state"] == psutil.CONN_LISTEN or (proto == "UDP" and not remote_ip):
                listeners.append(item)
        known_listeners = self.baselines.keys("listener")
        known_destinations = self.baselines.keys("destination")
        if not self.initialized:
            for item in listeners:
                listener_key = f"{item['protocol']}:{item['local_ip']}:{item['local_port']}"
                if listener_key not in known_listeners:
                    self.baselines.put("listener", listener_key, item)
            for item in items:
                if is_external(item["remote_ip"]) and str(item["remote_ip"]) not in known_destinations:
                    self.baselines.put("destination", str(item["remote_ip"]), {"first_process": item["process"]})
        else:
            for key in current - self.previous:
                item = next(value for value in items if (value["pid"], value["local_ip"], value["local_port"], value["remote_ip"], value["remote_port"], value["protocol"], value["state"]) == key)
                self.engine.ingest("network", "network", "connection_open", item)
            for item in listeners:
                listener_key = f"{item['protocol']}:{item['local_ip']}:{item['local_port']}"
                if listener_key not in known_listeners:
                    self.baselines.put("listener", listener_key, item)
                    known_listeners.add(listener_key)
                    self.engine.create_alert(
                        "MEDIUM", "network", "New Listening Port", "A process opened a listening port not present in the runtime baseline.",
                        "network", 70, item, "Confirm that the service and port are expected.", "T1049"
                    )
            for item in items:
                remote_ip = str(item["remote_ip"] or "")
                if is_external(remote_ip) and remote_ip not in known_destinations:
                    self.baselines.put("destination", remote_ip, {"first_process": item["process"]})
                    known_destinations.add(remote_ip)
                    self.engine.ingest("network", "network", "external_destination", item, severity="LOW")
        counts = Counter(item["process"] for item in items if item["remote_ip"])
        for process, count in counts.items():
            if count >= 80 and time.monotonic() - self.last_burst.get(process, 0) >= 600:
                self.engine.create_alert(
                    "MEDIUM", "network", "Unusually Many Connections", f"{process} currently owns {count} remote connections.",
                    "network", 65, {"process": process, "connection_count": count}, "Review the process and destination list.", "T1046"
                )
                self.last_burst[process] = time.monotonic()
        self.previous = current
        self.initialized = True
        return items, listeners


def detect_gateway_change(previous: dict | None, current: dict | None) -> bool:
    return bool(previous and current and previous.get("ip") == current.get("ip") and previous.get("mac") and current.get("mac") and previous["mac"].lower() != current["mac"].lower())


def detect_dns_change(previous: list[str] | None, current: list[str] | None) -> bool:
    return bool(previous is not None and current is not None and sorted(previous) != sorted(current))
