from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
from datetime import datetime, timezone

import psutil
from sqlalchemy import select

from aegis.collectors.connections import detect_dns_change, detect_gateway_change
from aegis.database.models import Device

log = logging.getLogger(__name__)


def run_command(command: list[str], timeout: int = 8) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


class DeviceCollector:
    def __init__(self, database, engine, baselines):
        self.database = database
        self.engine = engine
        self.baselines = baselines

    def collect(self) -> tuple[list[dict], dict]:
        interfaces = self.network_info()
        devices = self._neighbors()
        now = datetime.now(timezone.utc)
        known = self.baselines.keys("device")
        first_run = not known
        new_devices: list[tuple[str, dict]] = []
        with self.database.session() as session:
            for item in devices:
                key = f"{item['ip']}|{item['mac']}"
                existing = session.scalar(select(Device).where(Device.ip == item["ip"], Device.mac == item["mac"]))
                if existing:
                    existing.last_seen = now
                    existing.state = item["state"]
                else:
                    session.add(Device(**item, first_seen=now, last_seen=now))
                if key not in known:
                    new_devices.append((key, item))
        for key, item in new_devices:
            self.baselines.put("device", key, item)
            if not first_run:
                self.engine.create_alert("LOW", "network", "New Network Device", "A device not present in the saved baseline appeared on the local network.", "network", 68, item, "Confirm that the IP and MAC address belong to an expected device.", "T1046")
        self._check_gateway_dns(interfaces, devices)
        return devices, interfaces

    def _check_gateway_dns(self, info: dict, devices: list[dict]) -> None:
        gateway_ip = info.get("gateway")
        gateway_device = next((item for item in devices if item["ip"] == gateway_ip), None)
        current_gateway = {"ip": gateway_ip, "mac": gateway_device.get("mac") if gateway_device else None}
        previous_gateway = self.baselines.get("network", "gateway")
        if detect_gateway_change(previous_gateway, current_gateway):
            self.engine.create_alert("CRITICAL", "network", "Gateway MAC Changed", "Possible ARP spoofing, MITM, or a legitimate router or network change.", "network", 92, {"previous": previous_gateway, "current": current_gateway}, "Verify the gateway MAC address directly on the router before taking action.", "T1557")
        if gateway_ip:
            self.baselines.put("network", "gateway", current_gateway)
        dns = info.get("dns", [])
        previous_dns = self.baselines.get("network", "dns")
        if detect_dns_change(previous_dns, dns):
            self.engine.create_alert("MEDIUM", "network", "DNS Servers Changed", "The configured DNS server list changed from its previous baseline.", "network", 78, {"previous": previous_dns, "current": dns}, "Confirm the DNS configuration with the network owner.", "T1565")
        if dns:
            self.baselines.put("network", "dns", dns)

    @staticmethod
    def _neighbors() -> list[dict]:
        text = run_command(["powershell", "-NoProfile", "-Command", "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress"])
        devices: list[dict] = []
        try:
            parsed = json.loads(text) if text.strip() else []
            if isinstance(parsed, dict):
                parsed = [parsed]
            for row in parsed:
                ip, mac = row.get("IPAddress"), row.get("LinkLayerAddress")
                if ip and mac and mac != "00-00-00-00-00-00" and ip != "255.255.255.255" and not ipaddress.ip_address(ip).is_multicast:
                    devices.append({"ip": ip, "mac": mac, "state": str(row.get("State", "Unknown")), "vendor": "Unknown"})
        except (ValueError, TypeError, json.JSONDecodeError):
            pass
        if devices:
            return devices
        arp = run_command(["arp", "-a"])
        for ip, mac, state in re.findall(r"\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", arp):
            devices.append({"ip": ip, "mac": mac, "state": state, "vendor": "Unknown"})
        return devices

    @staticmethod
    def network_info() -> dict:
        result = {"interfaces": [], "dns": [], "gateway": None, "ssid": None, "bssid": None, "signal": None, "channel": None, "radio_type": None, "authentication": None, "cipher": None, "profile": None}
        for name, addresses in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            item = {"name": name, "ipv4": [], "ipv6": [], "mac": None, "speed_mbps": stats.speed if stats else 0, "up": stats.isup if stats else False}
            for address in addresses:
                if address.family.name == "AF_INET":
                    item["ipv4"].append(address.address)
                elif address.family.name == "AF_INET6":
                    item["ipv6"].append(address.address.split("%", 1)[0])
                elif address.family.name in {"AF_LINK", "AF_PACKET"}:
                    item["mac"] = address.address
            result["interfaces"].append(item)
        config = run_command(["powershell", "-NoProfile", "-Command", "Get-NetIPConfiguration | Select-Object InterfaceAlias,@{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}},@{N='DNS';E={$_.DNSServer.ServerAddresses}} | ConvertTo-Json -Compress"])
        try:
            rows = json.loads(config) if config.strip() else []
            if isinstance(rows, dict):
                rows = [rows]
            dns = []
            for row in rows:
                if row.get("Gateway") and not result["gateway"]:
                    result["gateway"] = row["Gateway"]
                values = row.get("DNS") or []
                dns.extend(values if isinstance(values, list) else [values])
            result["dns"] = sorted(set(filter(None, dns)))
        except (ValueError, TypeError, json.JSONDecodeError):
            pass
        if not result["gateway"] or not result["dns"]:
            fallback = run_command([
                "powershell", "-NoProfile", "-Command",
                "$gateway=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop; "
                "$dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {$_.ServerAddresses} | Where-Object {$_}); "
                "[pscustomobject]@{Gateway=$gateway;DNS=$dns} | ConvertTo-Json -Compress",
            ])
            try:
                row = json.loads(fallback) if fallback.strip() else {}
                result["gateway"] = result["gateway"] or row.get("Gateway")
                if not result["dns"]:
                    values = row.get("DNS") or []
                    result["dns"] = sorted(set(values if isinstance(values, list) else [values]))
            except (ValueError, TypeError, json.JSONDecodeError):
                pass
        wlan = run_command(["netsh", "wlan", "show", "interfaces"])
        mapping = {"SSID": "ssid", "BSSID": "bssid", "Signal": "signal", "Channel": "channel", "Radio type": "radio_type", "Authentication": "authentication", "Cipher": "cipher"}
        for label, key in mapping.items():
            match = re.search(rf"^\s*{re.escape(label)}\s*:\s*(.+)$", wlan, re.MULTILINE | re.IGNORECASE)
            if match:
                result[key] = match.group(1).strip()
        return result
