from __future__ import annotations

import json
import logging
import platform
import subprocess
import uuid

import psutil

from aegis.collectors.devices import DeviceCollector, run_command

log = logging.getLogger(__name__)


def finding(check_id: str, title: str, severity: str, details: str, recommendation: str, status: str = "OPEN") -> dict:
    return {"check_id": check_id, "title": title, "severity": severity, "status": status, "details": details, "recommendation": recommendation}


class WindowsAuditor:
    def run(self) -> list[dict]:
        results = [finding("SYS-001", "System information", "INFO", f"{platform.node()} running {platform.platform()}", "Keep the operating system and security tools updated.", "INFORMATIONAL")]
        results.extend(self._defender())
        results.extend(self._firewall())
        results.extend(self._registry_checks())
        results.extend(self._network())
        results.extend(self._ports())
        results.extend(self._accounts_and_policy())
        results.extend(self._inventory())
        return results

    def _powershell_json(self, script: str):
        text = run_command(["powershell", "-NoProfile", "-Command", f"{script} | ConvertTo-Json -Compress"], timeout=15)
        try:
            return json.loads(text) if text.strip() else None
        except json.JSONDecodeError:
            return None

    def _defender(self) -> list[dict]:
        data = self._powershell_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated")
        if not data:
            return [finding("DEF-000", "Microsoft Defender status unavailable", "LOW", "The Defender status command did not return data.", "Run AegisSOC as Administrator or verify that Defender is installed.")]
        items = []
        if not data.get("AntivirusEnabled"):
            items.append(finding("DEF-001", "Microsoft Defender antivirus disabled", "HIGH", "AntivirusEnabled is false.", "Enable Microsoft Defender or confirm that another trusted antivirus product is active."))
        if not data.get("RealTimeProtectionEnabled"):
            items.append(finding("DEF-002", "Defender realtime protection disabled", "HIGH", "RealTimeProtectionEnabled is false.", "Enable realtime protection in Windows Security."))
        if not items:
            items.append(finding("DEF-OK", "Microsoft Defender protection enabled", "INFO", "Antivirus and realtime protection are enabled.", "No action is required.", "PASS"))
        return items

    def _firewall(self) -> list[dict]:
        data = self._powershell_json("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction")
        if not data:
            return [finding("FW-000", "Windows Firewall status unavailable", "LOW", "Firewall profiles could not be queried.", "Run the audit with Administrator privileges.")]
        rows = data if isinstance(data, list) else [data]
        disabled = [row.get("Name") for row in rows if not row.get("Enabled")]
        if disabled:
            return [finding("FW-001", "Windows Firewall profile disabled", "HIGH", f"Disabled profiles: {', '.join(disabled)}", "Enable the affected Windows Firewall profiles.")]
        return [finding("FW-OK", "Windows Firewall profiles enabled", "INFO", "All reported firewall profiles are enabled.", "No action is required.", "PASS")]

    def _registry_checks(self) -> list[dict]:
        script = "$uac=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA; $rdp=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections; $smb=(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol; [pscustomobject]@{UAC=$uac;RDP=$rdp;SMB1=$smb}"
        data = self._powershell_json(script) or {}
        results = []
        results.append(finding("UAC-001", "User Account Control disabled", "HIGH", "EnableLUA is not set to 1.", "Enable UAC and restart Windows.") if data.get("UAC") != 1 else finding("UAC-OK", "User Account Control enabled", "INFO", "EnableLUA is set to 1.", "No action is required.", "PASS"))
        if data.get("RDP") == 0:
            results.append(finding("RDP-001", "Remote Desktop enabled", "MEDIUM", "Remote Desktop connections are allowed.", "Disable RDP if unused, or restrict access with firewall rules and Network Level Authentication."))
        else:
            results.append(finding("RDP-OK", "Remote Desktop disabled", "INFO", "Remote Desktop connections are denied.", "No action is required.", "PASS"))
        if data.get("SMB1") is True:
            results.append(finding("SMB-001", "SMBv1 server protocol enabled", "HIGH", "The legacy SMBv1 server protocol is enabled.", "Disable SMBv1 unless a documented legacy dependency requires it."))
        else:
            results.append(finding("SMB-OK", "SMBv1 server protocol disabled", "INFO", "SMBv1 is disabled or not installed.", "No action is required.", "PASS"))
        return results

    def _network(self) -> list[dict]:
        info = DeviceCollector.network_info()
        details = f"Gateway: {info.get('gateway') or 'Unavailable'}; DNS: {', '.join(info.get('dns') or []) or 'Unavailable'}"
        result = [finding("NET-INFO", "Network configuration", "INFO", details, "Confirm that gateway and DNS addresses match the trusted network.", "INFORMATIONAL")]
        profiles = self._powershell_json("Get-NetConnectionProfile | Select-Object Name,NetworkCategory,IPv4Connectivity")
        rows = profiles if isinstance(profiles, list) else ([profiles] if profiles else [])
        if any(row.get("NetworkCategory") == "Public" for row in rows):
            result.append(finding("NET-001", "Public network profile active", "LOW", "At least one interface uses the Public profile.", "This is appropriate on untrusted networks. Use Private only on networks you trust."))
        return result

    def _ports(self) -> list[dict]:
        try:
            listeners = [c for c in psutil.net_connections(kind="inet") if c.status == psutil.CONN_LISTEN]
            return [finding("PORT-INFO", "Listening ports inventory", "INFO", f"Found {len(listeners)} TCP listening sockets.", "Review unexpected listeners on the Network page.", "INFORMATIONAL")]
        except (psutil.AccessDenied, OSError):
            return [finding("PORT-000", "Listening ports unavailable", "LOW", "Current privileges did not allow a complete connection inventory.", "Run as Administrator for more complete telemetry.")]

    def _accounts_and_policy(self) -> list[dict]:
        admins = self._powershell_json("Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass")
        guest = self._powershell_json("Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue | Select-Object Name,Enabled")
        names = admins if isinstance(admins, list) else ([admins] if admins else [])
        results = [finding("ACC-INFO", "Local administrator accounts", "INFO", ", ".join(str(item.get("Name")) for item in names) or "Account list unavailable.", "Review membership regularly and remove unneeded administrators.", "INFORMATIONAL")]
        if guest and guest.get("Enabled"):
            results.append(finding("ACC-001", "Guest account enabled", "MEDIUM", "The built-in Guest account is enabled.", "Disable Guest unless there is a documented need."))
        policy = run_command(["net", "accounts"])
        results.append(finding("PWD-INFO", "Password policy summary", "INFO", policy.strip()[:1200] or "Password policy unavailable.", "Use an appropriate minimum length, lockout threshold, and managed password policy.", "INFORMATIONAL"))
        return results

    def _inventory(self) -> list[dict]:
        services = self._powershell_json("(Get-Service | Where-Object StartType -eq 'Automatic').Count")
        tasks = self._powershell_json("(Get-ScheduledTask | Where-Object State -ne 'Disabled').Count")
        updates = self._powershell_json("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn")
        details = f"Automatic services: {services if services is not None else 'unavailable'}; enabled scheduled tasks: {tasks if tasks is not None else 'unavailable'}; latest hotfix: {updates or 'unavailable'}"
        return [finding("INV-INFO", "Services, tasks, and update inventory", "INFO", details, "Review unexpected services and tasks, and keep Windows Update current.", "INFORMATIONAL")]
