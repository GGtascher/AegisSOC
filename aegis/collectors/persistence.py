from __future__ import annotations

import hashlib
import json
import logging

from aegis.collectors.devices import run_command

log = logging.getLogger(__name__)


class PersistenceCollector:
    def __init__(self, engine, baselines):
        self.engine = engine
        self.baselines = baselines
        self.initialized = False

    def collect(self) -> list[dict]:
        script = r"""
$result=@()
$keys=@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
foreach($key in $keys){if(Test-Path $key){$p=Get-ItemProperty $key; foreach($name in $p.PSObject.Properties.Name){if($name -notmatch '^PS'){ $result += [pscustomobject]@{kind='Registry';location=$key;name=$name;command=[string]$p.$name}}}}}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne 'Disabled'} | Select-Object -First 150 | ForEach-Object {$result += [pscustomobject]@{kind='ScheduledTask';location=$_.TaskPath;name=$_.TaskName;command=[string]$_.Actions.Execute}}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object -First 200 | ForEach-Object {$result += [pscustomobject]@{kind='Service';location=$_.Name;name=$_.DisplayName;command=$_.PathName}}
$result | ConvertTo-Json -Compress
"""
        text = run_command(["powershell", "-NoProfile", "-Command", script], timeout=15)
        try:
            items = json.loads(text) if text.strip() else []
            if isinstance(items, dict):
                items = [items]
        except json.JSONDecodeError:
            return []
        known = self.baselines.keys("persistence")
        first_run = not known
        for item in items:
            key = hashlib.sha256(f"{item.get('kind')}|{item.get('location')}|{item.get('name')}|{item.get('command')}".encode()).hexdigest()
            if key not in known:
                self.baselines.put("persistence", key, item)
                if not first_run and self.initialized:
                    self.engine.ingest("persistence", "persistence", "persistence_added", item)
                    self.engine.create_alert("HIGH", "persistence", "New Persistence Entry", "A new startup, task, or service entry appeared after the baseline was created.", "persistence", 80, item, "Confirm ownership, command path, signature, and business purpose.", "T1547")
        self.initialized = True
        return items
