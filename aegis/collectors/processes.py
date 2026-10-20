from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import psutil

log = logging.getLogger(__name__)


class ProcessCollector:
    def __init__(self, engine, baselines, max_hash_mb: int = 100):
        self.engine = engine
        self.baselines = baselines
        self.max_hash_bytes = max_hash_mb * 1024 * 1024
        self.previous: dict[int, dict] = {}
        self.hash_cache: dict[tuple[str, float, int], str | None] = {}
        self.initialized = False

    def collect(self) -> list[dict]:
        current: dict[int, dict] = {}
        for process in psutil.process_iter(["pid", "ppid", "name", "username", "exe", "cmdline", "create_time", "cpu_percent", "memory_info"]):
            try:
                info = process.info
                parent_name = None
                try:
                    parent = process.parent()
                    parent_name = parent.name() if parent else None
                except (psutil.Error, OSError):
                    pass
                path = info.get("exe") or ""
                memory = info.get("memory_info")
                item = {
                    "pid": info["pid"],
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "Unknown",
                    "parent": parent_name,
                    "username": info.get("username"),
                    "path": path,
                    "command_line": " ".join(info.get("cmdline") or []),
                    "cpu_percent": round(float(info.get("cpu_percent") or 0), 1),
                    "ram_mb": round((memory.rss if memory else 0) / 1024**2, 1),
                    "start_time": datetime.fromtimestamp(info.get("create_time") or 0, tz=timezone.utc).isoformat(),
                }
                current[item["pid"]] = item
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError, ValueError):
                continue
        if not self.initialized:
            for pid, item in current.items():
                self.baselines.put("process", str(pid), {"name": item["name"], "path": item["path"]})
            self.initialized = True
        else:
            for pid in current.keys() - self.previous.keys():
                self.engine.ingest("endpoint", "endpoint", "process_start", current[pid])
            for pid in self.previous.keys() - current.keys():
                self.engine.ingest("endpoint", "endpoint", "process_stop", self.previous[pid])
        self.previous = current
        return sorted(current.values(), key=lambda item: (-item["cpu_percent"], item["name"].lower()))

    def hash_executable(self, path_value: str) -> str | None:
        try:
            path = Path(path_value)
            stat = path.stat()
            key = (str(path), stat.st_mtime, stat.st_size)
            if key in self.hash_cache:
                return self.hash_cache[key]
            if not path.is_file() or stat.st_size > self.max_hash_bytes:
                self.hash_cache[key] = None
                return None
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            value = digest.hexdigest()
            self.hash_cache[key] = value
            return value
        except (OSError, PermissionError):
            return None
