from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger(__name__)
SUSPICIOUS_EXTENSIONS = {".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr"}


class IntegrityHandler(FileSystemEventHandler):
    def __init__(self, engine, max_hash_mb: int):
        self.engine = engine
        self.max_bytes = max_hash_mb * 1024 * 1024

    def _hash(self, path_value: str) -> tuple[str | None, str | None]:
        try:
            path = Path(path_value)
            size = path.stat().st_size
            if size > self.max_bytes:
                return None, f"Hash skipped because file is larger than {self.max_bytes // 1024**2} MB"
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest(), None
        except (OSError, PermissionError):
            return None, "File was unavailable during hashing"

    def _record(self, event_type: str, source: str, destination: str | None = None, is_directory: bool = False) -> None:
        if is_directory:
            return
        file_hash, hash_note = (None, None)
        if event_type in {"file_created", "file_modified", "file_moved"}:
            file_hash, hash_note = self._hash(destination or source)
        data = {"path": source, "destination": destination, "sha256": file_hash, "hash_note": hash_note}
        self.engine.ingest("file", "file", event_type, data)
        checked = (destination or source).lower()
        sensitive = "\\startup\\" in checked or "\\temp\\" in checked
        if Path(checked).suffix in SUSPICIOUS_EXTENSIONS and sensitive and event_type in {"file_created", "file_moved"}:
            self.engine.create_alert(
                "HIGH", "file", "Suspicious File in a Sensitive Location",
                "A script or executable file appeared in Startup or a temporary directory.",
                "file", 84, data, "Verify the file origin, signature, hash, and related process activity.", "T1547"
            )

    def on_created(self, event):
        self._record("file_created", event.src_path, is_directory=event.is_directory)

    def on_modified(self, event):
        self._record("file_modified", event.src_path, is_directory=event.is_directory)

    def on_deleted(self, event):
        self._record("file_deleted", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event):
        self._record("file_moved", event.src_path, event.dest_path, event.is_directory)


class FileIntegrityCollector:
    def __init__(self, engine):
        self.engine = engine
        self.observer: Observer | None = None
        self.paths: list[str] = []

    def start(self, paths: list[str], max_hash_mb: int = 100) -> None:
        self.stop()
        observer = Observer()
        handler = IntegrityHandler(self.engine, max_hash_mb)
        active = []
        for value in paths:
            path = Path(os.path.expandvars(value)).expanduser()
            if path.exists() and path.is_dir():
                try:
                    observer.schedule(handler, str(path), recursive=True)
                    active.append(str(path))
                except OSError:
                    log.exception("Could not monitor %s", path)
        if active:
            observer.start()
            self.observer = observer
        self.paths = active
        log.info("File monitoring started for %s path(s)", len(active))

    def stop(self) -> None:
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            self.observer = None
