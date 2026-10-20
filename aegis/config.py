from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parent.parent
if getattr(sys, "frozen", False):
    BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", SOURCE_ROOT))
    RUNTIME_ROOT = Path(sys.executable).resolve().parent
else:
    BUNDLE_ROOT = SOURCE_ROOT
    RUNTIME_ROOT = SOURCE_ROOT

ROOT = RUNTIME_ROOT
DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", RUNTIME_ROOT / "data"))
LOG_DIR = Path(os.getenv("AEGIS_LOG_DIR", RUNTIME_ROOT / "logs"))
RULES_DIR = Path(os.getenv("AEGIS_RULES_DIR", BUNDLE_ROOT / "rules"))
FRONTEND_DIST = BUNDLE_ROOT / "frontend" / "dist"
DB_PATH = DATA_DIR / "aegissoc.db"


@dataclass(frozen=True)
class Defaults:
    process_monitor: bool = True
    network_monitor: bool = True
    file_monitor: bool = True
    windows_events: bool = True
    process_interval: int = 3
    network_interval: int = 5
    device_interval: int = 30
    event_retention_days: int = 7
    max_hash_mb: int = 100


DEFAULTS = Defaults()


def default_fim_paths() -> list[str]:
    home = Path.home()
    candidates = [
        home / "Desktop",
        home / "Documents",
        Path(os.getenv("APPDATA", home)) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    return [str(path) for path in candidates if path.exists()]


def ensure_runtime_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
