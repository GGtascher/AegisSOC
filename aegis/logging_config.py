from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from aegis.config import LOG_DIR, ensure_runtime_dirs


def configure_logging() -> None:
    ensure_runtime_dirs()
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = RotatingFileHandler(
        LOG_DIR / "aegissoc.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)
