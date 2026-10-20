from __future__ import annotations

import ctypes
import platform

import psutil


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def system_snapshot() -> dict:
    memory = psutil.virtual_memory()
    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_percent": psutil.cpu_percent(interval=None),
        "ram_percent": memory.percent,
        "ram_used_gb": round(memory.used / 1024**3, 2),
        "ram_total_gb": round(memory.total / 1024**3, 2),
        "boot_time": psutil.boot_time(),
        "administrator": is_admin(),
    }
