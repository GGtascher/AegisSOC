from __future__ import annotations

import argparse

import uvicorn

from aegis.app import create_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AegisSOC local security operations platform")
    parser.add_argument("--demo", action="store_true", help="start with safe demo controls enabled")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    app = create_app(demo_mode=args.demo)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
