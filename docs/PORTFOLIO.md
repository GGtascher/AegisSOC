# AegisSOC Portfolio Notes

## Project Name

AegisSOC: Local Security Operations Platform

## Short Description

A Windows 11 security monitoring application that collects endpoint, network, file, persistence, and Windows security telemetry, applies local rules, correlates alerts into incidents, and presents the result in a realtime SOC dashboard.

## One-sentence Pitch

I built a fully local SOC platform that turns ordinary Windows telemetry into explainable alerts and incident timelines without cloud services or packet-sniffing drivers.

## Three CV Bullet Points

- Built a Windows security monitoring platform with Python, FastAPI, SQLAlchemy, SQLite, React, TypeScript, and WebSockets.
- Designed fault-isolated collectors and an explainable YAML detection pipeline for processes, network activity, file changes, Windows events, and persistence.
- Implemented heuristic risk scoring, local baselines, MITRE ATT&CK mappings, safe attack simulation, and time-and-entity incident correlation.

## Five CV Bullet Points

- Developed a full-stack Windows 11 SOC dashboard using FastAPI, React, TypeScript, SQLite, and WebSockets.
- Collected live process, connection, listening port, adapter, neighbor, file, persistence, and Windows Event Log telemetry with safe permission handling.
- Created readable YAML rules and focused heuristics for suspicious PowerShell, Office-to-shell execution, temporary-path execution, startup files, and configuration changes.
- Implemented persistent baselines, normalized events, alert workflow, bounded risk scoring, and deterministic incident correlation.
- Added a non-destructive demonstration chain, Windows security posture audit, automated pytest coverage, offline runtime, and end-user documentation.

## GitHub Description

Offline Windows security monitoring, detection, audit, and incident investigation dashboard built with FastAPI, SQLite, React, and TypeScript.

## LinkedIn Project Description

AegisSOC is my local Windows security operations portfolio project. It monitors processes, network connections, listening ports, devices, selected files, startup mechanisms, and Windows security events. A central detection engine evaluates readable YAML rules, records evidence in SQLite, and correlates related alerts into investigation timelines. The React dashboard receives realtime WebSocket updates and includes a safe simulated attack chain for demonstrations. The project works without cloud services during normal operation and clearly separates suspicious behavior from confirmed compromise.

## Technology Stack

Python 3.12, FastAPI, Uvicorn, SQLAlchemy, Pydantic, SQLite, psutil, watchdog, PyYAML, pywin32, pytest, HTTPX, React, TypeScript, Vite, Recharts, and Lucide React.

## Security Concepts

- Endpoint and network telemetry
- Host-based intrusion detection
- Security posture assessment
- File integrity monitoring
- Process ancestry and command-line analysis
- Local baselining and change detection
- Detection engineering and false-positive awareness
- Alert triage and incident correlation
- MITRE ATT&CK mapping
- Least network exposure and local data handling

## Architecture Summary

Windows collectors emit normalized events. The detection engine evaluates local YAML rules and small defensive heuristics. Alerts receive confidence and risk values, then the correlation engine connects activity by time, process, user, file, host, and network entities. SQLite preserves events and analyst state. FastAPI exposes local endpoints and a WebSocket stream. A compiled React application provides the analyst interface from the same `127.0.0.1` server.
