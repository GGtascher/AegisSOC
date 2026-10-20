# AegisSOC

Local Security Operations Platform for Windows 11.

AegisSOC is a portfolio security monitoring project that combines endpoint telemetry, network visibility, file integrity monitoring, local detection rules, security posture checks, alerts, and incident correlation in one offline web application. It binds only to `127.0.0.1`, stores data in SQLite, and does not send telemetry to cloud services.

## Why I Built It

Most SOC tools are designed around server infrastructure, agents, external intelligence feeds, and large deployment budgets. AegisSOC explores the core engineering ideas on one Windows computer: collecting useful signals, normalizing them, applying explainable rules, preserving evidence, and giving an analyst a clear investigation timeline.

The project intentionally favors dependable local behavior over an inflated feature list. It does not attempt to replace an enterprise EDR platform.

## Features

- Live process inventory with parent process, user, path, command line, CPU, RAM, start time, and on-demand SHA-256
- TCP and UDP connection inventory without packet sniffing
- Listening port, network adapter, gateway, DNS, Wi-Fi, and neighbor visibility
- File integrity monitoring for selected folders with size-limited hashing
- Windows Event Log collection where permissions allow it
- Startup registry, scheduled task, and automatic service baselines
- Local Windows security audit for Defender, Firewall, UAC, RDP, SMBv1, accounts, policy, services, tasks, updates, ports, and network profile
- Readable YAML detection rules with enable and disable controls
- Heuristic risk scores, alert workflow, and incident correlation
- Safe simulated attack chain for demonstrations
- WebSocket updates and a responsive React dashboard
- SQLite persistence, event retention, rotating logs, and isolated collector failures

## Architecture

```mermaid
flowchart LR
    W[Windows 11] --> C[Collectors]
    C --> E[Normalized Events]
    E --> D[Detection Engine]
    D --> R[YAML Rules and Baselines]
    R --> A[Alerts]
    A --> I[Incident Correlation]
    I --> S[(SQLite)]
    S --> F[FastAPI]
    F --> WS[WebSocket]
    WS --> UI[React SOC Dashboard]
```

Collectors share one normalized event structure. The detection engine evaluates local rules and focused behavior checks. Related alerts are grouped by time and entities such as PID, user, path, IP, and correlation ID. FastAPI serves both the API and compiled frontend.

## Endpoint Monitoring

The process collector uses `psutil` and safely handles disappearing or protected processes. Existing processes form the initial runtime baseline. Later starts and stops become events. Detection logic looks for suspicious PowerShell command fragments, Office-to-shell parent relationships, long PowerShell commands, and execution from temporary folders. These are indicators for review, not malware verdicts.

Executable hashes are calculated only on demand and cached by path, modification time, and size. Files over the configured limit are skipped.

## Network Monitoring

AegisSOC does not sniff packets or store payloads. It uses `psutil.net_connections()` plus built-in Windows commands such as `Get-NetIPConfiguration`, `Get-NetNeighbor`, `netsh wlan`, and `arp -a`. The dashboard presents connections, listeners, interfaces, addresses, DNS, gateway information, and nearby devices.

Gateway MAC and DNS changes are compared with their local baselines. A changed gateway MAC produces a high-priority warning because it can result from ARP spoofing, MITM activity, or a legitimate router change. The alert states this uncertainty directly.

## File Integrity Monitoring

`watchdog` observes Desktop, Documents, and the current user's Startup folder by default when those folders exist. Custom paths can be changed on the Settings page. Creation, modification, deletion, and move events are recorded. New script or executable files in Startup or temporary locations receive extra attention.

The whole `C:\` drive is not monitored by default. Broad recursive monitoring creates noise and can harm performance.

## Windows Security Audit

Run the Quick Audit from the Security Audit page. It gathers local configuration and returns findings with severity, details, and a recommendation. The audit never changes a setting. Standard-user mode still works, although some Security log, account, service, task, and connection details may be incomplete.

## Detection Engine

Every collector emits the same basic envelope:

```json
{
  "timestamp": "2026-10-20T10:41:03Z",
  "source": "endpoint",
  "category": "endpoint",
  "event_type": "process_start",
  "host": "WORKSTATION",
  "data": {}
}
```

The central engine stores the event, evaluates rules, creates alerts, asks the correlation engine to connect related activity, and publishes an update to WebSocket clients. A collector exception is logged and does not terminate the application.

## YAML Rules

Rules live in `rules/endpoint.yaml`, `rules/network.yaml`, `rules/files.yaml`, and `rules/windows.yaml`. The language stays deliberately small. It supports event type, process name, command fragments, file extensions, severity, description, recommendation, and an optional MITRE mapping. Rule state is stored in SQLite so a disabled rule remains disabled after restart.

## Incident Correlation

Correlation uses a ten-minute window and shared entities such as PID, parent PID, user, file, path, remote IP, host, or a demonstration correlation ID. Three or more related alerts form an incident. This is explainable deterministic logic, not machine learning.

## MITRE ATT&CK

Selected detections use local MITRE technique identifiers, including PowerShell `T1059.001`, Boot or Logon Autostart `T1547`, Windows Service `T1543.003`, Network Service Discovery `T1046`, and Brute Force `T1110`. Mapping is used only where it adds investigation context.

## Risk Scoring

Severity weights are INFO 0, LOW 5, MEDIUM 15, HIGH 30, and CRITICAL 50. Alert risk also considers confidence. System risk uses a saturating curve, so several small findings increase the score without allowing a raw sum to grow past 100. The result is a heuristic prioritization aid and does not prove compromise.

## Safe Demo Mode

Start with:

```powershell
python main.py --demo
```

Press **Safe Attack Simulation** to generate five clearly marked `SIMULATED` stages at short intervals: Office-to-PowerShell execution, encoded PowerShell, an external connection, an executable in Temp, and startup persistence. No malicious command, payload, registry edit, or outbound request is performed. The stages are stored, streamed to the interface, and correlated into a critical incident.

## Technology Stack

- Python 3.12, FastAPI, SQLAlchemy, Pydantic, Uvicorn
- psutil, watchdog, PyYAML, pywin32
- SQLite with WAL mode, foreign keys, and busy timeout
- React, TypeScript, Vite, Recharts, Lucide React
- pytest and HTTPX

## Installation

Requirements: Windows 11, Python 3.12 or newer, and Node.js with npm for the first frontend build.

```powershell
cd "PATH"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
```

The application itself runs offline after dependencies are installed.

## Usage

```powershell
cd "PATH"
.\.venv\Scripts\Activate.ps1
python main.py
```

Open `http://127.0.0.1:8765`. The final build does not require a separate Vite process. `run.bat` starts the same local server.

## Administrator Mode

AegisSOC detects whether it has elevated privileges. Standard mode covers ordinary process, file, network, database, rule, alert, and demo workflows. Administrator mode can improve Security Event Log access, process ownership and command-line coverage, connection-to-process attribution, local account data, scheduled tasks, services, Defender status, and audit completeness.

Running as Administrator increases visibility but also increases the impact of a software defect. Review the source and use elevation only when the additional telemetry is needed.

## Testing

```powershell
cd "Path"
.\.venv\Scripts\Activate.ps1
python -m pytest -q
cd frontend
npm run build
```

The test suite covers database initialization, alert state, scoring, YAML loading, process detections, network helpers, gateway and DNS change logic, correlation, audit storage, safe demo behavior, and API health.

## Project Structure

```text
AegisSOC/
|-- main.py
|-- aegis/
|   |-- collectors/
|   |-- detection/
|   |-- audit/
|   |-- database/
|   `-- api/
|-- rules/
|-- frontend/
|-- tests/
|-- docs/
|-- data/
`-- logs/
```

## Security

- The server binds to `127.0.0.1`, never `0.0.0.0` by default.
- No authentication is included because this is a local, single-user application.
- No external API, cloud database, or threat-intelligence service is used.
- File contents, passwords, and private document contents are not written to logs.
- The demonstration does not execute attack commands.
- Runtime databases, logs, environments, build output, and secrets are excluded from Git.

If the bind address is changed or the app is placed behind a proxy, authentication, TLS, CSRF controls, and access logging must be designed before other users are allowed to connect.

## Limitations

AegisSOC is a portfolio security monitoring platform. It is not an enterprise EDR replacement. It does not perform full packet inspection and cannot inspect encrypted network payloads. It does not guarantee malware detection. Heuristics can create false positives. Windows privileges can limit telemetry. No cloud threat intelligence is used.

Other practical limits:

- Process and connection monitoring is polling-based, so very short activity can be missed.
- The baseline is local and does not understand organization-wide policy.
- Event Log support focuses on a small set of meaningful IDs.
- Device vendors remain `Unknown` because online and bundled vendor lookups are intentionally absent.
- Incident correlation uses simple entity and time rules.

## Roadmap

- Signed local rule packs with version history
- Better Windows Event XML parsing and bookmarks
- Import and export of investigation bundles
- Optional local-only notification rules
- UI pagination for long-running installations
- MSI or signed installer after source behavior is stable

## License

MIT. See [LICENSE](LICENSE).
