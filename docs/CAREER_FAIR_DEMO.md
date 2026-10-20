# AegisSOC Career Fair Demo

## 30-second Pitch

"AegisSOC is a local Windows security operations platform I built with Python, FastAPI, SQLite, React, and TypeScript. It collects live endpoint and network telemetry, watches selected files and persistence locations, applies readable detection rules, and correlates alerts into investigation timelines. Everything runs on the laptop without cloud services, and the demo uses only simulated events."

## Two-minute Demo

1. Open the Dashboard. Point to live process and connection counts, local database status, and the `Internet Not Required` indicator.
2. Open Endpoint. Show process name, PID, parent, user, resource use, path, command line, and on-demand hashing.
3. Open Network. Show current interfaces, gateway, DNS, devices, connections, and listeners. Explain that no payload is captured.
4. Open Security Audit and run Quick Audit. Show that it checks Windows configuration without changing it.
5. Press Safe Attack Simulation. Explain that no malicious command runs.
6. Watch the simulated alerts arrive through WebSocket updates.
7. Open the critical incident. Show the ordered timeline, shared process entities, and MITRE techniques.
8. Open Rules. Show a readable YAML-backed detection and its persistent enable switch.

## Five-minute Demo

Start with the two-minute sequence, then add:

1. Pause and resume monitoring to demonstrate operational control.
2. Open a process detail and calculate its SHA-256. Explain the size limit and cache.
3. Explain the initial baseline for processes, ports, devices, gateway, DNS, and persistence entries.
4. Show alert states: New, Investigating, Resolved, and False Positive.
5. Open Timeline and filter events by category and severity.
6. Show `rules/endpoint.yaml` and walk through one PowerShell rule.
7. Explain that each collector is fault-isolated, so a denied Security log or missing Wi-Fi adapter does not terminate the application.
8. Close with limitations: polling can miss short events, there is no packet inspection, and a heuristic is not proof of compromise.

## Possible Employer Questions and Good Answers

### Why not use Scapy, Npcap, or an EDR driver?

The target is a dependable student portfolio application that works on an ordinary Windows 11 computer. I chose supported user-space sources and accepted reduced visibility. That tradeoff keeps installation simple and avoids pretending this is an enterprise sensor.

### How do you prevent false claims about malware?

Alerts say that suspicious behavior was detected. Evidence and recommendations are visible, and the documentation states that heuristics can produce false positives. Analysts can mark an alert as False Positive.

### How does correlation work?

It uses a fixed time window plus shared entities such as PID, parent PID, user, file path, remote IP, host, or simulation correlation ID. Three related alerts produce an incident. It is deterministic and explainable.

### How is risk calculated?

Severity has a base weight and confidence affects alert risk. System risk uses a saturating curve. This avoids presenting a raw sum that quickly becomes meaningless. Risk is for prioritization only.

### What happens when a collector fails?

The collection loop catches errors per collector, stores a short health message, logs the problem, and continues running the other collectors. Expected access errors are handled near the source.

### What data leaves the machine?

None during normal runtime. AegisSOC has no cloud API integration and binds to localhost. Dependency installation and a developer's Git push are separate setup activities.

### What would you change for production?

I would add authenticated agents, signed updates and rules, certificate-based transport, tamper protection, proper Event Log bookmarks, a migration framework, stronger query pagination, tenant separation, central retention policy, and signed installers.

### Why SQLite?

It matches a local single-user product and removes an external service dependency. WAL mode and a busy timeout improve concurrent reads. A larger deployment would need a central database and a different ingestion architecture.

## Technical Architecture Explanation

Collectors produce one event format rather than writing custom data directly into UI-specific tables. The detection engine owns alert creation. The correlation engine owns incidents. SQLAlchemy provides storage boundaries. FastAPI exposes read and state-change endpoints. WebSocket messages tell the frontend when to refresh. The compiled frontend is served by the same process, so the final run command stays simple.

## Security Design Explanation

- Server exposure is limited to `127.0.0.1`.
- The runtime has no external API calls.
- The demonstration stores fictional documentation IP ranges and does not execute commands.
- Logs exclude file contents and secrets.
- Monitored folders are intentionally narrow by default.
- Hashing is size-limited and cached.
- UI wording separates an indicator from a confirmed incident.
- Standard-user operation is supported, while the privilege limitation remains visible.

## Known Limitations

- Polling can miss processes or connections that exist for less than one interval.
- Some Windows telemetry requires Administrator privileges.
- A local baseline can treat legitimate change as suspicious.
- There is no packet payload capture or encrypted traffic inspection.
- There is no cloud threat intelligence or online reputation lookup.
- The incident engine is intentionally simple and does not use machine learning.
