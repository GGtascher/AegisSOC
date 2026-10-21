# AegisSOC Final Test Report

Test date: 20 October 2026  
Platform: Windows 11

## Result

The release candidate passed the functional, build, and local runtime checks performed during final verification.

AegisSOC operated successfully as a local Windows security monitoring platform, including its non-destructive simulation workflow.

No destructive attack code is included in the project.

## Automated Checks

| Check | Result | Details |
| --- | --- | --- |
| Python tests | PASS | 15 tests passed |
| Frontend production build | PASS | Vite production build completed successfully |
| npm dependency audit | PASS | 0 known vulnerabilities reported during testing |
| PyInstaller build | PASS | Standalone executable built successfully |
| Frontend from executable | PASS | Dashboard loaded successfully |
| API health from executable | PASS | Application and database reported healthy status |

The Python test suite produced one warning related to a deprecated third-party Starlette test helper. It did not affect application runtime or test completion.

## Runtime Checks

The source version and compiled executable were tested successfully.

An alternate local port was used during part of the test because the default port was already occupied by another local application.

AegisSOC continues to use port `8765` by default.

| Area | Result | Observed Result |
| --- | --- | --- |
| Health endpoint | PASS | API, database, and frontend responded normally |
| Process collector | PASS | Live process information was collected |
| Network collector | PASS | Connections, listeners, interfaces, gateway, and DNS information were collected |
| Device discovery | PASS | Local ARP and neighbor information was displayed |
| Security audit | PASS | Local security checks completed successfully |
| File integrity monitoring | PASS | Create, modify, move, and delete activity was recorded |
| Safe simulation | PASS | Five simulated alerts were created in the intended sequence |
| Correlation | PASS | Related simulated alerts were grouped into a critical incident |
| Persistence | PASS | Incident and timeline information remained available after restart |
| Live dashboard | PASS | WebSocket updates, charts, alerts, and incident views rendered correctly |

## File Integrity Monitoring Test

A harmless temporary text file was created inside a temporary monitored directory.

The test included:

1. file creation;
2. modification;
3. rename;
4. deletion.

AegisSOC recorded the resulting file activity in SQLite.

The temporary test directory was removed after verification and the original monitoring configuration was restored.

## Safe Simulation Test

The Safe Attack Simulation workflow was tested through the web interface.

The expected simulated stages were generated without modifying system security settings or executing malicious commands:

1. suspicious script execution;
2. encoded-command behavior;
3. unusual outbound connection;
4. persistence-like activity;
5. cleanup activity.

The generated records were clearly marked as simulated.

Related alerts were successfully correlated into an incident.

## Alternate Port Test

If the default port is already occupied, AegisSOC can be started on another local port:

```powershell
python main.py --port 8766
```

The dashboard is then available at:

```text
http://127.0.0.1:8766
```

## Reproduction Commands

From the AegisSOC project root:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

Build the frontend:

```powershell
cd frontend
npm run build
cd ..
```

Start the application:

```powershell
python main.py
```

Or use an alternate port:

```powershell
python main.py --port 8766
```

For a previously built standalone executable:

```powershell
.\dist\AegisSOC.exe --port 8766
```

## Notes

Runtime results can vary depending on:

- Windows permissions;
- available network interfaces;
- current system activity;
- Event Log access;
- Administrator privileges.

AegisSOC is a portfolio security monitoring platform and not an enterprise EDR replacement.
