# AegisSOC final test report

Test date: 20 October 2026  
Platform: Windows 11  
Project path: `E:\Програмування\Programming\AegisSOC`

## Result

The release candidate passed the functional, build and local runtime checks. AegisSOC works as a local monitoring platform and also includes a safe simulation mode for presentations. No destructive attack code is included.

## Automated checks

| Check | Result | Details |
| --- | --- | --- |
| Python tests | PASS | 15 passed |
| Frontend production build | PASS | Vite build completed, 2501 modules transformed |
| npm dependency audit | PASS | 0 known vulnerabilities |
| PyInstaller build | PASS | `dist\AegisSOC.exe`, 21,088,266 bytes |
| Frontend from EXE | PASS | HTTP 200 and the complete dashboard loaded |
| API health from EXE | PASS | status `ok`, database `ok` |

The only Python test warning comes from a deprecated Starlette test helper. It does not affect the application runtime.

## Runtime checks

The source version and the compiled EXE were tested on port 8766 because another local Python program was already using the default port 8765. The conflict belongs to the local environment, not to AegisSOC. The application still keeps 8765 as its default port.

| Area | Result | Observed result |
| --- | --- | --- |
| Health endpoint | PASS | API, database and frontend responded normally |
| Process collector | PASS | More than 400 processes collected on the test machine |
| Network collector | PASS | Connections, listeners, interfaces, gateway and DNS collected |
| Device discovery | PASS | Local ARP and neighbor information displayed |
| Security audit | PASS | 11 local checks returned; all findings on the test machine were informational |
| File integrity monitoring | PASS | Create, modify, rename and delete events stored in SQLite |
| Safe simulation | PASS | Five simulated alerts created in the intended chain |
| Correlation | PASS | One critical incident with risk 90 and five linked alerts |
| Persistence | PASS | Incident and timeline remained available after a complete restart |
| Live dashboard | PASS | WebSocket updates, charts, alert list and incident cards rendered correctly |

## File integrity test details

A harmless temporary text file was created, changed, renamed and deleted inside a temporary watched directory. The database recorded one create event, three modify observations, one move event and one delete event. The temporary directory was removed and the original monitoring settings were restored.

## Simulation details

The Safe Attack Simulation button was tested through the browser against the compiled application. The five expected stages were generated without changing system settings or executing harmful commands:

1. suspicious script execution
2. encoded command behavior
3. unusual outbound connection
4. persistence-like event
5. cleanup activity

The execution and persistence sequence correlated into a critical incident. Simulated records are clearly marked as simulated in the interface and database.

## Known environment note

At the time of testing, PID 39008 was already listening on `127.0.0.1:8765` and identified itself as another Python monitoring application. It was deliberately left untouched. Before starting AegisSOC with the default command, close the program currently using port 8765 or start AegisSOC with a different port:

```powershell
python main.py --port 8766
```

## Reproduction commands

```powershell
cd E:\Програмування\Programming\AegisSOC
.\.venv\Scripts\Activate.ps1
python -m pytest -q

cd frontend
npm run build
cd ..

python main.py --port 8766
```

For the packaged application:

```powershell
.\dist\AegisSOC.exe --port 8766
```

The web interface opens at `http://127.0.0.1:8766/` for the alternate-port commands above.
