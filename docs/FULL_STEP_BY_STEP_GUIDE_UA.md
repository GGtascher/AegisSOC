# AegisSOC: повний покроковий посібник

Цей документ розрахований на людину, яка тільки починає працювати з Python, Windows, Git та інструментами кібербезпеки. Усі команди нижче виконуються у PowerShell, якщо явно не вказано інше.

## 1. Що це за проєкт

AegisSOC є локальною платформою моніторингу безпеки для Windows 11. Вона дивиться на процеси, мережеві з'єднання, відкриті порти, пристрої в локальній мережі, зміни вибраних файлів, механізми автозапуску та доступні Windows events. Інформація потрапляє у локальну базу SQLite. Detection engine перетворює підозрілі події на alerts, а correlation engine збирає пов'язані alerts в incidents.

### Основні терміни

**IDS, Intrusion Detection System**: система виявлення ознак небажаної або підозрілої активності. IDS повідомляє про ознаку, але сама ознака ще не є доказом атаки.

**HIDS, Host-based IDS**: IDS, яка працює на конкретному комп'ютері та аналізує його локальні події, процеси, файли й налаштування.

**SOC, Security Operations Center**: команда та набір процесів для спостереження за безпекою, перевірки alerts і реагування на incidents. У цьому проєкті слово SOC означає локальний навчальний інтерфейс для такого робочого процесу.

**Endpoint telemetry**: технічні дані з комп'ютера. Наприклад, процес запустився, PowerShell отримав певний command line, файл з'явився у Startup.

**Network telemetry**: інформація про мережеві інтерфейси, адреси, connections, listening ports, gateway, DNS і сусідні пристрої. AegisSOC не зчитує payload пакетів.

**Alert**: структуроване попередження. Воно має severity, risk, confidence, evidence, recommendation та status.

**Incident**: група alerts, які можуть описувати одну історію. Наприклад, запуск PowerShell, мережеве з'єднання і новий запис автозапуску з одним PID протягом десяти хвилин.

**Baseline**: збережений стан, який вважається початковим. Перший список портів, DNS, gateway MAC або startup entries стає точкою порівняння для наступних запусків.

**Detection rule**: зрозуміле правило, яке описує умову та результат. Наприклад: якщо процес `powershell.exe` містить `-EncodedCommand`, створи HIGH alert.

**MITRE ATT&CK**: публічна база тактик і технік, які використовують під час атак. AegisSOC зберігає тільки локальні technique IDs для доречних detections. Він не звертається до MITRE API.

## 2. Точні шляхи та призначення папок

Корінь проєкту:

```text
E:\Програмування\Programming\AegisSOC
```

Основні файли:

- `E:\Програмування\Programming\AegisSOC\main.py`: точка запуску. Читає параметр `--demo`, створює FastAPI app і запускає Uvicorn тільки на `127.0.0.1:8765`.
- `E:\Програмування\Programming\AegisSOC\requirements.txt`: точні Python dependencies.
- `E:\Програмування\Programming\AegisSOC\run.bat`: простий запуск через локальну `.venv`.
- `E:\Програмування\Programming\AegisSOC\build.bat`: створення `.venv`, встановлення dependencies та frontend build.
- `E:\Програмування\Programming\AegisSOC\README.md`: технічний опис англійською.
- `E:\Програмування\Programming\AegisSOC\.gitignore`: перелік локальних файлів, які Git не повинен завантажувати.

Папки:

- `aegis\`: Python backend.
- `aegis\collectors\`: process, network, device, file, persistence, Windows events і system collectors.
- `aegis\detection\`: rules loader, scoring, baseline, detection та correlation logic.
- `aegis\audit\`: Windows Quick Audit.
- `aegis\database\`: SQLAlchemy models і SQLite session management.
- `aegis\api\`: HTTP routes та WebSocket.
- `rules\`: YAML detection rules.
- `frontend\`: React, TypeScript і Vite source.
- `frontend\dist\`: compiled frontend. FastAPI віддає саме цю папку.
- `data\`: runtime database.
- `logs\`: runtime log.
- `tests\`: pytest tests.
- `docs\`: цей посібник, portfolio notes, demo script і final test report.

## 3. Перший запуск

Відкрийте PowerShell і виконайте:

```powershell
cd "E:\Програмування\Programming\AegisSOC"
.\.venv\Scripts\Activate.ps1
python main.py
```

`cd` змінює поточну папку на корінь AegisSOC. Подвійні лапки потрібні через кирилицю та можливі пробіли у шляху.

`.\.venv\Scripts\Activate.ps1` активує окреме Python environment цього проєкту. Після активації на початку рядка PowerShell зазвичай видно `(.venv)`.

`python main.py` запускає backend, collectors і compiled frontend. Залиште це вікно відкритим. У браузері відкрийте:

```text
http://127.0.0.1:8765
```

Для зупинки поверніться у PowerShell і натисніть `Ctrl+C` один раз.

## 4. Якщо `.venv` не активується

PowerShell може показати повідомлення про заборону виконання scripts. Дозвольте scripts тільки у поточному вікні:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

`-Scope Process` є важливим. Налаштування зникне після закриття PowerShell і не змінить постійну системну policy.

Якщо `.venv` ще не існує:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## 5. Administrator mode

1. Натисніть Windows Search.
2. Введіть `PowerShell`.
3. Натисніть правою кнопкою на Windows PowerShell.
4. Оберіть `Run as Administrator`.
5. Підтвердьте UAC prompt.
6. Виконайте:

```powershell
cd "E:\Програмування\Programming\AegisSOC"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python main.py
```

Administrator mode може дати більше даних з Security Event Log, Defender, local users, services, scheduled tasks, чужих process command lines та connection ownership. Standard User mode залишається робочим. Права адміністратора не роблять detections точнішими автоматично, вони лише розширюють доступну telemetry.

## 6. Dashboard

Верхня смуга показує:

- `SYSTEM ONLINE`: backend відповідає.
- `MONITORING ACTIVE` або `PAUSED`: collectors працюють або призупинені.
- `DATABASE LOCAL`: дані зберігаються на цьому комп'ютері.
- `CLOUD NOT REQUIRED`: cloud services не використовуються.
- `INTERNET NOT REQUIRED`: після installation normal runtime працює offline.

`System Risk` має діапазон від 0 до 100. Він використовує активні alerts і saturating formula. Це heuristic priority, а не доказ compromise.

Cards:

- `Active Alerts`: NEW та INVESTIGATING alerts.
- `Critical Alerts`: активні CRITICAL alerts.
- `Incidents`: відкриті correlated incidents.
- `Processes`: поточна кількість видимих процесів.
- `Connections`: поточні TCP та UDP endpoints.
- `Network Devices`: пристрої, відомі neighbor collector.
- `Security Findings`: відкриті результати останнього audit.

Charts показують alerts по часу та severity. `Recent Alerts` і `Recent Incidents` дають швидкий перехід до останньої активності. Кнопка `Pause` зупиняє polling, але UI та API лишаються доступними. `Resume` відновлює collectors.

## 7. Endpoint

Process table має такі поля:

- `Name`: ім'я executable, наприклад `explorer.exe`.
- `PID`: Process Identifier, унікальне число для конкретного запущеного process.
- `PPID`: PID parent process.
- `Parent`: ім'я програми, яка створила process.
- `User`: Windows account, від якого process працює.
- `CPU`: недавнє завантаження CPU.
- `RAM`: physical memory process у MB.
- `Path`: повний шлях executable.
- `Command line`: команда та arguments запуску.
- `Start time`: час створення process.
- `SHA-256`: cryptographic hash executable, який обчислюється на вимогу.

Parent-child relationship корисний, бо контекст змінює оцінку. `powershell.exe`, запущений адміністратором вручну, може бути нормальним. Той самий process від `WINWORD.EXE` потребує перевірки, тому що Office document рідко має запускати command shell.

Hash не доводить, що файл безпечний або небезпечний. Він дає стабільний identifier для порівняння. AegisSOC не надсилає hash онлайн.

## 8. Network

- `IP`: логічна IPv4 або IPv6 address.
- `MAC`: link-layer address мережевого adapter або neighbor.
- `Gateway`: router address, через який іде traffic до інших networks.
- `DNS`: сервер, який перетворює domain names на IP addresses.
- `TCP`: connection-oriented protocol зі states на кшталт LISTEN та ESTABLISHED.
- `UDP`: connectionless protocol. Для нього remote endpoint або state може бути відсутнім.
- `Listening Port`: local port, на якому program очікує нові connections.
- `Connection`: local endpoint, optional remote endpoint, protocol, state, PID та process.
- `SSID`: назва Wi-Fi network.
- `BSSID`: MAC address Wi-Fi access point.

Під час першого collection наявні devices та listening ports стають baseline. Якщо пізніше з'явиться новий device, AegisSOC створить LOW alert. Vendor залишається `Unknown`, бо online lookup заборонений.

Gateway baseline зберігає gateway IP та MAC. Якщо IP лишився той самий, а MAC змінився, створюється CRITICAL alert. Причиною може бути ARP spoofing, але також заміна router або network change. Спочатку звірте MAC з router management page.

DNS change створює MEDIUM alert. Це може бути VPN, DHCP, нова network або небажана configuration change.

## 9. File Integrity Monitoring

Default paths:

- Desktop поточного user.
- Documents поточного user.
- Windows Startup folder поточного user.

Recorded operations:

- `Created`: file з'явився.
- `Modified`: file content або metadata змінилися.
- `Deleted`: file видалено.
- `Moved`: file перенесено або перейменовано.
- `SHA-256`: hash нового або зміненого file, якщо він не більший за configured maximum.

Щоб додати custom folder:

1. Відкрийте Settings.
2. У `File integrity monitoring paths` додайте абсолютний шлях окремим рядком.
3. Натисніть `Save settings`.
4. Переконайтеся, що folder існує і доступний.

Не додавайте весь `C:\`. Windows постійно змінює тисячі files, тому з'явиться шум і додаткове навантаження.

## 10. Alerts

Severity levels:

- `INFO`: контекст або inventory, який не означає risk.
- `LOW`: невелика зміна, яку бажано підтвердити.
- `MEDIUM`: activity потребує перевірки.
- `HIGH`: сильна підозріла ознака або небезпечна configuration.
- `CRITICAL`: найвищий local priority, наприклад gateway MAC change або завершений simulated chain.

Fields:

- `Risk`: нормалізований score конкретного alert.
- `Confidence`: наскільки умова rule відповідає evidence. Це не ймовірність атаки.
- `Evidence`: фактичні поля event, наприклад PID, path або remote IP.
- `Recommendation`: наступна безпечна дія analyst.
- `MITRE`: technique ID, якщо mapping доречний.

Statuses:

- `NEW`: alert ще не переглянули.
- `INVESTIGATING`: analyst почав перевірку.
- `RESOLVED`: перевірку завершено та alert закрито.
- `FALSE_POSITIVE`: activity визнана нормальною для цього environment.

Натисніть рядок alert, прочитайте description та evidence, після цього змініть status кнопкою в detail dialog.

## 11. Incidents

Correlation engine дивиться на alerts у короткому time window та порівнює PID, PPID, user, file, path, remote IP, host і correlation ID. Після трьох related alerts формується incident. Safe demo використовує окремий correlation ID, тому його п'ять етапів стабільно потрапляють в одну історію.

Incident detail показує:

- ID, title, severity, risk і status.
- Entities, що повторюються у evidence.
- Alerts у правильному часовому порядку.
- Timeline.
- MITRE techniques.
- Recommended investigation steps.

Practical investigation flow:

1. Перевірте user та process tree.
2. Звірте timestamps.
3. Перевірте executable path і hash.
4. Перегляньте remote IP та port.
5. Перевірте file і persistence evidence.
6. Відокремте legitimate administration від unexpected activity.
7. Лише після підтвердження плануйте containment.

## 12. Quick Audit

`Run Quick Audit` нічого не змінює. Він читає configuration і створює findings.

- `Defender`: чи увімкнений antivirus і realtime protection.
- `Firewall`: чи active Domain, Private і Public profiles.
- `UAC`: чи працює User Account Control.
- `RDP`: чи дозволені Remote Desktop connections.
- `SMB`: чи enabled legacy SMBv1 server protocol.
- `Network Profile`: Public або Private category.
- `Ports`: кількість TCP listeners.
- `Startup`: persistence collector окремо inventory registry entries.
- `Services`: automatic services count та baseline.
- `Scheduled Tasks`: enabled task count та baseline.
- `Password Policy`: результат локальної `net accounts` команди.
- `Local Administrators`: members групи Administrators, якщо доступні.
- `Windows Update`: latest visible hotfix.

`Unavailable` не означає failure самої програми. Часто це permission або відсутність конкретного Windows component.

## 13. YAML Rules

Endpoint rules:

```text
E:\Програмування\Programming\AegisSOC\rules\endpoint.yaml
```

Безпечний приклад:

```yaml
- id: ENDPOINT-LOCAL-001
  name: PowerShell Uses a Local Test Marker
  category: endpoint
  severity: LOW
  process_name: powershell.exe
  command_contains:
    - "aegis-local-test"
  description: A local test marker appeared in a PowerShell command.
  recommendation: Confirm that the test was expected.
  mitre:
    technique: T1059.001
    name: PowerShell
    tactic: Execution
```

Fields:

- `id`: унікальний stable identifier.
- `name`: короткий detection title.
- `category`: endpoint, network, file або windows.
- `severity`: INFO, LOW, MEDIUM, HIGH або CRITICAL.
- `process_name`: optional exact executable name у lowercase comparison.
- `command_contains`: список fragments. Достатньо одного match.
- `event_type`: optional event type filter.
- `extensions`: optional file extensions.
- `description`: що саме знайшло rule.
- `recommendation`: що перевірити.
- `mitre`: optional technique metadata.

Щоб додати rule, збережіть valid YAML і перезапустіть AegisSOC. Спочатку використовуйте LOW severity та test marker, щоб перевірити behavior без зайвого шуму.

Щоб вимкнути rule, відкрийте Rules і натисніть toggle. State збережеться у SQLite. YAML file не змінюється.

## 14. Demo mode

Запуск:

```powershell
cd "E:\Програмування\Programming\AegisSOC"
.\.venv\Scripts\Activate.ps1
python main.py --demo
```

Натисніть `Safe Attack Simulation`. Кожні приблизно 1.2 секунди з'являться:

1. Simulated Office document launched PowerShell.
2. Simulated encoded PowerShell detection.
3. Simulated external connection до documentation IP `203.0.113.42`.
4. Simulated executable in Temp.
5. Simulated Startup persistence entry.

Усі records мають marker `SIMULATED`. Програма не запускає PowerShell attack, не створює executable, не змінює Registry і не робить external connection. Вона лише записує harmless fictional events у власну database.

## 15. Career fair demo

### План на дві хвилини

1. Відкрийте Dashboard і покажіть `SYSTEM ONLINE`, local database та live process count.
2. Відкрийте Network і покажіть connections без packet payload.
3. Запустіть Quick Audit.
4. Натисніть Safe Attack Simulation.
5. Дочекайтеся alerts.
6. Відкрийте Critical Incident.
7. Покажіть timeline та MITRE mappings.
8. Відкрийте Rules і покажіть readable YAML concept.
9. Поясніть architecture від collector до React dashboard.

### Короткий English script

"This is AegisSOC, a local Windows security operations platform I built with FastAPI, SQLite, React, and TypeScript. It collects live process and network telemetry, monitors selected files and persistence locations, and applies readable local detection rules. Related alerts are correlated into an incident timeline. The application works offline and binds only to localhost. This attack chain is fully simulated, so no malicious command or network request is performed."

Повніший сценарій та відповіді на питання роботодавця є у `docs\CAREER_FAIR_DEMO.md`.

## 16. Database

Точний runtime path:

```text
E:\Програмування\Programming\AegisSOC\data\aegissoc.db
```

SQLite зберігає всю database в одному основному file. Поруч під час роботи можуть з'являтися `aegissoc.db-wal` і `aegissoc.db-shm`. Це нормально для WAL mode.

Зберігаються normalized events, alerts, incidents, links між incidents та alerts, devices, baselines, audit findings, settings і states правил.

### Backup

1. Зупиніть AegisSOC через `Ctrl+C`.
2. Скопіюйте `data\aegissoc.db` у безпечну local folder.
3. Не копіюйте database під час активного запису, якщо не використовуєте SQLite backup tool.

### Безпечний reset development database

1. Зупиніть AegisSOC.
2. Перейменуйте `data\aegissoc.db` на `data\aegissoc.backup.db`.
3. Так само перемістіть `-wal` та `-shm`, якщо вони лишилися.
4. Запустіть `python main.py`.

Нова database створиться автоматично. Старий file лишається backup. Не робіть reset, якщо потрібна incident history.

## 17. Logs

Точний шлях:

```text
E:\Програмування\Programming\AegisSOC\logs\aegissoc.log
```

Log містить startup, shutdown, collector failures, database transaction failures, monitoring state та internal warnings. Він не повинен містити file contents, passwords або private document contents. Rotating handler обмежує розмір і залишає кілька попередніх files.

## 18. Troubleshooting

### `python` not found

Встановіть Python 3.12 або новіший з python.org або Microsoft Store. Під час installer увімкніть `Add Python to PATH`. Закрийте та відкрийте PowerShell, потім перевірте `python --version`.

### Pip problem

Використовуйте `python -m pip`, а не окремий `pip`:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Venv problem

Видаліть пошкоджену `.venv` тільки після перевірки, що це саме folder проєкту, потім створіть її знову:

```powershell
python -m venv .venv
```

### PowerShell execution policy

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### `npm` not found

Встановіть current Node.js LTS, відкрийте новий PowerShell і перевірте `node --version` та `npm --version`.

### `npm install` failure

Перевірте internet connection під час installation, вільне місце і proxy settings. Потім у `frontend` повторіть:

```powershell
npm install
```

Normal runtime internet не потребує.

### Frontend build error

```powershell
cd "E:\Програмування\Programming\AegisSOC\frontend"
npm install
npm run build
```

Прочитайте перший TypeScript error. Не видаляйте `package-lock.json` без конкретної причини.

### Port 8765 occupied

Знайдіть process:

```powershell
Get-NetTCPConnection -LocalPort 8765 -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,State,OwningProcess
```

Після перевірки PID закрийте старий AegisSOC через його PowerShell window. Можна тимчасово запустити `python main.py --port 8766`, але compiled frontend очікує той самий host і працюватиме на новому port, якщо відкрити його вручну.

### AccessDenied

Це нормальна Windows boundary. Спробуйте Administrator mode. Якщо application не падає і показує limited telemetry, handling працює правильно.

### Standard User vs Administrator

Standard mode безпечніший для повсякденної demo. Administrator mode потрібен лише для повнішого Security log, account, process і connection visibility.

### Database locked

Переконайтеся, що запущений один AegisSOC process. Зупиніть duplicate instance, зачекайте кілька секунд і запустіть знову. SQLite має 15-second busy timeout та WAL mode.

### Windows Event Log unavailable

Запустіть як Administrator. Переконайтеся, що relevant event channel існує. AegisSOC продовжить роботу з іншими collectors.

### Wi-Fi data unavailable

`netsh wlan show interfaces` нічого не повертає, якщо немає Wi-Fi adapter, adapter disabled або connection відсутній. Ethernet telemetry працюватиме окремо.

### Network disconnected

Порожні connections або gateway є нормальними. Після підключення collector оновить дані під час наступного interval.

### Blank frontend

Перевірте, чи існує `frontend\dist\index.html`. Якщо ні, виконайте `npm run build`. Потім перезапустіть backend і зробіть hard refresh у browser через `Ctrl+F5`.

### API not responding

Відкрийте `http://127.0.0.1:8765/api/health`. Подивіться PowerShell output та `logs\aegissoc.log`. Перевірте port і firewall. AegisSOC навмисно не доступний через LAN IP.

## 19. Tests

Python tests:

```powershell
cd "E:\Програмування\Programming\AegisSOC"
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

Очікуваний результат: усі tests мають status passed. Warning може описувати third-party package і не завжди означає failure.

Frontend build:

```powershell
cd "E:\Програмування\Programming\AegisSOC\frontend"
npm run build
```

Очікуваний результат: Vite створить `frontend\dist` та повідомить build time. TypeScript errors мають бути виправлені до використання.

Manual health test:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/health | ConvertTo-Json
```

Очікуйте `status: ok`, `database: ok`, monitoring state та live або demo mode.

## 20. Build і EXE mode

Source mode є основним і найнадійнішим:

```powershell
python main.py
```

PyInstaller build, якщо він був успішно створений, розташований тут:

```text
E:\Програмування\Programming\AegisSOC\dist\AegisSOC.exe
```

EXE все одно потребує bundled frontend assets і writable `data` та `logs` folders. Дивіться фактичний status у `docs\FINAL_TEST_REPORT.md`. Якщо EXE має LIMITED або FAIL, використовуйте source mode.

## 21. GitHub для початківця

### Перед початком

Створіть account на github.com. Встановіть Git for Windows. У GitHub натисніть `New repository`, введіть `AegisSOC`, додайте description, оберіть Public для portfolio або Private для непублічної роботи. Не додавайте README, license чи `.gitignore` через сайт, бо вони вже є локально.

Відкрийте PowerShell:

```powershell
cd "E:\Програмування\Programming\AegisSOC"
git init
git status
git add .
git status
git commit -m "Initial AegisSOC release"
git branch -M main
git remote add origin https://github.com/YOUR-NAME/AegisSOC.git
git push -u origin main
```

Пояснення:

- `git init`: створює local repository metadata у `.git`.
- `git status`: показує files та staged state.
- `git add .`: додає files до наступного commit з урахуванням `.gitignore`.
- другий `git status`: обов'язкова перевірка перед commit.
- `git commit`: створює local snapshot.
- `git branch -M main`: називає основну branch `main`.
- `git remote add origin`: пов'язує local repo з GitHub URL.
- `git push -u origin main`: завантажує commit і запам'ятовує upstream.

GitHub може попросити sign-in через browser. Password account не використовується як Git password. Git Credential Manager відкриє authorization flow.

`.gitignore` виключає:

```text
.venv/
frontend/node_modules/
data/*.db
logs/
__pycache__/
.pytest_cache/
dist/
build/
.env
```

Не завантажуйте API keys, passwords, tokens, personal databases, logs, `.env`, private files або screenshots з sensitive information. Перед кожним push виконуйте `git status` і переглядайте staged files через `git diff --cached --stat`.

Наступні зміни:

```powershell
git status
git add .
git commit -m "Improve network collector error handling"
git push
```

Commit message має коротко описувати реальну зміну.

## 22. Повний потік architecture

```text
Windows
  -> Collectors
  -> Normalized Events
  -> Detection Engine
  -> Rules and Baselines
  -> Alerts
  -> Correlation
  -> Incidents
  -> SQLite
  -> FastAPI
  -> WebSocket
  -> React Dashboard
```

1. **Windows** є source system.
2. **Collectors** читають доступні process, connection, adapter, file, persistence, audit та event log data.
3. **Normalized Events** дають усім sources однаковий envelope.
4. **Detection Engine** приймає event і вирішує, чи треба alert.
5. **Rules and Baselines** описують підозрілі patterns та попередній normal state.
6. **Alerts** містять evidence, severity, confidence та recommendation.
7. **Correlation** шукає alerts, пов'язані часом і entities.
8. **Incidents** показують повну investigation story.
9. **SQLite** зберігає history та analyst state між restarts.
10. **FastAPI** повертає data через local HTTP API.
11. **WebSocket** повідомляє browser про нову activity без manual refresh.
12. **React Dashboard** показує data, filters, details, workflow actions та demo.

## Підсумок безпеки

AegisSOC допомагає побачити й пояснити локальну activity. Він не доводить compromise, не замінює antivirus або EDR і не повинен використовуватися як єдиний security control. Найцінніша частина проєкту для навчання: зв'язок між raw telemetry, detection logic, evidence, analyst decision та honest limitations.
