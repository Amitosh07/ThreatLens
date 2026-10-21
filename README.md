# ThreatLens

ThreatLens is a local network traffic analysis dashboard for authorized packet captures. Upload a PCAP or PCAPNG file, parse it with PyShark and TShark, review statistics and packet evidence, tune detection rules, and download a JSON or CSV report.

Alerts are heuristic leads. They are not confirmation of an intrusion, and a capture with no alerts is not certified safe or malware-free.

## Features

- Drag-and-drop upload with extension, magic-byte, and size checks
- Background analysis jobs with statuses `queued`, `processing`, `completed`, and `failed`
- Packet metadata for IPv4, IPv6, TCP, UDP, ICMP, ARP, and packets that lack an address or a port
- Protocol, host, port, pair, timeline, and TCP flag statistics calculated from the parsed packets
- Five configurable rules: possible port scan, possible traffic burst, sensitive port access, protocol outside a baseline, and repeated TCP SYN attempts
- A saved snapshot of the rules used for each analysis
- SQLite persistence across API restarts
- Search, filters, sorting, and pagination for packets and alerts
- JSON and CSV reports built from stored results

## Architecture

The React app talks only to the FastAPI service. FastAPI stores analyses in SQLite and capture files under `backend/storage/captures`, which is not served to the browser. PyShark drives TShark with an argument list, not a shell string. The design is described in [docs/architecture.md](docs/architecture.md).

Background processing uses FastAPI background tasks inside the API process. It is not a distributed job queue. A restart marks leftover `queued` or `processing` jobs as failed so they can be run again.

## Technology

- React, Vite, Tailwind CSS, React Router, Recharts, Axios
- Python, FastAPI, Uvicorn, PyShark, SQLAlchemy, SQLite, Pydantic, pytest
- TShark from a Wireshark install on Windows 11

## Prerequisites

- Windows 11
- Python 3.12 or newer (`py -3` on this project was verified with 3.13)
- Node.js and npm
- Wireshark, which provides `tshark.exe`

TShark does not have to be on `PATH`. The common location is:

```text
C:\Program Files\Wireshark\tshark.exe
```

## Install on Windows

Open PowerShell in the project folder. If script activation is blocked, the `python.exe` path below avoids `Activate.ps1`.

### Backend

```powershell
cd backend
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `backend/.env` if TShark is not in the default location. The variable is `THREATLENS_TSHARK_PATH`. Restart the API after changing it.

Check TShark:

```powershell
.\.venv\Scripts\python.exe -c "from app.services.tshark_service import check_tshark; import json; print(json.dumps(check_tshark(), indent=2))"
```

`available` should be `true`. If it is false, the JSON message explains how to set the path. Analysis is not silently skipped when TShark is missing; the job is stored as `failed` with that message.

### Frontend

```powershell
cd frontend
npm install
```

## Run

Use two terminals. Start commands from the directories below so relative paths resolve next to the code.

Terminal 1, API:

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Terminal 2, interface:

```powershell
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

- Dashboard: http://127.0.0.1:5173
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/api/v1/health

`start-threatlens.bat` creates the virtual environment and `backend/.env` when they are missing, installs frontend packages when `node_modules` is missing, and opens the API and Vite in two windows. The PowerShell commands above are the reliable fallback.

## Analyze a capture

1. Open **Upload**.
2. Choose a `.pcap` or `.pcapng` file from a network you are allowed to inspect, or generate the synthetic fixture described in [sample-data/README.md](sample-data/README.md).
3. Wait until the status is `completed`. A queued or processing job is not shown as a finished analysis.
4. Open the analysis for protocol charts, hosts, ports, and the packet table.
5. Open **Alerts** and inspect the packet evidence for a finding.
6. Adjust thresholds on **Rules**. Completed analyses keep the thresholds they were run with. Use **Run again** when you want the new settings; that replaces the previous results for that file.
7. Download JSON or CSV from **Reports**. If the download fails, the page shows the error.

The default upload limit is 50 MB (`THREATLENS_MAX_UPLOAD_BYTES`). Parsing stops after `THREATLENS_MAX_PACKETS` (100000) or `THREATLENS_MAX_PROCESSING_SECONDS` (300). A partial run is still `completed`, and the summary lists a warning. It does not invent the missing packets.

## Detection rules

See [docs/detection-rules.md](docs/detection-rules.md). The five rules are a possible port scan, a possible traffic burst, sensitive-port access, a protocol outside your baseline, and repeated TCP SYN attempts. SYN-ACK packets are not counted as connection attempts, and the SYN rule does not claim that a login failed.

## Tests

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
```

Details are in [docs/testing.md](docs/testing.md).

Build the interface:

```powershell
cd frontend
npm run build
```

## Configuration

`backend/.env.example` documents every setting:

| Variable | Default | Role |
| --- | --- | --- |
| `THREATLENS_DATABASE_URL` | `sqlite:///./threatlens.db` | SQLite file, relative to `backend/` |
| `THREATLENS_STORAGE_DIR` | `./storage` | Capture storage, not served by Vite |
| `THREATLENS_MAX_UPLOAD_BYTES` | `52428800` | Upload limit |
| `THREATLENS_MAX_PACKETS` | `100000` | Parse limit |
| `THREATLENS_MAX_PROCESSING_SECONDS` | `300` | Soft time limit |
| `THREATLENS_TSHARK_PATH` | Wireshark default | Full path to `tshark.exe` |
| `THREATLENS_CORS_ORIGINS` | localhost and 127.0.0.1 port 5173 | Direct browser calls to the API |

The Vite dev server proxies `/api` to `127.0.0.1:8000`, so the dashboard does not depend on CORS during development.

## Known limitations

- One local user. There is no login. Keep the API on `127.0.0.1`.
- Jobs run in the API process. They are not retried by a separate worker. An interrupted job is marked failed on the next startup.
- Packet payloads are not stored.
- Rules are indicators. Sensitive-port alerts are watchlist matches. Burst alerts are volume thresholds.
- If TShark hangs, the job is marked failed when the timeout expires, but the TShark process started by PyShark may need to be closed in Task Manager.
- Re-running an analysis deletes its previous packets and alerts even if the new parse fails.
- The default burst threshold will not fire on the small synthetic fixture until you lower it.

## Demonstration workflow

1. Start the API and the dashboard.
2. Open http://127.0.0.1:8000/api/v1/health and confirm TShark is available.
3. Generate `sample-data/synthetic-lab-fixture.pcap` if it is not already there.
4. Upload it and wait for `completed`.
5. Compare the packet table count with the summary packet count.
6. Open the port-scan alert and the repeated-SYN alert and read the observed value, threshold, and packet list.
7. Change a rule, confirm the original analysis snapshot is unchanged, then run it again if you want the new threshold.
8. Download the JSON and CSV reports.

A longer report structure for the college write-up is in [docs/project-report-outline.md](docs/project-report-outline.md).
