# Testing

Backend tests use pytest and FastAPI's `TestClient`. They do not need the internet. Detection, statistics, and most API tests use synthetic packet records or a mocked parser. One integration test builds a four-packet PCAP and parses it with the local TShark. If TShark cannot be resolved, that test is skipped. It is not skipped when TShark exists and then fails: a parse error fails the test.

## Run

From `backend` in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

`backend/pytest.ini` adds the backend directory to `pythonpath`.

## What is covered

- Health response shape and database connectivity
- Rejected extensions, empty files, bad magic, extension/format mismatch, and oversized uploads
- Server-generated capture names, including a client filename that contains `..`
- TCP, IPv6, ICMP, ARP, hex TCP flags, and a packet that throws while being read
- Packet-count and processing-time limits
- Host, protocol, byte, SYN, and SYN-ACK statistics
- Port scan, including the time window and a threshold that should not fire
- Traffic burst for a split source and for a single pair, including a byte-threshold alert
- Sensitive ports grouped into one event
- Baseline protocol matching
- Repeated SYN attempts, with SYN-ACK excluded
- Disabled rules
- Packets that have no IP address and no ports
- Analysis status moving through `processing` to `completed` or `failed`
- Rule edits that do not change an older analysis snapshot
- Alert pagination, search, and evidence lookup
- Invalid rule thresholds rejected with 422 and not saved
- Rules and interrupted jobs surviving a new application startup
- JSON and CSV reports, and a 409 report before completion
- A clear failure when TShark cannot be resolved
- A real TShark parse of a synthetic PCAP, checked against stored packet bytes and a port-22 watchlist alert

Mocked parser output is used only inside tests. The running API calls PyShark.

## Frontend

The React UI uses Vitest, React Testing Library, and jsdom. The tests render the routed app and stub the documented FastAPI response shapes in `frontend/tests/fixtures.js`. They cover file selection and upload requests, queued/processing/completed/failed presentation, navigation to packet results, alert evidence, rule validation and PATCH payloads, and JSON/CSV browser downloads and errors. These tests never claim to exercise PyShark, packet detection, SQLite, or the real browser download manager.

From `frontend` in PowerShell:

```powershell
cd frontend
npm ci
npm test
npm run build
```

For a full local check on Windows with TShark installed and resolvable by the backend, start both processes as described in the README. Upload `sample-data/synthetic-lab-fixture.pcap` through the UI, watch queued/processing change to completed, open packet evidence for the port-22 alert, change a rule and run a new analysis, then download and open both JSON and CSV reports. Confirm the stored analysis retains its original rule snapshot. This real PCAP path, TShark/PyShark startup and parsing, backend persistence, actual browser download behavior, and Windows path/configuration are outside the jsdom UI suite. The backend synthetic PCAP integration test covers its parser independently and skips when TShark is unavailable.
