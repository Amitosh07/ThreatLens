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

There is no separate UI test runner. Verify the interface with:

```powershell
cd frontend
npm run build
```

Then start both processes and upload `sample-data/synthetic-lab-fixture.pcap`.
