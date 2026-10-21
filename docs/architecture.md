# Architecture

ThreatLens is a local, single-user application. The React interface never reads the database or the capture files. It calls the FastAPI service, which stores results in SQLite.

```text
Browser (Vite, port 5173)
        |  /api/v1
        v
FastAPI (127.0.0.1:8000)
        |-- SQLite (analyses, packets, alerts, rules)
        |-- storage/captures (uploaded files, not web-served)
        |-- PyShark -> TShark (packet decode)
        \-- detection engine (pure Python over packet metadata)
```

## Request path

1. `POST /api/v1/uploads` checks the extension, size, and magic bytes, writes a server-generated filename under `backend/storage/captures`, and inserts an analysis row with status `queued`.
2. A FastAPI background task moves the row to `processing`, reads the current detection rules, and stores that snapshot on the analysis.
3. PyShark opens the capture with the configured TShark executable. Name resolution is disabled. Each decoded packet is reduced to a small record and then discarded.
4. Statistics and alerts are calculated from those records and committed with status `completed`. A parser or TShark failure sets status `failed` and stores a short message without a traceback.
5. The interface polls `GET /api/v1/analyses/{id}` and only treats the job as successful when the status is `completed`.

## Job processing

Background work uses FastAPI `BackgroundTasks` in the API process. It is not a durable queue. If the API stops while a job is `queued` or `processing`, the next startup marks that row `failed` and asks for **Run again**. Re-running deletes the previous packets, alerts, and summary for that file before parsing starts.

SQLite is opened with foreign keys, a busy timeout, and WAL mode so the request thread and the analysis thread can share the file.

## Why a rule snapshot exists

Rules live in `detection_rules` and can be edited after an analysis. Each completed analysis keeps `rule_snapshot_json`, and each alert stores the observed value and threshold that actually fired. Historical alerts are not rebuilt when a rule changes.

## What is intentionally absent

- No packet payloads are stored.
- Capture files are not mounted as static files.
- TShark is invoked with an argument list. Uploaded names are never placed in a shell command.
- There is no authentication. Bind the API to `127.0.0.1` and use it for local lab work.
