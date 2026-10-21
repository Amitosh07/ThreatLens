# College project report outline

Use this outline for the written report. Describe only the behavior that is in this repository. The screenshots should come from a capture you actually analyzed.

## 1. Title

Network Traffic Analysis and Anomaly Detection Dashboard (ThreatLens)

## 2. Problem statement

Analysts and students need a local way to inspect an authorized packet capture, summarize who talked to whom, and highlight patterns that deserve a closer look. ThreatLens does that offline. It does not scan networks, exploit hosts, or decide that a capture is safe.

## 3. Objectives

- Accept PCAP and PCAPNG uploads with validation and a size limit.
- Decode packets with PyShark and TShark, including packets that have no IP address or no ports.
- Calculate traffic statistics from the stored packet rows.
- Raise grouped alerts from five configurable rules.
- Keep a snapshot of the rules used for each analysis.
- Present the results in a dashboard and export JSON and CSV reports.

## 4. Tools

Wireshark/TShark, PyShark, Python, FastAPI, SQLAlchemy, SQLite, React, Vite, Tailwind CSS, and Recharts. The deployment target is Windows 11 on localhost.

## 5. Architecture

See `docs/architecture.md`. Include the diagram of the browser, API, SQLite, capture storage, and TShark. Explain that background jobs are in-process and are not a distributed queue.

## 6. Implementation

Walk through one upload:

1. Magic-byte and size checks.
2. Storage under `backend/storage/captures` with a generated name.
3. Background parse and the fields kept for each packet.
4. Summary definitions: unique source hosts, unique destination hosts, and the union of hosts.
5. Rule execution and alert evidence.
6. The React pages: overview, upload, analysis, alerts, rules, and reports.

## 7. Detection methodology

Summarize `docs/detection-rules.md`. For the demonstration, analyze `sample-data/synthetic-lab-fixture.pcap` and show the port-scan, sensitive-port, and repeated-SYN alerts. State the observed value and the threshold next to each one. If you also show a traffic burst, say that you lowered the configured threshold; the default of 500 packets does not match that small file.

Make the limitation explicit: these are heuristics. A sensitive-port alert is a watchlist hit. A SYN alert is not evidence of a failed login.

## 8. Testing

Cite `docs/testing.md` and paste the pytest summary from the machine you used. Mention the integration test that parses a synthetic capture with TShark, and the tests that reject bad uploads.

## 9. Demonstration script

1. Show the health endpoint and the TShark path.
2. Show the default rules.
3. Upload the synthetic fixture.
4. Open the analysis and compare the packet count with the summary.
5. Open an alert and show the supporting packets.
6. Change a threshold, show that the old analysis snapshot did not change, then run the analysis again and show the new result.
7. Download the JSON and CSV reports.

## 10. Limitations

- Local single-user application, no accounts.
- In-process background tasks.
- Configurable packet and time limits, default upload limit 50 MB.
- Payloads are not stored, so the tool cannot inspect file contents inside packets.
- No alerts does not mean the capture is malware-free.
- A stuck TShark process can outlive the processing timeout because PyShark owns that process.

## 11. Future work

A durable job queue, richer protocol baselines per lab, and optional enrichment that is still offline. Do not list active scanning or exploit features as future work for this defensive project.

## 12. Conclusion

Restate that the dashboard is driven by parsed captures and stored alerts, and that every alert remains an indicator for a human to review.
