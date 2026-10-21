# Sample data

ThreatLens does not ship a capture of a real network or a real attack. Use one of these sources.

## Synthetic lab fixture

From the repository root, with the backend virtual environment available:

```powershell
backend\.venv\Scripts\python.exe sample-data\generate_fixture_pcap.py
```

That writes `sample-data/synthetic-lab-fixture.pcap`. It is generated locally from Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ARP headers. With the default rules it is expected to produce:

- one Possible Port Scan alert from `10.10.1.5` to `10.10.1.20`
- Sensitive Port Access alerts for watched ports touched by that scan, including 21, 22, 23, and 25
- one Repeated Connection Attempts alert for 12 SYN packets to `10.10.1.30:443`

The default traffic-burst threshold is 500 packets or 1,000,000 bytes in 10 seconds, which this small file does not reach. Lower **Packet threshold per window** on the Rules page, run the analysis again, and the burst rule can match the same file. The file also includes a SYN-ACK so the summary can show that SYN-ACK packets are not counted as connection attempts.

## Capture your own lab traffic

1. Open Wireshark on a network you are allowed to monitor.
2. Start a short capture.
3. Generate ordinary traffic, such as a DNS lookup or a connection to a local lab host.
4. Stop the capture and save it as `.pcap` or `.pcapng`.
5. Upload that file in ThreatLens.

## Public sample captures

The Wireshark wiki lists small public captures and where to download them:

https://wiki.wireshark.org/SampleCaptures

Download a file yourself and upload it. This repository does not vendor those captures, and it does not claim that a file you have not downloaded is present.
