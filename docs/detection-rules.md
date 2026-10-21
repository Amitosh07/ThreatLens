# Detection rules

All five rules read packet metadata produced by the parser. They do not invent alerts, and they collapse matching packets into one event instead of raising one alert per packet.

Changing a rule in the interface updates SQLite. The next analysis copies the saved rule into its snapshot. Older analyses keep the snapshot they were run with.

Severity is one of `info`, `low`, `medium`, `high`, or `critical`. Evidence strength is separate: `low`, `medium`, or `high`. It describes how directly the packets match the rule. It is not a malware score.

## Possible Port Scan

A source IP contacts many distinct destination ports on one destination IP inside a time window.

- Default: 20 distinct ports within 60 seconds.
- One alert per source and destination pair, using the window with the most distinct ports.
- The alert lists the observed count, the threshold, example ports, and packet numbers.
- This can also match inventory or application behavior.

## Possible Traffic Burst

Fixed windows are aligned to the first packet timestamp.

- Default: 500 packets or 1,000,000 bytes within 10 seconds.
- A communicating pair that exceeds a threshold produces one pair alert for its busiest window.
- A source alert is added only when the source exceeds a threshold and no single pair accounts for that same window. That covers a source spreading traffic across many destinations.
- The explanation states whether the packet threshold, the byte threshold, or both were exceeded.

## Sensitive Port Access

Destination ports on the saved watchlist produce one alert per source, destination, and port. The default watchlist is administrative and database services such as 22, 23, 3389, 445, and 3306. DNS port 53 is not included by default because it is noisy; it can be added.

A match means the port was seen. It does not mean the session was an intrusion.

## Protocol Outside Baseline

The highest decoded protocol is compared, case-insensitively, with the expected set. Protocols in the set are ignored even if they are uncommon on the public internet. One alert is created per unexpected protocol, with the packet count and sample packet numbers.

The default set includes common lab and enterprise names such as TCP, UDP, ICMP, ARP, DNS, TLS, HTTP, and DHCP. Tighten it when you want the rule to be stricter.

## Repeated Connection Attempts

Counts TCP packets whose flags include SYN and do not include ACK. SYN-ACK responses are excluded. Grouping is by source IP, destination IP, and destination port.

- Default: 10 SYN attempts within 30 seconds.
- The alert does not say that a login failed or that the handshake was refused. The capture may not contain the response.

## Disabled rules

A disabled rule is skipped. Its previous alerts remain on analyses that already completed. Run the analysis again to apply the new enabled state.
