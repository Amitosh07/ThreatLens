"""Rule-based anomaly detection over parsed packet metadata."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.services.pcap_parser import PacketRecord
from app.utils.packets import split_flags
from app.utils.time import format_timestamp

PACKET_NUMBER_LIMIT = 100
PORT_SAMPLE_LIMIT = 50


@dataclass(slots=True)
class AlertDraft:
    rule_key: str
    rule_name: str
    severity: str
    evidence_strength: str
    description: str
    explanation: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    window_start: float | None = None
    window_end: float | None = None
    observed_value: str = ""
    threshold_value: str = ""
    packet_numbers: list[int] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


def _cap_numbers(numbers: list[int]) -> list[int]:
    unique = sorted(set(numbers))
    return unique[:PACKET_NUMBER_LIMIT]


def _best_count_window(events: list[tuple[float, int]], window_seconds: int, threshold: int):
    """Return the window with the most events once the threshold is reached."""
    if not events:
        return None
    ordered = sorted(events, key=lambda item: (item[0], item[1]))
    best = None
    left = 0
    for right, (timestamp, number) in enumerate(ordered):
        while timestamp - ordered[left][0] > window_seconds and left < right:
            left += 1
        count = right - left + 1
        if count < threshold:
            continue
        score = (count, -ordered[left][0])
        if best is None or score > best[0]:
            window = ordered[left : right + 1]
            best = (
                score,
                {
                    "count": count,
                    "start": window[0][0],
                    "end": window[-1][0],
                    "packet_numbers": [item[1] for item in window],
                },
            )
    return None if best is None else best[1]


def _best_port_window(events: list[tuple[float, int, int]], window_seconds: int, threshold: int):
    """events are (timestamp, destination port, packet number)."""
    if not events:
        return None
    ordered = sorted(events, key=lambda item: (item[0], item[2]))
    counts: Counter[int] = Counter()
    best = None
    left = 0
    for right, (timestamp, port, _number) in enumerate(ordered):
        counts[port] += 1
        while timestamp - ordered[left][0] > window_seconds and left < right:
            old_port = ordered[left][1]
            counts[old_port] -= 1
            if counts[old_port] <= 0:
                del counts[old_port]
            left += 1
        distinct = len(counts)
        if distinct < threshold:
            continue
        score = (distinct, -ordered[left][0])
        if best is None or score > best[0]:
            window = ordered[left : right + 1]
            best = (
                score,
                {
                    "distinct": distinct,
                    "start": window[0][0],
                    "end": window[-1][0],
                    "ports": sorted(counts),
                    "packet_numbers": [item[2] for item in window],
                },
            )
    return None if best is None else best[1]


def detect_port_scan(packets: list[PacketRecord], rule: dict) -> list[AlertDraft]:
    params = rule["parameters"]
    threshold = int(params["distinct_ports"])
    window_seconds = int(params["window_seconds"])
    grouped: dict[tuple[str, str], list[tuple[float, int, int]]] = defaultdict(list)
    for packet in packets:
        if not packet.src_ip or not packet.dst_ip or packet.dst_port is None:
            continue
        grouped[(packet.src_ip, packet.dst_ip)].append((packet.timestamp, packet.dst_port, packet.packet_number))

    alerts: list[AlertDraft] = []
    for (src_ip, dst_ip), events in grouped.items():
        found = _best_port_window(events, window_seconds, threshold)
        if found is None:
            continue
        observed = found["distinct"]
        strength = "high" if observed >= threshold * 2 else "medium"
        examples = ", ".join(str(port) for port in found["ports"][:12])
        alerts.append(
            AlertDraft(
                rule_key=rule["rule_key"],
                rule_name=rule["name"],
                severity=rule["severity"],
                evidence_strength=strength,
                description=(
                    f"Possible port scan: {src_ip} contacted {observed} distinct ports on {dst_ip}."
                ),
                explanation=(
                    f"Source {src_ip} contacted {observed} distinct destination ports on {dst_ip} "
                    f"between {format_timestamp(found['start'])} and {format_timestamp(found['end'])}. "
                    f"Example ports: {examples}. The configured threshold is {threshold} distinct ports "
                    f"within {window_seconds} seconds. This can match scanning or benign inventory and "
                    "is not confirmation of malicious activity."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                window_start=found["start"],
                window_end=found["end"],
                observed_value=f"{observed} distinct ports",
                threshold_value=f"{threshold} distinct ports within {window_seconds} seconds",
                packet_numbers=_cap_numbers(found["packet_numbers"]),
                evidence={
                    "distinct_ports": observed,
                    "ports_sample": found["ports"][:PORT_SAMPLE_LIMIT],
                    "port_count": len(found["ports"]),
                    "packet_count": len(found["packet_numbers"]),
                    "window_seconds": window_seconds,
                },
            )
        )
    return alerts


def _exceeds(record: dict, packet_rate: int, byte_rate: int) -> list[str]:
    reasons = []
    if record["packets"] >= packet_rate:
        reasons.append("packet_rate")
    if record["bytes"] >= byte_rate:
        reasons.append("byte_rate")
    return reasons


def _better_burst(candidate: dict, current: dict) -> bool:
    return (candidate["packets"], candidate["bytes"]) > (current["packets"], current["bytes"])


def detect_traffic_burst(packets: list[PacketRecord], rule: dict) -> list[AlertDraft]:
    params = rule["parameters"]
    packet_rate = int(params["packet_rate"])
    byte_rate = int(params["byte_rate"])
    window_seconds = int(params["window_seconds"])
    if not packets:
        return []
    origin = min(packet.timestamp for packet in packets)

    def bucket_for(timestamp: float) -> int:
        if window_seconds <= 0:
            return 0
        return int((timestamp - origin) / window_seconds)

    sources: dict[tuple[str, int], dict] = {}
    pairs: dict[tuple[str, str, int], dict] = {}
    for packet in packets:
        if not packet.src_ip:
            continue
        bucket = bucket_for(packet.timestamp)
        source_key = (packet.src_ip, bucket)
        source = sources.setdefault(
            source_key,
            {"packets": 0, "bytes": 0, "numbers": [], "start": packet.timestamp, "end": packet.timestamp, "bucket": bucket},
        )
        source["packets"] += 1
        source["bytes"] += max(packet.length, 0)
        source["numbers"].append(packet.packet_number)
        source["start"] = min(source["start"], packet.timestamp)
        source["end"] = max(source["end"], packet.timestamp)
        if packet.dst_ip:
            pair_key = (packet.src_ip, packet.dst_ip, bucket)
            pair = pairs.setdefault(
                pair_key,
                {
                    "packets": 0,
                    "bytes": 0,
                    "numbers": [],
                    "start": packet.timestamp,
                    "end": packet.timestamp,
                    "bucket": bucket,
                },
            )
            pair["packets"] += 1
            pair["bytes"] += max(packet.length, 0)
            pair["numbers"].append(packet.packet_number)
            pair["start"] = min(pair["start"], packet.timestamp)
            pair["end"] = max(pair["end"], packet.timestamp)

    pair_peaks: dict[tuple[str, str], dict] = {}
    for (src_ip, dst_ip, _bucket), record in pairs.items():
        reasons = _exceeds(record, packet_rate, byte_rate)
        if not reasons:
            continue
        record = {**record, "reasons": reasons, "src_ip": src_ip, "dst_ip": dst_ip}
        current = pair_peaks.get((src_ip, dst_ip))
        if current is None or _better_burst(record, current):
            pair_peaks[(src_ip, dst_ip)] = record

    source_peaks: dict[str, dict] = {}
    for (src_ip, _bucket), record in sources.items():
        reasons = _exceeds(record, packet_rate, byte_rate)
        if not reasons:
            continue
        record = {**record, "reasons": reasons, "src_ip": src_ip}
        current = source_peaks.get(src_ip)
        if current is None or _better_burst(record, current):
            source_peaks[src_ip] = record

    covered = {(record["src_ip"], record["bucket"]) for record in pair_peaks.values()}
    alerts: list[AlertDraft] = []
    for record in pair_peaks.values():
        alerts.append(_burst_alert(rule, record, packet_rate, byte_rate, window_seconds, entity="pair"))
    for record in source_peaks.values():
        if (record["src_ip"], record["bucket"]) in covered:
            continue
        alerts.append(_burst_alert(rule, record, packet_rate, byte_rate, window_seconds, entity="source"))
    return alerts


def _burst_alert(rule: dict, record: dict, packet_rate: int, byte_rate: int, window_seconds: int, entity: str) -> AlertDraft:
    reasons = record["reasons"]
    reason_text = []
    if "packet_rate" in reasons:
        reason_text.append("packet-rate")
    if "byte_rate" in reasons:
        reason_text.append("byte-rate")
    joined = " and ".join(reason_text)
    if entity == "pair":
        subject = f"{record['src_ip']} to {record['dst_ip']}"
        description = (
            f"Possible traffic burst: {subject} exceeded the {joined} threshold "
            f"({record['packets']} packets, {record['bytes']} bytes)."
        )
    else:
        subject = record["src_ip"]
        description = (
            f"Possible traffic burst: source {subject} exceeded the {joined} threshold "
            f"({record['packets']} packets, {record['bytes']} bytes)."
        )
    explanation = (
        f"{subject} accounted for {record['packets']} packets and {record['bytes']} bytes "
        f"between {format_timestamp(record['start'])} and {format_timestamp(record['end'])}. "
        f"The configured thresholds are {packet_rate} packets or {byte_rate} bytes within "
        f"{window_seconds} seconds. The {joined} threshold was exceeded. "
        "This is a volume anomaly and is not confirmation of a flood or malicious activity."
    )
    return AlertDraft(
        rule_key=rule["rule_key"],
        rule_name=rule["name"],
        severity=rule["severity"],
        evidence_strength="medium",
        description=description,
        explanation=explanation,
        src_ip=record["src_ip"],
        dst_ip=record.get("dst_ip"),
        window_start=record["start"],
        window_end=record["end"],
        observed_value=f"{record['packets']} packets, {record['bytes']} bytes",
        threshold_value=f"{packet_rate} packets or {byte_rate} bytes within {window_seconds} seconds",
        packet_numbers=_cap_numbers(record["numbers"]),
        evidence={
            "entity": entity,
            "packets": record["packets"],
            "bytes": record["bytes"],
            "exceeded": reasons,
            "window_seconds": window_seconds,
            "packet_count": len(record["numbers"]),
        },
    )


def detect_sensitive_port(packets: list[PacketRecord], rule: dict) -> list[AlertDraft]:
    ports = {int(port) for port in rule["parameters"]["ports"]}
    grouped: dict[tuple[str | None, str | None, int], list[PacketRecord]] = defaultdict(list)
    for packet in packets:
        if packet.dst_port is None or packet.dst_port not in ports:
            continue
        grouped[(packet.src_ip, packet.dst_ip, packet.dst_port)].append(packet)

    alerts: list[AlertDraft] = []
    for (src_ip, dst_ip, port), matches in grouped.items():
        numbers = [packet.packet_number for packet in matches]
        start = min(packet.timestamp for packet in matches)
        end = max(packet.timestamp for packet in matches)
        source = src_ip or "an unknown source"
        destination = dst_ip or "an unknown destination"
        alerts.append(
            AlertDraft(
                rule_key=rule["rule_key"],
                rule_name=rule["name"],
                severity=rule["severity"],
                evidence_strength="low",
                description=f"Traffic to watched port {port}/destination from {source} to {destination}.",
                explanation=(
                    f"{len(matches)} packet(s) from {source} to {destination} used destination port {port}, "
                    f"which is on the sensitive-port watchlist. The packets fall between "
                    f"{format_timestamp(start)} and {format_timestamp(end)}. "
                    "This is a watchlist match, not confirmation that the traffic is malicious."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=port,
                window_start=start,
                window_end=end,
                observed_value=f"destination port {port}, {len(matches)} packet(s)",
                threshold_value="destination port is on the sensitive-port watchlist",
                packet_numbers=_cap_numbers(numbers),
                evidence={
                    "port": port,
                    "packet_count": len(matches),
                    "watchlist_size": len(ports),
                },
            )
        )
    return alerts


def detect_unusual_protocol(packets: list[PacketRecord], rule: dict) -> list[AlertDraft]:
    expected = {str(name).upper() for name in rule["parameters"]["expected_protocols"]}
    grouped: dict[str, list[PacketRecord]] = defaultdict(list)
    for packet in packets:
        protocol = (packet.protocol or "UNKNOWN").upper()
        if protocol in expected:
            continue
        grouped[protocol].append(packet)

    alerts: list[AlertDraft] = []
    for protocol, matches in grouped.items():
        numbers = [packet.packet_number for packet in matches]
        start = min(packet.timestamp for packet in matches)
        end = max(packet.timestamp for packet in matches)
        alerts.append(
            AlertDraft(
                rule_key=rule["rule_key"],
                rule_name=rule["name"],
                severity=rule["severity"],
                evidence_strength="low",
                description=f"Protocol {protocol} is outside the configured baseline ({len(matches)} packet(s)).",
                explanation=(
                    f"{len(matches)} packet(s) were decoded as {protocol}, which is not in the configured "
                    f"expected protocol set. The packets fall between {format_timestamp(start)} and "
                    f"{format_timestamp(end)}. Protocols that are listed in the baseline are not flagged, "
                    "even if they are uncommon. This is not confirmation of malicious activity."
                ),
                window_start=start,
                window_end=end,
                observed_value=f"{protocol}, {len(matches)} packet(s)",
                threshold_value="protocol is outside the configured expected set",
                packet_numbers=_cap_numbers(numbers),
                evidence={
                    "protocol": protocol,
                    "packet_count": len(matches),
                    "expected_count": len(expected),
                },
            )
        )
    return alerts


def _is_syn_attempt(packet: PacketRecord) -> bool:
    if (packet.transport or "").upper() != "TCP":
        return False
    flags = set(split_flags(packet.tcp_flags))
    return "SYN" in flags and "ACK" not in flags


def detect_repeated_syn(packets: list[PacketRecord], rule: dict) -> list[AlertDraft]:
    params = rule["parameters"]
    threshold = int(params["syn_count"])
    window_seconds = int(params["window_seconds"])
    grouped: dict[tuple[str, str, int], list[tuple[float, int]]] = defaultdict(list)
    for packet in packets:
        if not _is_syn_attempt(packet):
            continue
        if not packet.src_ip or not packet.dst_ip or packet.dst_port is None:
            continue
        grouped[(packet.src_ip, packet.dst_ip, packet.dst_port)].append((packet.timestamp, packet.packet_number))

    alerts: list[AlertDraft] = []
    for (src_ip, dst_ip, dst_port), events in grouped.items():
        found = _best_count_window(events, window_seconds, threshold)
        if found is None:
            continue
        observed = found["count"]
        alerts.append(
            AlertDraft(
                rule_key=rule["rule_key"],
                rule_name=rule["name"],
                severity=rule["severity"],
                evidence_strength="medium",
                description=(
                    f"Repeated TCP SYN attempts: {src_ip} sent {observed} SYN packets to {dst_ip}:{dst_port}."
                ),
                explanation=(
                    f"Source {src_ip} sent {observed} TCP SYN packets without the ACK flag to "
                    f"{dst_ip} port {dst_port} between {format_timestamp(found['start'])} and "
                    f"{format_timestamp(found['end'])}. The configured threshold is {threshold} SYN attempts "
                    f"within {window_seconds} seconds. SYN-ACK responses are excluded. "
                    "This does not show that a login failed or that the connection was refused."
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                window_start=found["start"],
                window_end=found["end"],
                observed_value=f"{observed} SYN attempts",
                threshold_value=f"{threshold} SYN attempts within {window_seconds} seconds",
                packet_numbers=_cap_numbers(found["packet_numbers"]),
                evidence={
                    "syn_count": observed,
                    "packet_count": len(found["packet_numbers"]),
                    "window_seconds": window_seconds,
                    "excluded": "SYN-ACK responses are not counted.",
                },
            )
        )
    return alerts


DETECTORS = {
    "port_scan": detect_port_scan,
    "traffic_burst": detect_traffic_burst,
    "sensitive_port": detect_sensitive_port,
    "unusual_protocol": detect_unusual_protocol,
    "repeated_syn": detect_repeated_syn,
}


def run_detection(packets: list[PacketRecord], snapshot: list[dict]) -> list[AlertDraft]:
    alerts: list[AlertDraft] = []
    for rule in snapshot:
        if not rule.get("enabled", False):
            continue
        detector = DETECTORS.get(rule.get("rule_key"))
        if detector is None:
            continue
        alerts.extend(detector(packets, rule))
    return alerts
