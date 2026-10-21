"""Aggregate compact packet records into dashboard statistics."""

from collections import Counter

from app.services.pcap_parser import PacketRecord
from app.utils.packets import split_flags

NICE_BUCKETS = (0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600)


def choose_bucket_seconds(span: float, target_buckets: int = 40) -> float:
    if span <= 0:
        return 1.0
    raw = span / max(target_buckets, 1)
    for step in NICE_BUCKETS:
        if step >= raw:
            return float(step)
    return float(NICE_BUCKETS[-1])


def _percentage(count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(count * 100 / total, 2)


def _top_counters(counter: Counter, byte_counter: Counter, limit: int = 10) -> list[dict]:
    rows = []
    for key, packets in counter.most_common(limit):
        rows.append({"ip": key, "packets": packets, "bytes": byte_counter[key]})
    return rows


def build_summary(
    packets: list[PacketRecord],
    processing_ms: int,
    warnings: list[str] | None = None,
    top_limit: int = 10,
) -> dict:
    """Summarize parsed packets.

    Unique source hosts count distinct source IP addresses.
    Unique destination hosts count distinct destination IP addresses.
    Unique hosts count the union of those two sets. A host that only sends,
    only receives, or does both is counted once in the union.
    Protocol percentages use packet counts, not bytes.
    """
    source_packets: Counter[str] = Counter()
    source_bytes: Counter[str] = Counter()
    destination_packets: Counter[str] = Counter()
    destination_bytes: Counter[str] = Counter()
    protocol_packets: Counter[str] = Counter()
    protocol_bytes: Counter[str] = Counter()
    transports: Counter[str] = Counter()
    pair_packets: Counter[tuple[str, str]] = Counter()
    pair_bytes: Counter[tuple[str, str]] = Counter()
    source_ports: Counter[int] = Counter()
    destination_ports: Counter[int] = Counter()
    syn_attempts = 0
    syn_ack_responses = 0

    for packet in packets:
        protocol = packet.protocol or "UNKNOWN"
        length = max(packet.length, 0)
        protocol_packets[protocol] += 1
        protocol_bytes[protocol] += length
        transport = packet.transport if packet.transport in {"TCP", "UDP", "ICMP"} else "Other"
        transports[transport] += 1
        if packet.src_ip:
            source_packets[packet.src_ip] += 1
            source_bytes[packet.src_ip] += length
        if packet.dst_ip:
            destination_packets[packet.dst_ip] += 1
            destination_bytes[packet.dst_ip] += length
        if packet.src_ip and packet.dst_ip:
            pair = (packet.src_ip, packet.dst_ip)
            pair_packets[pair] += 1
            pair_bytes[pair] += length
        if packet.src_port is not None:
            source_ports[packet.src_port] += 1
        if packet.dst_port is not None:
            destination_ports[packet.dst_port] += 1
        flags = set(split_flags(packet.tcp_flags))
        if "SYN" in flags and "ACK" in flags:
            syn_ack_responses += 1
        elif "SYN" in flags:
            syn_attempts += 1

    total_packets = len(packets)
    total_bytes = sum(max(packet.length, 0) for packet in packets)
    timestamps = [packet.timestamp for packet in packets]
    if timestamps:
        capture_start = min(timestamps)
        capture_end = max(timestamps)
        span = max(0.0, capture_end - capture_start)
    else:
        capture_start = None
        capture_end = None
        span = 0.0

    bucket_seconds = choose_bucket_seconds(span)
    if span > 0 and span / bucket_seconds > 80:
        bucket_seconds = max(bucket_seconds, span / 60)
    timeline = []
    if timestamps and capture_start is not None:
        bucket_packets: Counter[int] = Counter()
        bucket_byte_counts: Counter[int] = Counter()
        for packet in packets:
            index = 0 if bucket_seconds <= 0 else int((packet.timestamp - capture_start) / bucket_seconds)
            bucket_packets[index] += 1
            bucket_byte_counts[index] += max(packet.length, 0)
        for index in range(max(bucket_packets) + 1):
            timeline.append(
                {
                    "bucket_start": capture_start + index * bucket_seconds,
                    "packets": bucket_packets[index],
                    "bytes": bucket_byte_counts[index],
                }
            )

    protocols = [
        {
            "protocol": protocol,
            "packets": count,
            "bytes": protocol_bytes[protocol],
            "percentage": _percentage(count, total_packets),
        }
        for protocol, count in protocol_packets.most_common()
    ]
    pairs = [
        {
            "src_ip": src,
            "dst_ip": dst,
            "packets": count,
            "bytes": pair_bytes[(src, dst)],
        }
        for (src, dst), count in pair_packets.most_common(top_limit)
    ]

    return {
        "packet_count": total_packets,
        "total_bytes": total_bytes,
        "unique_source_hosts": len(source_packets),
        "unique_destination_hosts": len(destination_packets),
        "unique_hosts": len(set(source_packets) | set(destination_packets)),
        "protocols": protocols,
        "transports": {name: transports.get(name, 0) for name in ("TCP", "UDP", "ICMP", "Other")},
        "top_sources": _top_counters(source_packets, source_bytes, top_limit),
        "top_destinations": _top_counters(destination_packets, destination_bytes, top_limit),
        "top_pairs": pairs,
        "top_source_ports": [
            {"port": port, "packets": count} for port, count in source_ports.most_common(top_limit)
        ],
        "top_destination_ports": [
            {"port": port, "packets": count} for port, count in destination_ports.most_common(top_limit)
        ],
        "timeline": timeline,
        "timeline_bucket_seconds": bucket_seconds,
        "tcp_syn_attempts": syn_attempts,
        "tcp_syn_ack_responses": syn_ack_responses,
        "capture_start": capture_start,
        "capture_end": capture_end,
        "capture_span_seconds": round(span, 6),
        "processing_ms": processing_ms,
        "warnings": list(warnings or []),
        "definitions": {
            "unique_source_hosts": "Distinct source IP addresses.",
            "unique_destination_hosts": "Distinct destination IP addresses.",
            "unique_hosts": "Distinct IP addresses that appear as a source, a destination, or both.",
            "protocol_percentage": "Share of packets, calculated from packet count rather than bytes.",
            "tcp_syn_attempts": "TCP packets with SYN set and ACK unset. These are connection attempts, not confirmed failures.",
            "tcp_syn_ack_responses": "TCP packets with both SYN and ACK set.",
        },
    }
