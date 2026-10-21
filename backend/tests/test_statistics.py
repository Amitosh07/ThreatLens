"""Traffic statistics definitions."""

from app.services.traffic_analyzer import build_summary
from tests.conftest import packet


def test_host_protocol_and_byte_totals_are_exact():
    packets = [
        packet(packet_number=1, src_ip="1.1.1.1", dst_ip="2.2.2.2", length=100, protocol="TCP", transport="TCP"),
        packet(
            packet_number=2,
            src_ip="1.1.1.1",
            dst_ip="3.3.3.3",
            length=50,
            protocol="UDP",
            transport="UDP",
            tcp_flags=None,
            timestamp=1_700_000_010,
        ),
        packet(
            packet_number=3,
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            length=42,
            protocol="ARP",
            transport=None,
            tcp_flags=None,
            timestamp=1_700_000_020,
        ),
    ]
    summary = build_summary(packets, processing_ms=15)
    assert summary["packet_count"] == 3
    assert summary["total_bytes"] == 192
    assert summary["unique_source_hosts"] == 1
    assert summary["unique_destination_hosts"] == 2
    assert summary["unique_hosts"] == 3
    protocols = {item["protocol"]: item for item in summary["protocols"]}
    assert protocols["TCP"]["packets"] == 1
    assert protocols["TCP"]["percentage"] == 33.33
    assert summary["transports"] == {"TCP": 1, "UDP": 1, "ICMP": 0, "Other": 1}
    assert summary["top_pairs"][0]["packets"] == 1
    assert summary["tcp_syn_attempts"] == 1
    assert summary["tcp_syn_ack_responses"] == 0
    assert summary["processing_ms"] == 15
    assert summary["timeline"]
    assert summary["capture_span_seconds"] == 20


def test_syn_ack_is_not_counted_as_an_attempt():
    packets = [
        packet(packet_number=1, tcp_flags="SYN,ACK", transport="TCP"),
        packet(packet_number=2, tcp_flags="SYN", transport="TCP"),
    ]
    summary = build_summary(packets, processing_ms=1)
    assert summary["tcp_syn_attempts"] == 1
    assert summary["tcp_syn_ack_responses"] == 1


def test_empty_capture_summary():
    summary = build_summary([], processing_ms=0)
    assert summary["packet_count"] == 0
    assert summary["unique_hosts"] == 0
    assert summary["protocols"] == []
    assert summary["timeline"] == []
