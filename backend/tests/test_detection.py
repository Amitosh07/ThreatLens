"""Deterministic detection rules."""

from app.services.detection_engine import run_detection
from app.services.rule_catalog import get_rule_definition
from tests.conftest import packet


def rule(key, **parameter_overrides):
    definition = get_rule_definition(key)
    parameters = dict(definition["parameters"])
    parameters.update(parameter_overrides)
    return {
        "rule_key": key,
        "name": definition["name"],
        "enabled": True,
        "severity": definition["severity"],
        "parameters": parameters,
    }


def test_port_scan_groups_one_alert_and_reports_threshold():
    packets = [
        packet(packet_number=index, timestamp=1_700_000_000 + index, dst_port=index, tcp_flags="SYN")
        for index in range(1, 4)
    ]
    alerts = run_detection(packets, [rule("port_scan", distinct_ports=3, window_seconds=60)])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.observed_value == "3 distinct ports"
    assert "3 distinct ports within 60 seconds" in alert.threshold_value
    assert alert.packet_numbers == [1, 2, 3]
    assert "not confirmation" in alert.explanation
    assert alert.src_ip == "10.0.0.1"
    assert alert.dst_ip == "10.0.0.2"


def test_port_scan_does_not_cross_the_time_window():
    packets = [
        packet(packet_number=1, timestamp=0, dst_port=1),
        packet(packet_number=2, timestamp=10, dst_port=2),
        packet(packet_number=3, timestamp=71, dst_port=3),
    ]
    alerts = run_detection(packets, [rule("port_scan", distinct_ports=3, window_seconds=60)])
    assert alerts == []


def test_port_scan_respects_a_higher_threshold():
    packets = [packet(packet_number=index, timestamp=index, dst_port=index) for index in range(1, 6)]
    alerts = run_detection(packets, [rule("port_scan", distinct_ports=100, window_seconds=60)])
    assert alerts == []


def test_traffic_burst_for_a_split_source_and_a_single_pair():
    split = []
    for index, destination in enumerate(["10.0.0.2", "10.0.0.3"], start=1):
        for offset in range(5):
            split.append(
                packet(
                    packet_number=len(split) + 1,
                    timestamp=1_700_000_000 + offset,
                    dst_ip=destination,
                    length=100,
                    tcp_flags=None,
                )
            )
    source_alerts = run_detection(split, [rule("traffic_burst", packet_rate=8, byte_rate=10**12, window_seconds=10)])
    assert [alert.evidence["entity"] for alert in source_alerts] == ["source"]
    assert source_alerts[0].evidence["packets"] == 10
    assert "packet-rate" in source_alerts[0].explanation

    pair_packets = [
        packet(packet_number=index, timestamp=1_700_000_000 + index * 0.1, length=200, tcp_flags=None)
        for index in range(1, 11)
    ]
    pair_alerts = run_detection(pair_packets, [rule("traffic_burst", packet_rate=8, byte_rate=10**12, window_seconds=10)])
    assert len(pair_alerts) == 1
    assert pair_alerts[0].evidence["entity"] == "pair"
    assert pair_alerts[0].dst_ip == "10.0.0.2"


def test_traffic_burst_reports_the_byte_threshold():
    packets = [packet(packet_number=1, timestamp=1_700_000_000, length=5000, tcp_flags=None)]
    alerts = run_detection(packets, [rule("traffic_burst", packet_rate=9999, byte_rate=1000, window_seconds=10)])
    assert len(alerts) == 1
    assert alerts[0].evidence["exceeded"] == ["byte_rate"]
    assert "1000 bytes" in alerts[0].threshold_value
    assert "5000" in alerts[0].observed_value


def test_sensitive_port_is_one_event_and_not_called_malicious():
    packets = [
        packet(packet_number=1, dst_port=22, tcp_flags="SYN,ACK"),
        packet(packet_number=2, dst_port=22, timestamp=1_700_000_002, tcp_flags="ACK"),
        packet(packet_number=3, dst_port=80),
    ]
    alerts = run_detection(packets, [rule("sensitive_port", ports=[22, 3389])])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.dst_port == 22
    assert alert.packet_numbers == [1, 2]
    assert alert.evidence_strength == "low"
    assert "not confirmation" in alert.explanation
    assert "malicious" in alert.explanation


def test_unusual_protocol_uses_the_configured_baseline():
    packets = [
        packet(packet_number=1, protocol="TCP", transport="TCP"),
        packet(packet_number=2, protocol="GRE", transport=None, tcp_flags=None, src_port=None, dst_port=None),
        packet(packet_number=3, protocol="GRE", transport=None, tcp_flags=None, src_port=None, dst_port=None),
    ]
    alerts = run_detection(packets, [rule("unusual_protocol", expected_protocols=["TCP", "UDP"])])
    assert len(alerts) == 1
    assert alerts[0].evidence["protocol"] == "GRE"
    assert alerts[0].evidence["packet_count"] == 2
    included = run_detection(packets, [rule("unusual_protocol", expected_protocols=["TCP", "GRE"])])
    assert included == []


def test_repeated_syn_ignores_syn_ack():
    attempts = [
        packet(packet_number=index, timestamp=1_700_000_000 + index, dst_port=443, tcp_flags="SYN", transport="TCP")
        for index in range(1, 4)
    ]
    responses = [
        packet(
            packet_number=10 + index,
            timestamp=1_700_000_000 + index,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=443,
            dst_port=40000,
            tcp_flags="SYN,ACK",
            transport="TCP",
        )
        for index in range(5)
    ]
    alerts = run_detection(attempts + responses, [rule("repeated_syn", syn_count=3, window_seconds=30)])
    assert len(alerts) == 1
    assert alerts[0].evidence["syn_count"] == 3
    assert alerts[0].dst_port == 443
    assert "refused" in alerts[0].explanation
    assert "SYN-ACK" in alerts[0].explanation

    only_responses = run_detection(responses, [rule("repeated_syn", syn_count=3, window_seconds=30)])
    assert only_responses == []


def test_disabled_rule_produces_no_alert():
    packets = [packet(packet_number=index, timestamp=index, dst_port=index) for index in range(1, 5)]
    disabled = rule("port_scan", distinct_ports=3, window_seconds=60)
    disabled["enabled"] = False
    assert run_detection(packets, [disabled]) == []


def test_missing_ip_and_port_fields_do_not_crash():
    packets = [
        packet(packet_number=1, src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol="ARP", transport=None, tcp_flags=None)
    ]
    snapshot = [rule(key) for key in ("port_scan", "traffic_burst", "sensitive_port", "unusual_protocol", "repeated_syn")]
    snapshot[3]["parameters"]["expected_protocols"] = ["ARP"]
    assert run_detection(packets, snapshot) == []
