"""Optional parse of a real synthetic capture when TShark is installed."""

import pytest

from app.services.errors import TsharkNotFoundError
from app.utils.synthetic_pcap import arp_request, build_pcap, icmp_frame, ipv6_tcp_frame, tcp_frame


def test_tshark_parses_a_small_synthetic_capture(client):
    from app.services.tshark_service import resolve_tshark

    try:
        resolve_tshark()
    except TsharkNotFoundError:
        pytest.skip("TShark is not installed")

    content = build_pcap(
        [
            tcp_frame("10.1.1.1", "10.1.1.2", 40000, 22, 0x02, identification=1),
            icmp_frame("10.1.1.1", "10.1.1.2", identification=2),
            arp_request("10.1.1.8", "10.1.1.9"),
            ipv6_tcp_frame("2001:db8::1", "2001:db8::2", 12345, 80, 0x02),
        ],
        timestamps=[1_700_000_000, 1_700_000_001, 1_700_000_002, 1_700_000_003],
    )
    response = client.post(
        "/api/v1/uploads",
        files={"file": ("synthetic.pcap", content, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201
    analysis_id = response.json()["id"]
    detail = client.get(f"/api/v1/analyses/{analysis_id}").json()
    assert detail["status"] == "completed", detail.get("error_message")
    assert detail["packet_count"] == 4

    packets = client.get(f"/api/v1/analyses/{analysis_id}/packets", params={"page_size": 20}).json()["items"]
    assert len(packets) == 4
    assert any(packet["dst_port"] == 22 and packet["src_ip"] == "10.1.1.1" for packet in packets)
    assert any(packet["transport"] == "ICMP" and packet["src_port"] is None for packet in packets)
    assert any(packet["protocol"] == "ARP" and packet["src_port"] is None for packet in packets)
    assert any(packet["src_ip"] and "2001:db8" in packet["src_ip"].lower() for packet in packets)
    summary = detail["summary"]
    assert summary["packet_count"] == 4
    assert summary["total_bytes"] == sum(packet["length"] for packet in packets)
    alerts = client.get(f"/api/v1/analyses/{analysis_id}/alerts").json()["items"]
    assert any(alert["rule_key"] == "sensitive_port" and alert["dst_port"] == 22 for alert in alerts)
    assert all("malicious" in alert["explanation"].lower() or "not confirmation" in alert["explanation"].lower() for alert in alerts)
