"""Analysis API, status transitions, pagination, and rule snapshots."""

from app.services.errors import CaptureParseError
from app.services.pcap_parser import ParseResult
from tests.conftest import packet, upload


def _completed(client, mock_parser, packets):
    mock_parser["packets"] = packets
    created = upload(client)
    assert created.status_code == 201, created.text
    analysis_id = created.json()["id"]
    detail = client.get(f"/api/v1/analyses/{analysis_id}")
    assert detail.status_code == 200, detail.text
    return analysis_id, detail.json()


def test_statistics_match_stored_packets_and_missing_fields(client, mock_parser):
    packets = [
        packet(packet_number=1, protocol="TCP", src_ip="10.0.0.1", dst_ip="10.0.0.2", length=100, transport="TCP"),
        packet(
            packet_number=2,
            protocol="UDP",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.3",
            length=50,
            src_port=53,
            dst_port=53,
            transport="UDP",
            tcp_flags=None,
            timestamp=1_700_000_010,
        ),
        packet(
            packet_number=3,
            protocol="ARP",
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            length=42,
            transport=None,
            tcp_flags=None,
            timestamp=1_700_000_020,
        ),
    ]
    analysis_id, detail = _completed(client, mock_parser, packets)
    assert detail["status"] == "completed"
    assert detail["packet_count"] == 3
    assert detail["total_bytes"] == 192
    assert detail["summary"]["unique_source_hosts"] == 1
    assert detail["summary"]["unique_destination_hosts"] == 2
    assert detail["summary"]["unique_hosts"] == 3
    assert detail["rule_snapshot"]

    first_page = client.get(f"/api/v1/analyses/{analysis_id}/packets", params={"page_size": 2})
    assert first_page.status_code == 200
    assert first_page.json()["total"] == 3
    assert len(first_page.json()["items"]) == 2
    assert first_page.json()["pages"] == 2
    second_page = client.get(f"/api/v1/analyses/{analysis_id}/packets", params={"page": 2, "page_size": 2})
    assert len(second_page.json()["items"]) == 1

    arp = client.get(f"/api/v1/analyses/{analysis_id}/packets", params={"protocol": "ARP"}).json()
    assert arp["items"][0]["src_ip"] is None
    assert arp["items"][0]["src_port"] is None
    assert arp["items"][0]["dst_port"] is None

    hosts = client.get(f"/api/v1/analyses/{analysis_id}/hosts").json()
    assert hosts["unique_hosts"] == detail["summary"]["unique_hosts"]
    assert hosts["top_sources"][0]["packets"] == 2


def test_packet_pagination_for_a_larger_result(client, mock_parser):
    packets = [
        packet(packet_number=index, timestamp=1_700_000_000 + index, src_port=10000 + index, dst_port=80)
        for index in range(1, 31)
    ]
    analysis_id, _detail = _completed(client, mock_parser, packets)
    page = client.get(
        f"/api/v1/analyses/{analysis_id}/packets",
        params={"page": 3, "page_size": 10, "sort": "packet_number", "order": "asc"},
    ).json()
    assert page["total"] == 30
    assert [item["packet_number"] for item in page["items"]] == list(range(21, 31))


def test_processing_status_is_visible_and_failure_is_stored(client, monkeypatch):
    seen = {}

    def fake_parse(path, tshark_path, max_packets, max_seconds):
        from sqlalchemy import select

        from app.database import SessionLocal
        from app.models import Analysis

        db = SessionLocal()
        try:
            seen["status"] = db.scalars(select(Analysis)).one().status
        finally:
            db.close()
        raise CaptureParseError("TShark could not read this capture. The file may be truncated.")

    monkeypatch.setattr("app.services.analysis_runner.parse_capture", fake_parse)
    monkeypatch.setattr("app.services.analysis_runner.resolve_tshark", lambda: r"C:\tshark.exe")
    created = upload(client)
    analysis_id = created.json()["id"]
    detail = client.get(f"/api/v1/analyses/{analysis_id}").json()
    assert seen["status"] == "processing"
    assert detail["status"] == "failed"
    assert "truncated" in detail["error_message"].lower()
    assert "Traceback" not in detail["error_message"]
    packets = client.get(f"/api/v1/analyses/{analysis_id}/packets")
    assert packets.status_code == 409
    report = client.get(f"/api/v1/analyses/{analysis_id}/report", params={"format": "json"})
    assert report.status_code == 409


def test_rule_changes_do_not_rewrite_completed_analyses(client, mock_parser):
    packets = [
        packet(packet_number=index, timestamp=1_700_000_000 + index, dst_port=80 + index, tcp_flags="SYN")
        for index in range(1, 4)
    ]
    first_id, first = _completed(client, mock_parser, packets)
    assert first["alert_count"] == 0
    assert first["rule_snapshot"]
    port_rule = next(item for item in first["rule_snapshot"] if item["rule_key"] == "port_scan")
    assert port_rule["parameters"]["distinct_ports"] == 20

    rules = client.get("/api/v1/rules").json()
    rule_id = next(item["id"] for item in rules if item["rule_key"] == "port_scan")
    updated = client.patch(f"/api/v1/rules/{rule_id}", json={"parameters": {"distinct_ports": 3}})
    assert updated.status_code == 200

    unchanged = client.get(f"/api/v1/analyses/{first_id}").json()
    assert unchanged["alert_count"] == 0
    stored_rule = next(item for item in unchanged["rule_snapshot"] if item["rule_key"] == "port_scan")
    assert stored_rule["parameters"]["distinct_ports"] == 20
    assert client.get("/api/v1/analyses", params={"q": "lab"}).json()["total"] == 1

    second_id, second = _completed(client, mock_parser, packets)
    assert second_id != first_id
    assert any(alert["rule_key"] == "port_scan" for alert in client.get("/api/v1/alerts", params={"analysis_id": second_id}).json()["items"])
    assert client.get("/api/v1/alerts", params={"analysis_id": first_id}).json()["total"] == 0


def test_disabled_rule_is_skipped_until_enabled(client, mock_parser):
    rules = client.get("/api/v1/rules").json()
    rule_id = next(item["id"] for item in rules if item["rule_key"] == "sensitive_port")
    disabled = client.patch(f"/api/v1/rules/{rule_id}", json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    packets = [packet(packet_number=1, dst_port=22, tcp_flags="SYN")]
    _analysis_id, detail = _completed(client, mock_parser, packets)
    assert detail["alert_count"] == 0

    enabled = client.patch(
        f"/api/v1/rules/{rule_id}",
        json={"enabled": True, "severity": "high", "parameters": {"ports": [22]}},
    )
    assert enabled.status_code == 200
    rerun = client.post(f"/api/v1/analyses/{detail['id']}/run")
    assert rerun.status_code == 200
    completed = client.get(f"/api/v1/analyses/{detail['id']}").json()
    assert completed["status"] == "completed"
    alerts = client.get(f"/api/v1/analyses/{detail['id']}/alerts").json()["items"]
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["dst_port"] == 22
    evidence = client.get(f"/api/v1/alerts/{alerts[0]['id']}").json()
    assert evidence["packets"][0]["dst_port"] == 22
    assert evidence["packet_numbers"] == [1]


def test_failed_rerun_does_not_leave_a_completed_status(client, mock_parser):
    analysis_id, detail = _completed(client, mock_parser, [packet(packet_number=1, dst_port=80)])
    assert detail["status"] == "completed"
    mock_parser["error"] = CaptureParseError("TShark could not read this capture.")
    rerun = client.post(f"/api/v1/analyses/{analysis_id}/run")
    assert rerun.status_code == 200
    failed = client.get(f"/api/v1/analyses/{analysis_id}").json()
    assert failed["status"] == "failed"
    assert client.get(f"/api/v1/analyses/{analysis_id}/packets").status_code == 409


def test_alert_filters_and_pagination(client, mock_parser):
    packets = [
        packet(packet_number=index, src_ip=f"10.9.0.{index}", dst_ip="10.9.1.1", dst_port=22, timestamp=1_700_000_000 + index)
        for index in range(1, 16)
    ]
    analysis_id, _detail = _completed(client, mock_parser, packets)
    page = client.get(
        "/api/v1/alerts",
        params={"analysis_id": analysis_id, "severity": "low", "page_size": 10, "page": 2, "sort": "id", "order": "asc"},
    )
    assert page.status_code == 200
    body = page.json()
    assert body["total"] == 15
    assert len(body["items"]) == 5
    found = client.get("/api/v1/alerts", params={"q": "10.9.0.4"}).json()
    assert found["total"] == 1
    assert found["items"][0]["src_ip"] == "10.9.0.4"
    assert client.get("/api/v1/alerts/999999").status_code == 404


def test_invalid_rule_threshold_is_rejected(client):
    rules = client.get("/api/v1/rules").json()
    rule_id = next(item["id"] for item in rules if item["rule_key"] == "port_scan")
    response = client.patch(f"/api/v1/rules/{rule_id}", json={"parameters": {"distinct_ports": 1}})
    assert response.status_code == 422
    sensitive = next(item["id"] for item in rules if item["rule_key"] == "sensitive_port")
    bad_port = client.patch(f"/api/v1/rules/{sensitive}", json={"parameters": {"ports": [22, 99999]}})
    assert bad_port.status_code == 422
    current = next(item for item in client.get("/api/v1/rules").json() if item["id"] == rule_id)
    assert current["parameters"]["distinct_ports"] == 20


def test_rules_persist_across_a_new_process_startup(client):
    rules = client.get("/api/v1/rules").json()
    rule_id = next(item["id"] for item in rules if item["rule_key"] == "repeated_syn")
    saved = client.patch(f"/api/v1/rules/{rule_id}", json={"parameters": {"syn_count": 4}, "enabled": False})
    assert saved.status_code == 200
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as restarted:
        again = next(item for item in restarted.get("/api/v1/rules").json() if item["id"] == rule_id)
    assert again["enabled"] is False
    assert again["parameters"]["syn_count"] == 4
    assert again["parameters"]["window_seconds"] == 30


def test_interrupted_job_is_failed_on_startup(client):
    from app.database import SessionLocal
    from app.models import Analysis
    from app.utils.time import utcnow
    from fastapi.testclient import TestClient
    from app.main import create_app

    db = SessionLocal()
    analysis = Analysis(
        id="interrupted-job",
        original_filename="partial.pcap",
        stored_filename="partial.pcap",
        file_size=10,
        file_hash="abc",
        status="processing",
        created_at=utcnow(),
    )
    db.add(analysis)
    db.commit()
    db.close()
    with TestClient(create_app()) as restarted:
        detail = restarted.get("/api/v1/analyses/interrupted-job").json()
    assert detail["status"] == "failed"
    assert "interrupted" in detail["error_message"].lower()


def test_parser_limit_warning_is_stored(client, mock_parser):
    mock_parser["warnings"] = ["Processing stopped after 2 packets because THREATLENS_MAX_PACKETS was reached."]
    _analysis_id, detail = _completed(client, mock_parser, [packet(packet_number=1)])
    assert detail["status"] == "completed"
    assert detail["summary"]["warnings"]
