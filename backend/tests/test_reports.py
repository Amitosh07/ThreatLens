"""Report downloads."""

from tests.conftest import packet, upload


def test_json_and_csv_reports_include_real_results(client, mock_parser):
    mock_parser["packets"] = [
        packet(packet_number=1, dst_port=22, length=80, src_ip="10.4.0.1", dst_ip="10.4.0.2")
    ]
    created = upload(client, filename="branch-lab.pcap")
    analysis_id = created.json()["id"]
    detail = client.get(f"/api/v1/analyses/{analysis_id}").json()
    assert detail["status"] == "completed"
    assert detail["alert_count"] >= 1

    json_response = client.get(f"/api/v1/analyses/{analysis_id}/report", params={"format": "json"})
    assert json_response.status_code == 200
    assert "attachment" in json_response.headers["content-disposition"]
    assert json_response.headers["content-disposition"].endswith('.json"')
    report = json_response.json()
    assert report["analysis"]["id"] == analysis_id
    assert report["analysis"]["packet_count"] == 1
    assert report["summary"]["total_bytes"] == 80
    assert report["rule_snapshot"]
    assert any(alert["rule_key"] == "sensitive_port" for alert in report["alerts"])
    assert "malware-free" in report["disclaimer"]
    assert report["alerts"][0]["packet_numbers"]

    csv_response = client.get(f"/api/v1/analyses/{analysis_id}/report", params={"format": "csv"})
    assert csv_response.status_code == 200
    text = csv_response.content.decode("utf-8-sig")
    assert "sensitive_port" in text
    assert "10.4.0.1" in text
    assert "branch-lab.pcap" in text
    assert "record_type" in text


def test_unknown_analysis_report_is_not_found(client):
    response = client.get("/api/v1/analyses/missing/report", params={"format": "json"})
    assert response.status_code == 404
