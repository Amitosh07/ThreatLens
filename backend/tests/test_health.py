"""Health endpoint."""


def test_health_reports_database_and_tshark(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["app"] == "ThreatLens"
    assert body["database"] == "ok"
    assert body["status"] in {"ok", "degraded"}
    assert isinstance(body["tshark"]["available"], bool)
    assert "malware-free" in body["disclaimer"]
    if body["tshark"]["available"]:
        assert body["tshark"]["path"]
        assert body["status"] == "ok"
    else:
        assert "Wireshark" in body["tshark"]["message"]
        assert body["status"] == "degraded"


def test_root_points_at_docs(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["health"] == "/api/v1/health"
