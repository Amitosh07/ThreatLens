"""Shared API test fixtures."""

import pytest
from fastapi.testclient import TestClient

from app.services.pcap_parser import PacketRecord


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "test.db"
    storage = tmp_path / "storage"
    monkeypatch.setenv("THREATLENS_DATABASE_URL", f"sqlite:///{database_path.resolve().as_posix()}")
    monkeypatch.setenv("THREATLENS_STORAGE_DIR", str(storage))
    monkeypatch.setenv("THREATLENS_MAX_UPLOAD_BYTES", "52428800")
    monkeypatch.setenv("THREATLENS_MAX_PACKETS", "1000")
    monkeypatch.setenv("THREATLENS_MAX_PROCESSING_SECONDS", "30")
    from app.config import get_settings
    from app.database import reset_database_state

    get_settings.cache_clear()
    reset_database_state()
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
    reset_database_state()
    get_settings.cache_clear()


@pytest.fixture
def mock_parser(monkeypatch):
    from app.services.pcap_parser import ParseResult

    state = {"packets": [], "warnings": [], "error": None, "calls": 0}

    def fake_parse(path, tshark_path, max_packets, max_seconds):
        state["calls"] += 1
        if state["error"] is not None:
            raise state["error"]
        warnings = list(state["warnings"])
        packets = list(state["packets"])
        if len(packets) > max_packets:
            warnings.append(f"Processing stopped after {max_packets} packets.")
            packets = packets[:max_packets]
        return ParseResult(packets=packets, warnings=warnings)

    monkeypatch.setattr("app.services.analysis_runner.parse_capture", fake_parse)
    monkeypatch.setattr(
        "app.services.analysis_runner.resolve_tshark",
        lambda: r"C:\Program Files\Wireshark\tshark.exe",
    )
    return state


def packet(**overrides) -> PacketRecord:
    values = {
        "packet_number": 1,
        "timestamp": 1_700_000_000.0,
        "length": 60,
        "protocol": "TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 40000,
        "dst_port": 80,
        "transport": "TCP",
        "tcp_flags": "SYN",
        "icmp_type": None,
        "icmp_code": None,
    }
    values.update(overrides)
    return PacketRecord(**values)


def upload(client, filename="lab.pcap", content=None):
    if content is None:
        from app.utils.synthetic_pcap import build_pcap, icmp_frame

        content = build_pcap([icmp_frame("10.0.0.8", "10.0.0.9")])
    return client.post(
        "/api/v1/uploads",
        files={"file": (filename, content, "application/vnd.tcpdump.pcap")},
    )
