"""TShark discovery and the failure shown when it is unavailable."""

from pathlib import Path

import pytest

from app.services.errors import TsharkNotFoundError
from tests.conftest import upload


def test_resolve_uses_the_configured_executable(tmp_path, monkeypatch):
    executable = tmp_path / "tshark.exe"
    executable.write_bytes(b"")
    monkeypatch.setenv("THREATLENS_TSHARK_PATH", str(executable))
    from app.config import get_settings

    get_settings.cache_clear()
    from app.services.tshark_service import resolve_tshark

    assert Path(resolve_tshark()) == executable
    get_settings.cache_clear()


def test_missing_tshark_explains_how_to_configure_it(monkeypatch, tmp_path):
    missing = tmp_path / "missing-tshark.exe"
    monkeypatch.setenv("THREATLENS_TSHARK_PATH", str(missing))
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr("app.services.tshark_service.candidate_paths", lambda: [str(missing)])
    from app.services.tshark_service import resolve_tshark

    with pytest.raises(TsharkNotFoundError) as caught:
        resolve_tshark()
    message = caught.value.message
    assert "THREATLENS_TSHARK_PATH" in message
    assert "Wireshark" in message
    assert "not run" in message or "not skipped" in message or "not found" in message
    get_settings.cache_clear()


def test_analysis_fails_clearly_when_tshark_is_unavailable(client, monkeypatch):
    def missing():
        raise TsharkNotFoundError(
            "TShark was not found. Install Wireshark and set THREATLENS_TSHARK_PATH "
            r"to C:\Program Files\Wireshark\tshark.exe."
        )

    monkeypatch.setattr("app.services.analysis_runner.resolve_tshark", missing)
    created = upload(client)
    assert created.status_code == 201
    detail = client.get(f"/api/v1/analyses/{created.json()['id']}").json()
    assert detail["status"] == "failed"
    assert "THREATLENS_TSHARK_PATH" in detail["error_message"]
    assert detail["packet_count"] == 0
    assert "Traceback" not in detail["error_message"]
