"""Upload validation."""

from app.utils.files import captures_dir, safe_capture_path
from app.services.errors import UnsafePathError
from tests.conftest import upload
import pytest


def test_rejects_unsupported_extension(client):
    response = client.post(
        "/api/v1/uploads",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 400
    assert "pcap" in response.json()["detail"].lower()


def test_rejects_empty_file(client):
    response = upload(client, content=b"")
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_rejects_invalid_pcap_magic(client):
    response = upload(client, content=b"this is not a capture file")
    assert response.status_code == 400
    assert "not a valid" in response.json()["detail"].lower()
    assert list(captures_dir().glob("*")) == [] or all(path.name == ".gitkeep" for path in captures_dir().iterdir())


def test_rejects_pcapng_contents_with_pcap_extension(client):
    response = upload(client, filename="capture.pcap", content=b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    assert response.status_code == 400


def test_rejects_oversized_upload(client, monkeypatch):
    monkeypatch.setenv("THREATLENS_MAX_UPLOAD_BYTES", "32")
    from app.config import get_settings

    get_settings.cache_clear()
    response = upload(client, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    assert response.status_code == 413
    assert "32" in response.json()["detail"]
    stored = [path for path in captures_dir().iterdir() if path.name != ".gitkeep"]
    assert stored == []


def test_uses_server_filename_not_client_path(client, mock_parser):
    response = upload(client, filename="..\\..\\secret.pcap")
    assert response.status_code == 201
    body = response.json()
    assert body["original_filename"] == "secret.pcap"
    assert body["status"] == "queued"
    stored = [path for path in captures_dir().iterdir() if path.suffix == ".pcap"]
    assert len(stored) == 1
    assert stored[0].name != "secret.pcap"
    assert stored[0].name.endswith(".pcap")
    completed = client.get(f"/api/v1/analyses/{body['id']}")
    assert completed.json()["status"] == "completed"


def test_rejects_traversal_when_reading_storage():
    with pytest.raises(UnsafePathError):
        safe_capture_path("..\\secret.pcap")
