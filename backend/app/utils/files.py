"""Upload names, capture magic bytes, and safe storage paths."""

from pathlib import Path

from app.config import get_settings
from app.services.errors import UnsafePathError

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


def captures_dir() -> Path:
    path = get_settings().storage_path / "captures"
    path.mkdir(parents=True, exist_ok=True)
    return path


def sanitize_original_name(filename: str) -> str:
    cleaned = filename.replace("\\", "/").replace("\x00", "")
    name = Path(cleaned).name.strip()
    if not name or name in {".", ".."}:
        raise ValueError("A file name is required.")
    return name[:255]


def extension_of(filename: str) -> str:
    return Path(filename).suffix.lower()


def validate_extension(extension: str) -> None:
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng files are accepted.")


def validate_magic(prefix: bytes, extension: str) -> None:
    if len(prefix) < 4:
        raise ValueError("The file is too small to be a packet capture.")
    magic = prefix[:4]
    if extension == ".pcap" and magic not in PCAP_MAGICS:
        raise ValueError("The file content is not a valid classic PCAP capture.")
    if extension == ".pcapng" and magic != PCAPNG_MAGIC:
        raise ValueError("The file content is not a valid PCAPNG capture.")


def safe_capture_path(stored_filename: str) -> Path:
    if (
        not stored_filename
        or stored_filename != Path(stored_filename).name
        or ".." in stored_filename
        or "/" in stored_filename
        or "\\" in stored_filename
    ):
        raise UnsafePathError("The stored capture name is not valid.")
    root = captures_dir().resolve()
    path = (root / stored_filename).resolve()
    if path.parent != root:
        raise UnsafePathError("The stored capture name is not valid.")
    return path
