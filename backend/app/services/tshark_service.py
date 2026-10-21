"""Locate TShark without using a shell or a user-supplied command string."""

import logging
import os
import shutil
import subprocess
from pathlib import Path

from app.config import get_settings
from app.services.errors import TsharkNotFoundError

logger = logging.getLogger("threatlens.tshark")

SETUP_MESSAGE = (
    "TShark was not found. Install Wireshark, which includes TShark, or set "
    "THREATLENS_TSHARK_PATH in backend/.env to the full path of tshark.exe. "
    r"A common Windows location is C:\Program Files\Wireshark\tshark.exe. "
    "Restart the API after changing .env. Packet analysis is not run when TShark is missing."
)


def candidate_paths() -> list[str]:
    settings = get_settings()
    candidates: list[str] = []
    if settings.tshark_path:
        candidates.append(settings.tshark_path.strip().strip('"'))
    discovered = shutil.which("tshark")
    if discovered:
        candidates.append(discovered)
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if root:
            candidates.append(str(Path(root) / "Wireshark" / "tshark.exe"))
    candidates.append(r"C:\Program Files\Wireshark\tshark.exe")
    candidates.append(r"C:\Program Files (x86)\Wireshark\tshark.exe")
    unique: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def resolve_tshark() -> str:
    configured = (get_settings().tshark_path or "").strip().strip('"')
    for candidate in candidate_paths():
        if Path(candidate).is_file():
            return str(Path(candidate))
    message = SETUP_MESSAGE
    if configured and not Path(configured).is_file():
        message = f"The configured TShark path does not exist: {configured}. {SETUP_MESSAGE}"
    raise TsharkNotFoundError(message)


def tshark_version(path: str) -> str | None:
    try:
        completed = subprocess.run(
            [path, "-v"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Unable to read TShark version: %s", exc)
        return None
    output = (completed.stdout or completed.stderr or "").strip()
    if not output:
        return None
    return output.splitlines()[0].strip()


def check_tshark() -> dict:
    try:
        path = resolve_tshark()
    except TsharkNotFoundError as exc:
        return {"available": False, "path": None, "version": None, "message": exc.message}
    return {"available": True, "path": path, "version": tshark_version(path), "message": None}
