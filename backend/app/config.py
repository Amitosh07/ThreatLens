"""Runtime configuration loaded from the environment and backend/.env."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    app_name: str = "ThreatLens"
    database_url: str = "sqlite:///./threatlens.db"
    storage_dir: str = "./storage"
    max_upload_bytes: int = Field(default=50 * 1024 * 1024, ge=1)
    max_packets: int = Field(default=100_000, ge=1)
    max_processing_seconds: int = Field(default=300, ge=1)
    tshark_path: str | None = None
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    model_config = SettingsConfigDict(
        env_prefix="THREATLENS_",
        env_file=str(BACKEND_ROOT / ".env"),
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def storage_path(self) -> Path:
        path = Path(self.storage_dir)
        if not path.is_absolute():
            path = BACKEND_ROOT / path
        return path.resolve()

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url
        prefix = "sqlite:///"
        if not url.startswith(prefix):
            return url
        raw = url[len(prefix) :]
        if raw == ":memory:" or raw.startswith("file:"):
            return url
        path = Path(raw)
        if not path.is_absolute():
            path = BACKEND_ROOT / path
        return prefix + path.resolve().as_posix()


@lru_cache
def get_settings() -> Settings:
    return Settings()
