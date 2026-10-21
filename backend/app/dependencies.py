"""Database session dependency re-export."""

from app.database import get_db

__all__ = ["get_db"]
