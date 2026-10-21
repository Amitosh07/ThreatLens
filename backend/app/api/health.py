"""Health endpoint."""

import logging

from fastapi import APIRouter
from sqlalchemy import text

from app.config import get_settings
from app.constants import DISCLAIMER
from app.database import get_engine
from app.schemas import HealthResponse
from app.services.tshark_service import check_tshark

router = APIRouter()
logger = logging.getLogger("threatlens.health")


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    database = "ok"
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Database health check failed")
        database = "error"
    tshark = check_tshark()
    if database != "ok":
        status = "error"
    elif not tshark["available"]:
        status = "degraded"
    else:
        status = "ok"
    return HealthResponse(
        status=status,
        app=get_settings().app_name,
        database=database,
        tshark=tshark,
        disclaimer=DISCLAIMER,
    )
