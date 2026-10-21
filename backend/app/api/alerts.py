"""Alert listing and evidence lookup."""

import math

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Analysis, Packet
from app.schemas import AlertOut, AlertPage
from app.serializers import alert_out

router = APIRouter()

SEVERITY_ORDER = case(
    (Alert.severity == "critical", 5),
    (Alert.severity == "high", 4),
    (Alert.severity == "medium", 3),
    (Alert.severity == "low", 2),
    (Alert.severity == "info", 1),
    else_=0,
)


def _pages(total: int, page_size: int) -> int:
    if total <= 0:
        return 0
    return math.ceil(total / page_size)


def _like(column, text: str):
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.like(f"%{escaped}%", escape="\\")


def _filtered_alerts(
    db: Session,
    analysis_id: str | None,
    severity: str | None,
    rule_key: str | None,
    q: str | None,
):
    stmt = select(Alert)
    if analysis_id:
        stmt = stmt.where(Alert.analysis_id == analysis_id)
    if severity:
        if severity not in {"info", "low", "medium", "high", "critical"}:
            raise HTTPException(status_code=400, detail="Unknown severity.")
        stmt = stmt.where(Alert.severity == severity)
    if rule_key:
        stmt = stmt.where(Alert.rule_key == rule_key)
    if q and q.strip():
        term = q.strip()
        stmt = stmt.where(
            or_(
                _like(Alert.rule_name, term),
                _like(Alert.description, term),
                _like(Alert.src_ip, term),
                _like(Alert.dst_ip, term),
                _like(Alert.observed_value, term),
            )
        )
    return stmt


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    analysis_id: str | None = None,
    severity: str | None = None,
    rule_key: str | None = None,
    q: str | None = None,
    sort: str = "severity",
    order: str = "desc",
    db: Session = Depends(get_db),
) -> AlertPage:
    if sort not in {"severity", "id", "rule_name", "window_start"}:
        raise HTTPException(status_code=400, detail="Unsupported alert sort.")
    if order not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="Sort order must be asc or desc.")
    stmt = _filtered_alerts(db, analysis_id, severity, rule_key, q)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    sort_column = {
        "severity": SEVERITY_ORDER,
        "id": Alert.id,
        "rule_name": Alert.rule_name,
        "window_start": Alert.window_start,
    }[sort]
    ordering = sort_column.desc() if order == "desc" else sort_column.asc()
    rows = db.scalars(stmt.order_by(ordering, Alert.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return AlertPage(
        items=[alert_out(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=_pages(total, page_size),
    )


@router.get("/analyses/{analysis_id}/alerts", response_model=AlertPage)
def analysis_alerts(
    analysis_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    severity: str | None = None,
    rule_key: str | None = None,
    q: str | None = None,
    sort: str = "severity",
    order: str = "desc",
    db: Session = Depends(get_db),
) -> AlertPage:
    if db.get(Analysis, analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return list_alerts(
        page=page,
        page_size=page_size,
        analysis_id=analysis_id,
        severity=severity,
        rule_key=rule_key,
        q=q,
        sort=sort,
        order=order,
        db=db,
    )


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    numbers = list(alert.packet_numbers or [])[:100]
    packets = []
    if numbers:
        packets = db.scalars(
            select(Packet)
            .where(Packet.analysis_id == alert.analysis_id, Packet.packet_number.in_(numbers))
            .order_by(Packet.packet_number)
        ).all()
    return alert_out(alert, packets=packets)
