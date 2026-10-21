"""Analysis listing, detail, rerun, summary, hosts, and packets."""

import math

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import String, asc, cast, delete, desc, func, or_, select
from sqlalchemy.orm import Session

from app.constants import DISCLAIMER
from app.database import get_db
from app.models import Alert, Analysis, Packet
from app.schemas import AnalysisDetail, AnalysisPage, OverviewResponse, PacketPage
from app.serializers import analysis_brief, analysis_detail, alert_out, packet_out
from app.services.analysis_runner import process_analysis
from app.services.tshark_service import check_tshark

router = APIRouter()

PACKET_SORTS = {
    "packet_number": Packet.packet_number,
    "timestamp": Packet.timestamp,
    "length": Packet.length,
    "protocol": Packet.protocol,
}


def _pages(total: int, page_size: int) -> int:
    if total <= 0:
        return 0
    return math.ceil(total / page_size)


def _get_analysis(db: Session, analysis_id: str) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


def _require_completed(analysis: Analysis) -> Analysis:
    if analysis.status != "completed":
        raise HTTPException(
            status_code=409,
            detail="Results are available after analysis completes successfully.",
        )
    return analysis


def _like(column, text: str):
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.like(f"%{escaped}%", escape="\\")


@router.get("/overview", response_model=OverviewResponse)
def overview(
    analysis_id: str | None = None,
    db: Session = Depends(get_db),
) -> OverviewResponse:
    total = db.scalar(select(func.count()).select_from(Analysis)) or 0
    recent = db.scalars(select(Analysis).order_by(Analysis.created_at.desc()).limit(8)).all()
    if analysis_id:
        selected = _get_analysis(db, analysis_id)
    else:
        selected = next((row for row in recent if row.status == "completed"), None)
        if selected is None and recent:
            selected = recent[0]
    recent_alerts = db.scalars(select(Alert).order_by(Alert.id.desc()).limit(8)).all()
    counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    if selected is not None:
        grouped = db.execute(
            select(Alert.severity, func.count())
            .where(Alert.analysis_id == selected.id)
            .group_by(Alert.severity)
        ).all()
        for severity, count in grouped:
            if severity in counts:
                counts[severity] = count
    return OverviewResponse(
        total_analyses=total,
        selected_analysis=None if selected is None else analysis_detail(selected),
        recent_analyses=[analysis_brief(row) for row in recent],
        recent_alerts=[alert_out(row) for row in recent_alerts],
        alert_severity_counts=counts,
        disclaimer=DISCLAIMER,
        tshark=check_tshark(),
    )


@router.get("/analyses", response_model=AnalysisPage)
def list_analyses(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    q: str | None = Query(None),
    db: Session = Depends(get_db),
) -> AnalysisPage:
    stmt = select(Analysis)
    if status:
        if status not in {"queued", "processing", "completed", "failed"}:
            raise HTTPException(status_code=400, detail="Unknown analysis status.")
        stmt = stmt.where(Analysis.status == status)
    if q and q.strip():
        stmt = stmt.where(_like(Analysis.original_filename, q.strip()))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Analysis.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return AnalysisPage(
        items=[analysis_brief(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=_pages(total, page_size),
    )


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: str, db: Session = Depends(get_db)) -> AnalysisDetail:
    return analysis_detail(_get_analysis(db, analysis_id))


@router.post("/analyses/{analysis_id}/run", response_model=AnalysisDetail)
def run_analysis(
    analysis_id: str,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
) -> AnalysisDetail:
    analysis = _get_analysis(db, analysis_id)
    if analysis.status == "processing":
        raise HTTPException(status_code=409, detail="This analysis is already running.")
    db.execute(delete(Packet).where(Packet.analysis_id == analysis.id))
    db.execute(delete(Alert).where(Alert.analysis_id == analysis.id))
    analysis.status = "queued"
    analysis.error_message = None
    analysis.started_at = None
    analysis.completed_at = None
    analysis.duration_ms = None
    analysis.packet_count = 0
    analysis.total_bytes = 0
    analysis.alert_count = 0
    analysis.summary_json = None
    analysis.rule_snapshot_json = None
    db.commit()
    db.refresh(analysis)
    background.add_task(process_analysis, analysis.id)
    return analysis_detail(analysis)


@router.get("/analyses/{analysis_id}/summary")
def analysis_summary(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    analysis = _require_completed(_get_analysis(db, analysis_id))
    return {
        "analysis_id": analysis.id,
        "original_filename": analysis.original_filename,
        "packet_count": analysis.packet_count,
        "total_bytes": analysis.total_bytes,
        "duration_ms": analysis.duration_ms,
        "summary": analysis.summary_json,
        "rule_snapshot": analysis.rule_snapshot_json,
    }


@router.get("/analyses/{analysis_id}/hosts")
def analysis_hosts(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    analysis = _require_completed(_get_analysis(db, analysis_id))
    summary = analysis.summary_json or {}
    return {
        "analysis_id": analysis.id,
        "unique_source_hosts": summary.get("unique_source_hosts", 0),
        "unique_destination_hosts": summary.get("unique_destination_hosts", 0),
        "unique_hosts": summary.get("unique_hosts", 0),
        "top_sources": summary.get("top_sources", []),
        "top_destinations": summary.get("top_destinations", []),
        "top_pairs": summary.get("top_pairs", []),
        "top_source_ports": summary.get("top_source_ports", []),
        "top_destination_ports": summary.get("top_destination_ports", []),
        "definitions": summary.get("definitions", {}),
    }


@router.get("/analyses/{analysis_id}/packets", response_model=PacketPage)
def analysis_packets(
    analysis_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = Query(None, ge=0, le=65535),
    dst_port: int | None = Query(None, ge=0, le=65535),
    q: str | None = None,
    numbers: str | None = None,
    sort: str = "packet_number",
    order: str = "asc",
    db: Session = Depends(get_db),
) -> PacketPage:
    analysis = _require_completed(_get_analysis(db, analysis_id))
    if sort not in PACKET_SORTS:
        raise HTTPException(status_code=400, detail="Unsupported packet sort.")
    if order not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="Sort order must be asc or desc.")
    stmt = select(Packet).where(Packet.analysis_id == analysis.id)
    if protocol:
        stmt = stmt.where(func.upper(Packet.protocol) == protocol.strip().upper())
    if src_ip:
        stmt = stmt.where(Packet.src_ip == src_ip.strip())
    if dst_ip:
        stmt = stmt.where(Packet.dst_ip == dst_ip.strip())
    if src_port is not None:
        stmt = stmt.where(Packet.src_port == src_port)
    if dst_port is not None:
        stmt = stmt.where(Packet.dst_port == dst_port)
    if q and q.strip():
        term = q.strip()
        stmt = stmt.where(
            or_(
                _like(Packet.src_ip, term),
                _like(Packet.dst_ip, term),
                _like(Packet.protocol, term),
                _like(cast(Packet.src_port, String), term),
                _like(cast(Packet.dst_port, String), term),
            )
        )
    if numbers:
        parsed: list[int] = []
        for part in numbers.split(","):
            part = part.strip()
            if not part:
                continue
            if not part.isdigit():
                raise HTTPException(status_code=400, detail="Packet numbers must be positive integers.")
            parsed.append(int(part))
            if len(parsed) > 200:
                raise HTTPException(status_code=400, detail="Request 200 packet numbers or fewer.")
        stmt = stmt.where(Packet.packet_number.in_(parsed or [-1]))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    direction = asc if order == "asc" else desc
    rows = db.scalars(
        stmt.order_by(direction(PACKET_SORTS[sort]), Packet.packet_number)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return PacketPage(
        items=[packet_out(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=_pages(total, page_size),
    )
