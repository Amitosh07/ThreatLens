"""Download JSON and CSV reports for a completed analysis."""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Analysis
from app.services.report_generator import build_report, download_filename, report_csv, report_json

router = APIRouter()


@router.get("/analyses/{analysis_id}/report")
def download_report(
    analysis_id: str,
    format: str = Query(..., pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
) -> Response:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if analysis.status != "completed":
        raise HTTPException(
            status_code=409,
            detail="A report is available after analysis completes successfully.",
        )
    alerts = db.scalars(select(Alert).where(Alert.analysis_id == analysis.id).order_by(Alert.id)).all()
    report = build_report(analysis, list(alerts))
    if format == "json":
        content = report_json(report)
        media_type = "application/json"
        extension = "json"
    else:
        content = report_csv(report)
        media_type = "text/csv; charset=utf-8"
        extension = "csv"
    filename = download_filename(analysis.original_filename, analysis.id, extension)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
