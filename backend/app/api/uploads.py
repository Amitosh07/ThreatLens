"""PCAP upload validation and storage."""

import hashlib
import logging
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import Analysis
from app.schemas import AnalysisBrief
from app.serializers import analysis_brief
from app.services.analysis_runner import process_analysis
from app.utils.files import (
    captures_dir,
    extension_of,
    sanitize_original_name,
    validate_extension,
    validate_magic,
)
from app.utils.time import utcnow

router = APIRouter()
logger = logging.getLogger("threatlens.uploads")


@router.post("/uploads", response_model=AnalysisBrief, status_code=201)
async def upload_capture(
    background: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> AnalysisBrief:
    if not file.filename:
        raise HTTPException(status_code=400, detail="A file name is required.")
    try:
        original_name = sanitize_original_name(file.filename)
        extension = extension_of(original_name)
        validate_extension(extension)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    settings = get_settings()
    stored_name = f"{uuid4().hex}{extension}"
    destination = captures_dir() / stored_name
    digest = hashlib.sha256()
    size = 0
    magic = b""
    try:
        with destination.open("wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                if size == 0:
                    magic = chunk[:4]
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds the {settings.max_upload_bytes} byte upload limit.",
                    )
                digest.update(chunk)
                handle.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")
        try:
            validate_magic(magic, extension)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        analysis = Analysis(
            id=str(uuid4()),
            original_filename=original_name,
            stored_filename=stored_name,
            file_size=size,
            file_hash=digest.hexdigest(),
            status="queued",
            created_at=utcnow(),
            packet_count=0,
            total_bytes=0,
            alert_count=0,
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
    except HTTPException:
        destination.unlink(missing_ok=True)
        raise
    except Exception as exc:
        destination.unlink(missing_ok=True)
        logger.exception("Upload failed")
        raise HTTPException(status_code=500, detail="The file could not be stored.") from exc
    finally:
        await file.close()

    background.add_task(process_analysis, analysis.id)
    return analysis_brief(analysis)
