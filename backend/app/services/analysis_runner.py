"""Run a queued analysis outside the upload request."""

from concurrent.futures import ThreadPoolExecutor
import logging
import threading
import time

from sqlalchemy import delete, select

from app.config import get_settings
from app.database import SessionLocal
from app.models import Alert, Analysis, DetectionRule, Packet
from app.services.detection_engine import run_detection
from app.services.errors import ThreatLensError
from app.services.pcap_parser import parse_capture
from app.services.rule_catalog import snapshot_from_rule
from app.services.traffic_analyzer import build_summary
from app.services.tshark_service import resolve_tshark
from app.utils.files import safe_capture_path
from app.utils.time import utcnow

logger = logging.getLogger("threatlens.runner")

_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


def _lock_for(analysis_id: str) -> threading.Lock:
    with _guard:
        lock = _locks.get(analysis_id)
        if lock is None:
            lock = threading.Lock()
            _locks[analysis_id] = lock
        return lock


def user_message(exc: Exception | None) -> str:
    if isinstance(exc, ThreatLensError):
        return exc.message[:500]
    return "Analysis failed while processing the capture."


def _mark_failed(analysis_id: str, exc: Exception | None) -> None:
    db = SessionLocal()
    try:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            return
        finished = utcnow()
        analysis.status = "failed"
        analysis.completed_at = finished
        analysis.error_message = user_message(exc)
        if analysis.started_at is not None:
            started = analysis.started_at
            if started.tzinfo is None and finished.tzinfo is not None:
                started = started.replace(tzinfo=finished.tzinfo)
            analysis.duration_ms = max(0, int((finished - started).total_seconds() * 1000))
        db.commit()
    finally:
        db.close()


def _parse_with_timeout(path, tshark_path: str, max_packets: int, max_seconds: int):
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pcap-parse")
    future = executor.submit(parse_capture, path, tshark_path, max_packets, max_seconds)
    try:
        return future.result(timeout=max_seconds + 5)
    except TimeoutError as exc:
        from app.services.errors import AnalysisTimeoutError

        raise AnalysisTimeoutError(
            "Analysis exceeded the configured processing time limit. "
            "Increase THREATLENS_MAX_PROCESSING_SECONDS or upload a smaller capture."
        ) from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _store_results(db, analysis: Analysis, packets, summary: dict, drafts) -> None:
    db.execute(delete(Packet).where(Packet.analysis_id == analysis.id))
    db.execute(delete(Alert).where(Alert.analysis_id == analysis.id))
    batch: list[Packet] = []
    for record in packets:
        batch.append(
            Packet(
                analysis_id=analysis.id,
                packet_number=record.packet_number,
                timestamp=record.timestamp,
                length=record.length,
                protocol=record.protocol,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                src_port=record.src_port,
                dst_port=record.dst_port,
                transport=record.transport,
                tcp_flags=record.tcp_flags,
                icmp_type=record.icmp_type,
                icmp_code=record.icmp_code,
            )
        )
        if len(batch) >= 1000:
            db.add_all(batch)
            db.flush()
            batch = []
    if batch:
        db.add_all(batch)
    for draft in drafts:
        db.add(
            Alert(
                analysis_id=analysis.id,
                rule_key=draft.rule_key,
                rule_name=draft.rule_name,
                severity=draft.severity,
                evidence_strength=draft.evidence_strength,
                description=draft.description,
                explanation=draft.explanation,
                src_ip=draft.src_ip,
                dst_ip=draft.dst_ip,
                src_port=draft.src_port,
                dst_port=draft.dst_port,
                window_start=draft.window_start,
                window_end=draft.window_end,
                observed_value=draft.observed_value,
                threshold_value=draft.threshold_value,
                packet_numbers=draft.packet_numbers,
                evidence=draft.evidence,
            )
        )
    analysis.packet_count = summary["packet_count"]
    analysis.total_bytes = summary["total_bytes"]
    analysis.alert_count = len(drafts)
    analysis.summary_json = summary


def process_analysis(analysis_id: str) -> None:
    """Parse, summarize, and score one queued capture.

    This runs in a FastAPI background task, not a distributed job queue.
    A restart marks leftover queued or processing rows as failed.
    """
    lock = _lock_for(analysis_id)
    if not lock.acquire(blocking=False):
        return
    try:
        settings = get_settings()
        db = SessionLocal()
        try:
            analysis = db.get(Analysis, analysis_id)
            if analysis is None or analysis.status != "queued":
                return
            rules = db.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()
            snapshot = [snapshot_from_rule(rule) for rule in rules]
            analysis.status = "processing"
            analysis.started_at = utcnow()
            analysis.error_message = None
            analysis.rule_snapshot_json = snapshot
            stored_filename = analysis.stored_filename
            db.commit()
        finally:
            db.close()

        started = time.perf_counter()
        try:
            tshark_path = resolve_tshark()
            capture_path = safe_capture_path(stored_filename)
            if not capture_path.is_file():
                from app.services.errors import CaptureParseError

                raise CaptureParseError("The stored capture file is missing.")
            parsed = _parse_with_timeout(
                capture_path,
                tshark_path,
                settings.max_packets,
                settings.max_processing_seconds,
            )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            summary = build_summary(parsed.packets, processing_ms=elapsed_ms, warnings=parsed.warnings)
            drafts = run_detection(parsed.packets, snapshot)
        except Exception as exc:
            logger.exception("Analysis %s failed", analysis_id)
            _mark_failed(analysis_id, exc)
            return

        db = SessionLocal()
        try:
            analysis = db.get(Analysis, analysis_id)
            if analysis is None:
                return
            _store_results(db, analysis, parsed.packets, summary, drafts)
            analysis.status = "completed"
            analysis.completed_at = utcnow()
            analysis.duration_ms = elapsed_ms
            analysis.error_message = None
            db.commit()
        except Exception as exc:
            logger.exception("Analysis %s could not be stored", analysis_id)
            db.rollback()
            _mark_failed(analysis_id, exc)
        finally:
            db.close()
    finally:
        lock.release()
