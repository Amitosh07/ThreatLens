"""Map database rows to API schemas."""

from copy import deepcopy
from datetime import datetime, timezone

from app.models import Alert, Analysis, Packet
from app.schemas import AlertOut, AnalysisBrief, AnalysisDetail, PacketOut, RuleOut
from app.services.rule_catalog import get_rule_definition
from app.utils.time import as_utc


def _timestamp_iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def packet_out(row: Packet) -> PacketOut:
    return PacketOut(
        packet_number=row.packet_number,
        timestamp=row.timestamp,
        timestamp_iso=_timestamp_iso(row.timestamp),
        length=row.length,
        protocol=row.protocol,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        src_port=row.src_port,
        dst_port=row.dst_port,
        transport=row.transport,
        tcp_flags=row.tcp_flags,
        icmp_type=row.icmp_type,
        icmp_code=row.icmp_code,
    )


def analysis_brief(row: Analysis) -> AnalysisBrief:
    return AnalysisBrief(
        id=row.id,
        original_filename=row.original_filename,
        file_size=row.file_size,
        file_hash=row.file_hash,
        status=row.status,
        created_at=as_utc(row.created_at),
        started_at=as_utc(row.started_at),
        completed_at=as_utc(row.completed_at),
        duration_ms=row.duration_ms,
        packet_count=row.packet_count,
        total_bytes=row.total_bytes,
        alert_count=row.alert_count,
        error_message=row.error_message,
    )


def analysis_detail(row: Analysis) -> AnalysisDetail:
    brief = analysis_brief(row)
    return AnalysisDetail(
        **brief.model_dump(),
        summary=row.summary_json,
        rule_snapshot=row.rule_snapshot_json,
    )


def alert_out(row: Alert, packets: list[Packet] | None = None) -> AlertOut:
    return AlertOut(
        id=row.id,
        analysis_id=row.analysis_id,
        rule_key=row.rule_key,
        rule_name=row.rule_name,
        severity=row.severity,
        evidence_strength=row.evidence_strength,
        description=row.description,
        explanation=row.explanation,
        src_ip=row.src_ip,
        dst_ip=row.dst_ip,
        src_port=row.src_port,
        dst_port=row.dst_port,
        window_start=row.window_start,
        window_end=row.window_end,
        observed_value=row.observed_value,
        threshold_value=row.threshold_value,
        packet_numbers=list(row.packet_numbers or []),
        evidence=dict(row.evidence or {}),
        created_at=as_utc(row.created_at),
        packets=None if packets is None else [packet_out(packet) for packet in packets],
    )


def rule_out(row) -> RuleOut:
    definition = get_rule_definition(row.rule_key)
    schema = deepcopy(definition["parameter_schema"]) if definition else []
    return RuleOut(
        id=row.id,
        rule_key=row.rule_key,
        name=row.name,
        description=row.description,
        enabled=row.enabled,
        severity=row.severity,
        parameters=deepcopy(row.parameters or {}),
        parameter_schema=schema,
        updated_at=as_utc(row.updated_at),
    )
