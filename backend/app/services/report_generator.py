"""JSON and CSV reports from stored analysis results."""

import csv
import io
import json
import re
from pathlib import Path

from app.constants import DISCLAIMER
from app.utils.time import as_utc, utcnow


def _iso(value) -> str | None:
    moment = as_utc(value)
    if moment is None:
        return None
    return moment.isoformat()


def build_report(analysis, alerts: list) -> dict:
    return {
        "generator": "ThreatLens",
        "generated_at": utcnow().isoformat(),
        "disclaimer": DISCLAIMER,
        "analysis": {
            "id": analysis.id,
            "original_filename": analysis.original_filename,
            "file_size": analysis.file_size,
            "file_hash": analysis.file_hash,
            "status": analysis.status,
            "created_at": _iso(analysis.created_at),
            "started_at": _iso(analysis.started_at),
            "completed_at": _iso(analysis.completed_at),
            "duration_ms": analysis.duration_ms,
            "packet_count": analysis.packet_count,
            "total_bytes": analysis.total_bytes,
            "alert_count": analysis.alert_count,
        },
        "summary": analysis.summary_json,
        "rule_snapshot": analysis.rule_snapshot_json,
        "alerts": [
            {
                "id": alert.id,
                "rule_key": alert.rule_key,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "evidence_strength": alert.evidence_strength,
                "description": alert.description,
                "explanation": alert.explanation,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "window_start": alert.window_start,
                "window_end": alert.window_end,
                "observed_value": alert.observed_value,
                "threshold_value": alert.threshold_value,
                "packet_numbers": alert.packet_numbers,
                "evidence": alert.evidence,
            }
            for alert in alerts
        ],
    }


def report_json(report: dict) -> bytes:
    return json.dumps(report, indent=2).encode("utf-8")


def _flatten_summary(summary: dict | None) -> list[tuple[str, str, str]]:
    if not summary:
        return []
    rows = [
        ("summary", "packet_count", str(summary.get("packet_count", 0))),
        ("summary", "total_bytes", str(summary.get("total_bytes", 0))),
        ("summary", "unique_source_hosts", str(summary.get("unique_source_hosts", 0))),
        ("summary", "unique_destination_hosts", str(summary.get("unique_destination_hosts", 0))),
        ("summary", "unique_hosts", str(summary.get("unique_hosts", 0))),
        ("summary", "tcp_syn_attempts", str(summary.get("tcp_syn_attempts", 0))),
        ("summary", "tcp_syn_ack_responses", str(summary.get("tcp_syn_ack_responses", 0))),
        ("summary", "capture_start", "" if summary.get("capture_start") is None else str(summary.get("capture_start"))),
        ("summary", "capture_end", "" if summary.get("capture_end") is None else str(summary.get("capture_end"))),
    ]
    for item in summary.get("protocols") or []:
        rows.append(("protocol", item.get("protocol", ""), f"{item.get('packets', 0)} packets ({item.get('percentage', 0)}%)"))
    for item in summary.get("top_sources") or []:
        rows.append(("source_host", item.get("ip", ""), f"{item.get('packets', 0)} packets, {item.get('bytes', 0)} bytes"))
    for item in summary.get("top_destinations") or []:
        rows.append(("destination_host", item.get("ip", ""), f"{item.get('packets', 0)} packets, {item.get('bytes', 0)} bytes"))
    for item in summary.get("top_pairs") or []:
        rows.append(
            (
                "host_pair",
                f"{item.get('src_ip', '')} -> {item.get('dst_ip', '')}",
                f"{item.get('packets', 0)} packets, {item.get('bytes', 0)} bytes",
            )
        )
    return rows


def report_csv(report: dict) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "record_type",
            "analysis_id",
            "filename",
            "metric",
            "value",
            "alert_id",
            "rule_key",
            "rule_name",
            "severity",
            "evidence_strength",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "window_start",
            "window_end",
            "observed_value",
            "threshold_value",
            "packet_numbers",
            "description",
            "explanation",
        ]
    )
    analysis = report["analysis"]
    identity = (analysis["id"], analysis["original_filename"])
    writer.writerow(["disclaimer", *identity, "disclaimer", report["disclaimer"], *([""] * 16)])
    for key in (
        "file_hash",
        "status",
        "packet_count",
        "total_bytes",
        "duration_ms",
        "created_at",
        "started_at",
        "completed_at",
    ):
        writer.writerow(["metadata", *identity, key, analysis.get(key), *([""] * 16)])
    for record_type, metric, value in _flatten_summary(report.get("summary")):
        writer.writerow([record_type, *identity, metric, value, *([""] * 16)])
    for rule in report.get("rule_snapshot") or []:
        writer.writerow(
            [
                "rule_snapshot",
                *identity,
                rule.get("rule_key", ""),
                json.dumps(
                    {
                        "enabled": rule.get("enabled"),
                        "severity": rule.get("severity"),
                        "parameters": rule.get("parameters"),
                    }
                ),
                *([""] * 16),
            ]
        )
    for alert in report.get("alerts") or []:
        numbers = alert.get("packet_numbers") or []
        writer.writerow(
            [
                "alert",
                analysis["id"],
                analysis["original_filename"],
                alert.get("rule_key", ""),
                alert.get("observed_value", ""),
                alert.get("id", ""),
                alert.get("rule_key", ""),
                alert.get("rule_name", ""),
                alert.get("severity", ""),
                alert.get("evidence_strength", ""),
                alert.get("src_ip") or "",
                alert.get("dst_ip") or "",
                "" if alert.get("src_port") is None else alert.get("src_port"),
                "" if alert.get("dst_port") is None else alert.get("dst_port"),
                "" if alert.get("window_start") is None else alert.get("window_start"),
                "" if alert.get("window_end") is None else alert.get("window_end"),
                alert.get("observed_value") or "",
                alert.get("threshold_value") or "",
                " ".join(str(number) for number in numbers),
                alert.get("description") or "",
                alert.get("explanation") or "",
            ]
        )
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


def download_filename(original_filename: str, analysis_id: str, extension: str) -> str:
    stem = Path(original_filename).stem
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", stem).strip("_")[:60] or "capture"
    return f"threatlens-{stem}-{analysis_id[:8]}.{extension}"
