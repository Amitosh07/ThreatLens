"""Pydantic request and response models."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TsharkStatus(BaseModel):
    available: bool
    path: str | None = None
    version: str | None = None
    message: str | None = None


class HealthResponse(BaseModel):
    status: str
    app: str
    database: str
    tshark: TsharkStatus
    disclaimer: str


class AnalysisBrief(BaseModel):
    id: str
    original_filename: str
    file_size: int
    file_hash: str
    status: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    packet_count: int
    total_bytes: int
    alert_count: int
    error_message: str | None = None


class AnalysisDetail(AnalysisBrief):
    summary: dict[str, Any] | None = None
    rule_snapshot: list[dict[str, Any]] | None = None


class AnalysisPage(BaseModel):
    items: list[AnalysisBrief]
    total: int
    page: int
    page_size: int
    pages: int


class PacketOut(BaseModel):
    packet_number: int
    timestamp: float
    timestamp_iso: str | None = None
    length: int
    protocol: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    transport: str | None = None
    tcp_flags: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None


class PacketPage(BaseModel):
    items: list[PacketOut]
    total: int
    page: int
    page_size: int
    pages: int


class AlertOut(BaseModel):
    id: int
    analysis_id: str
    rule_key: str
    rule_name: str
    severity: str
    evidence_strength: str
    description: str
    explanation: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    window_start: float | None = None
    window_end: float | None = None
    observed_value: str | None = None
    threshold_value: str | None = None
    packet_numbers: list[int] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    packets: list[PacketOut] | None = None


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int
    pages: int


class RuleOut(BaseModel):
    id: int
    rule_key: str
    name: str
    description: str
    enabled: bool
    severity: str
    parameters: dict[str, Any]
    parameter_schema: list[dict[str, Any]]
    updated_at: datetime


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    severity: str | None = None
    parameters: dict[str, Any] | None = None


class OverviewResponse(BaseModel):
    total_analyses: int
    selected_analysis: AnalysisDetail | None = None
    recent_analyses: list[AnalysisBrief]
    recent_alerts: list[AlertOut]
    alert_severity_counts: dict[str, int]
    disclaimer: str
    tshark: TsharkStatus
