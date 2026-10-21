"""Seed rules and recover jobs left behind by a restart."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.constants import ANALYSIS_INTERRUPTED
from app.models import Analysis, Base, DetectionRule
from app.services.rule_catalog import RULE_CATALOG
from app.utils.time import utcnow
from copy import deepcopy

from app.config import get_settings
from app.database import SessionLocal, get_engine


def seed_rules(db: Session) -> None:
    existing = set(db.scalars(select(DetectionRule.rule_key)).all())
    for definition in RULE_CATALOG:
        if definition["rule_key"] in existing:
            continue
        db.add(
            DetectionRule(
                rule_key=definition["rule_key"],
                name=definition["name"],
                description=definition["description"],
                enabled=definition["enabled"],
                severity=definition["severity"],
                parameters=deepcopy(definition["parameters"]),
                updated_at=utcnow(),
            )
        )
    db.commit()


def recover_interrupted_analyses(db: Session) -> None:
    rows = db.scalars(select(Analysis).where(Analysis.status.in_(("queued", "processing")))).all()
    if not rows:
        return
    now = utcnow()
    for row in rows:
        row.status = "failed"
        row.completed_at = now
        row.error_message = ANALYSIS_INTERRUPTED
    db.commit()


def prepare_database() -> None:
    settings = get_settings()
    settings.storage_path.mkdir(parents=True, exist_ok=True)
    (settings.storage_path / "captures").mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=get_engine())
    db = SessionLocal()
    try:
        seed_rules(db)
        recover_interrupted_analyses(db)
    finally:
        db.close()
