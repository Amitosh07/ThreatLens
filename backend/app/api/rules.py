"""View and update persisted detection rules."""

from copy import deepcopy

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import DetectionRule
from app.schemas import RuleOut, RuleUpdate
from app.serializers import rule_out
from app.services.rule_catalog import validate_parameters, validate_severity
from app.utils.time import utcnow

router = APIRouter()


@router.get("/rules", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db)) -> list[RuleOut]:
    rows = db.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()
    return [rule_out(row) for row in rows]


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: int, payload: RuleUpdate, db: Session = Depends(get_db)) -> RuleOut:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found.")
    if payload.enabled is None and payload.severity is None and payload.parameters is None:
        raise HTTPException(status_code=400, detail="No rule changes were provided.")
    try:
        if payload.severity is not None:
            rule.severity = validate_severity(payload.severity)
        if payload.enabled is not None:
            rule.enabled = payload.enabled
        if payload.parameters is not None:
            merged = deepcopy(rule.parameters or {})
            merged.update(payload.parameters)
            rule.parameters = validate_parameters(rule.rule_key, merged)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    rule.updated_at = utcnow()
    db.commit()
    db.refresh(rule)
    return rule_out(rule)
