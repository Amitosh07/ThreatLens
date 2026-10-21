"""API routers."""

from fastapi import APIRouter

from app.api import alerts, analyses, health, reports, rules, uploads

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(uploads.router, tags=["Uploads"])
api_router.include_router(analyses.router, tags=["Analyses"])
api_router.include_router(alerts.router, tags=["Alerts"])
api_router.include_router(rules.router, tags=["Rules"])
api_router.include_router(reports.router, tags=["Reports"])
