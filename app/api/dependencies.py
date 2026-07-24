from fastapi import Request

from app.storage import ThreatRepository


def get_repository(request: Request) -> ThreatRepository:
    return request.app.state.repository

