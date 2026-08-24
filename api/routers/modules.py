"""/api/modules — advertise the scanner's capabilities (all discoverable
scan modules), so the UI can list and let users toggle individual modules."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from vantis.core.engine import discover_all_modules

router = APIRouter(prefix="/api", tags=["meta"])

_ORDER = {"recon": 0, "web": 1, "cve": 2}


class ModuleInfo(BaseModel):
    name: str
    category: str
    description: str


@router.get("/modules", response_model=list[ModuleInfo])
def list_modules() -> list[ModuleInfo]:
    mods = [
        ModuleInfo(name=m.name, category=m.category, description=m.description or "")
        for m in discover_all_modules()
    ]
    mods.sort(key=lambda m: (_ORDER.get(m.category, 99), m.name))
    return mods
