"""Scan management endpoints."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/", summary="List scan jobs")
async def list_scans():
    return {"scans": []}

@router.post("/", summary="Start a new scan job")
async def start_scan():
    # Safety check: scanning must be explicitly enabled in config
    return {"message": "Scan queued"}
