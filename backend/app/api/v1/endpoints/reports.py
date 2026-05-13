"""Report generation endpoints."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/", summary="List available reports")
async def list_reports():
    return {"reports": []}

@router.post("/generate", summary="Generate a report")
async def generate_report():
    return {"message": "Report generation queued"}
