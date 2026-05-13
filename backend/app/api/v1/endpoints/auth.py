"""Authentication endpoints."""
from fastapi import APIRouter
router = APIRouter()

@router.post("/login", summary="Login and get JWT token")
async def login():
    return {"message": "Login endpoint — to be implemented"}

@router.post("/logout", summary="Logout")
async def logout():
    return {"message": "Logged out"}
