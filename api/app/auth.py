"""
Authentication module — users, password hashing, JWT tokens.
"""

import bcrypt
from datetime import datetime, timedelta
from jose import jwt

SECRET_KEY = "Potenza-OT-Inventory-2026-SecureKey"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

# ── Users database ────────────────────────────────────────────
# Passwords stored as bcrypt hashes — never plaintext
USERS = {
    "Engineer": {
        "username": "Engineer",
        "password_hash": bcrypt.hashpw(b"Luis2005+-*", bcrypt.gensalt()).decode(),
        "role": "admin",
        "full_name": "Luis Engineer"
    },
    "FieldSupport": {
        "username": "FieldSupport",
        "password_hash": bcrypt.hashpw(b"Support01", bcrypt.gensalt()).decode(),
        "role": "analyst",
        "full_name": "Field Support"
    },
    "View": {
        "username": "View",
        "password_hash": bcrypt.hashpw(b"View01", bcrypt.gensalt()).decode(),
        "role": "viewer",
        "full_name": "Viewer"
    },
}


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def authenticate_user(username: str, password: str):
    user = USERS.get(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None
