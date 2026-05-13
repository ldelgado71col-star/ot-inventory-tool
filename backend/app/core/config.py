"""
Application configuration — loaded from environment variables.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_DEBUG: bool = False
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    # Database
    DATABASE_URL: str = "postgresql://otuser:changeme@localhost:5432/ot_inventory"

    # Security
    SECRET_KEY: str = "change-this-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Scanning — disabled by default for OT safety
    SCAN_ENABLED: bool = False
    PASSIVE_ENABLED: bool = False
    PASSIVE_INTERFACE: str = "eth0"
    SCAN_RATE_LIMIT_PPS: int = 10
    SCAN_TIMEOUT_SECONDS: int = 2
    SCAN_MAX_RETRIES: int = 1

    # Logging
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = "../../config/.env"
        case_sensitive = True


settings = Settings()
