"""
Argus ASM — settings
All configuration is loaded from environment variables or a .env file.
Never hardcode secrets in source code.

Usage:
    from config.settings import settings
    print(settings.DATABASE_URL)
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    Application-wide settings.
    Values are read from environment variables first,
    then from a .env file in the project root.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",         # silently ignore unknown env vars
    )

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    DATABASE_URL: str = Field(
        default="postgresql://postgres:password@localhost:5432/argus",
        description="Full SQLAlchemy connection string for PostgreSQL.",
    )
    DB_ECHO: bool = Field(
        default=False,
        description="Set True to log every SQL statement (noisy, dev only).",
    )

    # ------------------------------------------------------------------ #
    # Scan settings
    # ------------------------------------------------------------------ #
    PORT_SCAN_TIMEOUT: float = Field(
        default=1.0,
        description="Seconds to wait per TCP connect attempt.",
    )
    PORT_SCAN_WORKERS: int = Field(
        default=150,
        description="Max concurrent threads for port scanning.",
    )
    SUBDOMAIN_WORKERS: int = Field(
        default=20,
        description="Max concurrent threads for subdomain brute-force.",
    )
    BANNER_TIMEOUT: float = Field(
        default=3.0,
        description="Seconds to wait for banner/HTTP response.",
    )

    # ------------------------------------------------------------------ #
    # Optional API keys (leave blank to skip those modules)
    # ------------------------------------------------------------------ #
    SHODAN_API_KEY: str = Field(
        default="",
        description="Shodan API key. Leave empty to skip Shodan lookups.",
    )
    NVD_API_KEY: str = Field(
        default="",
        description="NVD API key for higher rate limits. Optional.",
    )

    # ------------------------------------------------------------------ #
    # Scheduler (Week 2)
    # ------------------------------------------------------------------ #
    SCAN_INTERVAL_HOURS: int = Field(
        default=24,
        description="How often to re-scan each target (hours).",
    )


# Single shared instance — import this everywhere
settings = Settings()
