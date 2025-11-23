"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "NavajaCyber"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4

    # Security
    secret_key: str = "change-this-to-a-secure-random-string-min-32-chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    allowed_hosts: str = "localhost,127.0.0.1"

    # Rate Limiting
    rate_limit_default: int = 100
    rate_limit_analysis: int = 10
    rate_limit_scan: int = 5

    # Database
    database_url: str = "postgresql+asyncpg://navaja:navaja_secret@localhost:5432/navaja_cyber"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 300

    # MinIO
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket_evidence: str = "navaja-evidence"
    minio_bucket_reports: str = "navaja-reports"
    minio_secure: bool = False

    # Elasticsearch
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_index_logs: str = "navaja-logs"
    elasticsearch_index_findings: str = "navaja-findings"

    # Analysis
    analysis_timeout: int = 300
    bandit_confidence: str = "MEDIUM"
    max_repo_size_mb: int = 500

    # Forensic
    forensic_hash_algorithm: str = "sha256"
    evidence_retention_days: int = 90

    # CTF
    ctf_docker_network: str = "navaja-ctf-net"
    ctf_challenge_timeout: int = 3600
    ctf_flag_prefix: str = "NAVAJA{"
    ctf_flag_suffix: str = "}"

    # Alerts
    alert_webhook_url: str = ""
    alert_slack_webhook: str = ""

    # Simulation
    simulation_mode: bool = False


@lru_cache
def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()


settings = get_settings()
