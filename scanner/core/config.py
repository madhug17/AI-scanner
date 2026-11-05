import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI App Security & Quality Scanner"
    app_env: str = "development"
    app_debug: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    scan_version: str = "1.0.0"

    # Database
    database_url: str = os.getenv(
        "DATABASE_URL", "sqlite:///./scanner.db"
    )

    # Redis
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_rate_limit_per_minute: int = 60
    redis_scan_cache_ttl: int = 3600

    # Kafka
    kafka_bootstrap_servers: str = os.getenv(
        "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
    )
    kafka_scan_requests_topic: str = "scan.requested"
    kafka_scan_deadletter_topic: str = "scan.deadletter"
    kafka_consumer_group: str = "scanner-workers"

    # Repository Safety & Limits
    max_repo_clone_timeout_sec: int = 120
    max_repo_size_mb: int = 100
    max_file_size_bytes: int = 1_000_000  # 1 MB

    # External Analyzers
    semgrep_binary: str = "semgrep"
    gitleaks_binary: str = "gitleaks"
    pip_audit_binary: str = "pip-audit"
    osv_api_url: str = "https://api.osv.dev/v1/query"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

