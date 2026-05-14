from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    app_name: str = Field(default="DAST Orchestration Platform")
    environment: str = Field(default="development")
    api_cors_origins: str = Field(default="")

    # Database
    database_url: str = Field(default="postgresql+asyncpg://dast_user:dast_password@localhost:5432/dast_wrapper")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Celery
    celery_broker_url: str = Field(default="redis://localhost:6379/0")
    celery_result_backend: str = Field(default="redis://localhost:6379/0")
    celery_scan_queue: str = Field(default="scan")
    celery_replay_queue: str = Field(default="replay")
    celery_validation_queue: str = Field(default="validation")
    celery_report_queue: str = Field(default="report")
    celery_worker_concurrency: int = Field(default=2)
    celery_task_time_limit_seconds: int = Field(default=3600)
    celery_task_soft_time_limit_seconds: int = Field(default=3300)
    max_active_scans: int = Field(default=3)

    # OpenAI
    openai_api_key: Optional[str] = None
    openai_base_url: Optional[str] = None

    # ZAP
    zap_api_url: str = Field(default="http://localhost:8080")
    zap_scan_timeout_seconds: int = Field(default=1800)
    zap_poll_interval_seconds: int = Field(default=5)
    zap_poll_max_errors: int = Field(default=12)

    # Replay validation
    replay_timeout_seconds: int = Field(default=30)
    replay_max_concurrency: int = Field(default=4)
    replay_allowed_hosts: str = Field(default="")
    replay_rate_limit_per_second: float = Field(default=2.0)

    # Security
    secret_key: str = Field(default="your-secret-key-here")
    default_workspace_id: str = Field(default="default")

    # Logging
    log_level: str = Field(default="INFO")

    @property
    def cors_origins(self) -> list[str]:
        if not self.api_cors_origins:
            return []
        return [origin.strip() for origin in self.api_cors_origins.split(",") if origin.strip()]

    @property
    def allowed_replay_hosts(self) -> set[str]:
        if not self.replay_allowed_hosts:
            return set()
        return {host.strip() for host in self.replay_allowed_hosts.split(",") if host.strip()}

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


settings = Settings()
