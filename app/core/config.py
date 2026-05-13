from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = Field(default="postgresql+asyncpg://dast_user:dast_password@localhost:5432/dast_wrapper")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Celery
    celery_broker_url: str = Field(default="redis://localhost:6379/0")
    celery_result_backend: str = Field(default="redis://localhost:6379/0")

    # OpenAI
    openai_api_key: Optional[str] = None
    openai_base_url: Optional[str] = None

    # ZAP
    zap_api_url: str = Field(default="http://localhost:8080")
    zap_scan_timeout_seconds: int = Field(default=1800)
    zap_poll_interval_seconds: int = Field(default=5)
    zap_poll_max_errors: int = Field(default=12)

    # Security
    secret_key: str = Field(default="your-secret-key-here")

    # Logging
    log_level: str = Field(default="INFO")

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
