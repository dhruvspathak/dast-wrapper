import logging
import re
import sys
from typing import Any

import structlog

TOKEN_KEYS = re.compile(
    r"(authorization|cookie|set-cookie|token|secret|password|api[_-]?key)",
    re.IGNORECASE,
)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***REDACTED***" if TOKEN_KEYS.search(str(key)) else _redact_value(val)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def redact_secrets(_, __, event_dict):
    return _redact_value(event_dict)


def configure_logging(log_level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            redact_secrets,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
