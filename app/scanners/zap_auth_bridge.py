from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from zapv2 import ZAPv2

logger = logging.getLogger(__name__)


class ZAPAuthContextBridge:
    def __init__(self, zap: ZAPv2):
        self.zap = zap

    def apply(self, target_url: str, auth_headers: dict[str, str] | None, cookies: dict[str, str] | None) -> None:
        self._clear_replacer_rules()
        self._register_context(target_url)

        if auth_headers:
            self._inject_headers(auth_headers)

        if cookies:
            self._inject_cookies(cookies)

    def _register_context(self, target_url: str) -> None:
        parsed = urlparse(target_url)
        domain = parsed.netloc
        if not domain:
            return

        context_name = f"auth_context_{domain}"
        try:
            self.zap.context.new_context(context_name)
        except Exception:
            pass

        try:
            self.zap.context.include_in_context(context_name, rf".*{re.escape(domain)}.*")
        except Exception:
            pass

    def _inject_headers(self, auth_headers: dict[str, str]) -> None:
        for header, value in auth_headers.items():
            logger.info("ZAP auth bridge injecting header %s", header)
            try:
                self.zap.replacer.add_rule(
                    description=f"Auth header {header}",
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    replacement=value,
                    matchstring=header,
                )
            except Exception as exc:
                logger.warning("Failed to inject auth header %s into ZAP: %s", header, exc)

    def _inject_cookies(self, cookies: dict[str, str]) -> None:
        cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
        logger.info("ZAP auth bridge injecting cookies: %s", list(cookies.keys()))
        try:
            self.zap.replacer.add_rule(
                description="Auth cookies",
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                replacement=cookie_header,
                matchstring="Cookie",
            )
        except Exception as exc:
            logger.warning("Failed to inject auth cookies into ZAP: %s", exc)

    def _clear_replacer_rules(self) -> None:
        if hasattr(self.zap.replacer, "remove_all_rules"):
            try:
                self.zap.replacer.remove_all_rules()
            except Exception:
                pass
