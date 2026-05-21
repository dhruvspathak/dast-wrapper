from __future__ import annotations

import logging
import re
from urllib.parse import urlparse
import time

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

    def verify_authenticated_access(self, target_url: str, protected_paths: list[str] | None = None) -> bool:
        """Attempt to access a few protected paths through ZAP to ensure auth was applied."""
        if protected_paths is None:
            protected_paths = ["/api/me", "/dashboard", "/profile"]

        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in protected_paths:
            url = base + path
            try:
                # ask ZAP to open the URL through the proxy
                self.zap.core.urlopen(url)
                # allow ZAP to process the request
                time.sleep(1)
                # attempt to locate a message for this URL in ZAP's messages
                msgs = self.zap.core.messages()
                matched = [m for m in msgs if url in (m.get("requestHeader") or "")]
                if not matched:
                    logger.debug("ZAP did not record a message for %s", url)
                    return False
                # inspect response status line
                # the message structure varies; look for status in the responseHeader
                for m in matched:
                    resp = m.get("responseHeader") or ""
                    if " 200 " in resp or " 302 " in resp or " 301 " in resp:
                        # consider 200/30x as evidence ZAP could access the route
                        return True
            except Exception as exc:
                logger.debug("ZAP authenticated access check failed for %s: %s", url, exc)
                return False
        return False
