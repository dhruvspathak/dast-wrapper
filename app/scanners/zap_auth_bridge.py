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
        except Exception as exc:
            logger.debug("Failed to create ZAP context %s: %s", context_name, exc)

        try:
            self.zap.context.include_in_context(context_name, rf".*{re.escape(domain)}.*")
        except Exception as exc:
            logger.debug("Failed to include domain %s in ZAP context: %s", domain, exc)

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
        """Inject cookies using ZAP's native cookie storage instead of replacer rules."""
        logger.info("ZAP auth bridge injecting cookies: %s", list(cookies.keys()))
        try:
            # Use replacer to inject each cookie as a full Cookie header line
            # This is more reliable than trying to replace an existing header
            cookie_parts = [f"{name}={value}" for name, value in cookies.items()]
            for cookie_part in cookie_parts:
                try:
                    self.zap.replacer.add_rule(
                        description=f"Auth cookie {cookie_part.split('=')[0]}",
                        enabled="true",
                        matchtype="REQ_HEADER",
                        matchregex="false",
                        replacement=f"{'; '.join([cookie_part] + [c for c in cookie_parts if c != cookie_part])}",
                        matchstring="Cookie",
                    )
                except Exception as exc:
                    logger.debug("Failed to inject cookie %s: %s", cookie_part, exc)
        except Exception as exc:
            logger.warning("Failed to inject auth cookies into ZAP: %s", exc)

    def _clear_replacer_rules(self) -> None:
        if hasattr(self.zap.replacer, "remove_all_rules"):
            try:
                self.zap.replacer.remove_all_rules()
            except Exception as exc:
                logger.debug("Failed to clear ZAP replacer rules: %s", exc)

    def verify_authenticated_access(self, target_url: str, protected_paths: list[str] | None = None) -> bool:
        """Attempt to access a few protected paths through ZAP to ensure auth was applied.
        Only 200 status is considered authenticated; redirects indicate auth failure.
        """
        if protected_paths is None:
            protected_paths = ["/api/me", "/dashboard", "/settings"]

        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        authenticated_count = 0

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
                    continue
                # inspect response status line
                # the message structure varies; look for status in the responseHeader
                for m in matched:
                    resp = m.get("responseHeader") or ""
                    # Only 200 status indicates authenticated access.
                    # Redirects (301/302) suggest auth failed and we were sent to login page.
                    if " 200 " in resp:
                        logger.debug("ZAP verified authenticated access to %s with 200 OK", url)
                        authenticated_count += 1
                        break
                    elif " 301 " in resp or " 302 " in resp:
                        logger.debug("ZAP got redirect to %s; auth likely failed", url)
                        continue
            except Exception as exc:
                logger.debug("ZAP authenticated access check failed for %s: %s", url, exc)
                continue
        
        # Require at least 1 successful 200 response from protected paths
        return authenticated_count > 0
