from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from playwright.async_api import Page

from app.auth.browser_session import browser_context
from app.schemas.canonical import AuthContext

logger = logging.getLogger(__name__)

AUTHENTICATED_UI_SELECTORS = [
    "button:has-text('Logout')",
    "a:has-text('Logout')",
    "button:has-text('Sign out')",
    "a:has-text('Sign out')",
    "[aria-label*='logout']",
    "[aria-label*='profile']",
    "[data-testid*='profile']",
    "[class*='avatar']",
    "[class*='profile']",
    "[href*='dashboard']",
]

COMMON_AUTH_ROUTES = [
    "/api/me",
    "/api/user",
    "/dashboard",
    "/profile",
    "/admin",
    "/graphql",
    "/user",
    "/settings",
]

LOGIN_ROUTE_INDICATORS = [
    "/signin",
    "/sign-in",
    "/login",
    "/auth",
    "/account/login",
    "/oauth",
]

ROLE_SPECIFIC_PATTERNS = [
    "/admin",
    "/dashboard",
    "/settings",
    "/user",
    "/profile",
]


@dataclass(slots=True)
class AuthAssertionReport:
    browser: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    behavioral: dict[str, Any] = field(default_factory=dict)
    discovered_routes: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    confidence_level: str = "low"
    auth_validated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "browser": self.browser,
            "network": self.network,
            "behavioral": self.behavioral,
            "discovered_routes": self.discovered_routes,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level,
            "auth_validated": self.auth_validated,
        }


class AuthConfidenceScore:
    LEVELS = ["low", "medium", "high", "critical"]

    @staticmethod
    def compute(report: AuthAssertionReport) -> tuple[float, str]:
        score = 0.0

        if not report.browser.get("login_page_detected", False):
            score += 0.2
        if report.browser.get("authenticated_dom_markers"):
            if any(report.browser["authenticated_dom_markers"].values()):
                score += 0.2

        if report.network.get("has_cookies"):
            score += 0.15
        if report.network.get("has_auth_header"):
            score += 0.15
        if report.network.get("has_jwt"):
            score += 0.1

        if report.behavioral.get("api_me_success"):
            score += 0.2
        if report.behavioral.get("protected_routes_accessible"):
            score += 0.1
        if report.behavioral.get("role_specific_routes_accessible"):
            score += 0.1

        score = min(1.0, score)
        if score >= 0.85:
            level = "critical"
        elif score >= 0.65:
            level = "high"
        elif score >= 0.35:
            level = "medium"
        else:
            level = "low"

        return score, level


class AuthAssertionEngine:
    def __init__(self):
        self.browser_markers = AUTHENTICATED_UI_SELECTORS
        self.protected_routes = COMMON_AUTH_ROUTES

    async def validate(
        self,
        page: Page,
        auth_context: AuthContext,
        application_base_url: str,
        login_url: str | None = None,
    ) -> AuthAssertionReport:
        report = AuthAssertionReport()
        application_base_url = application_base_url.rstrip("/")
        login_url = (login_url or application_base_url).rstrip("/")

        report.browser = await self._evaluate_browser_state(page, login_url)
        report.network = self._evaluate_network_state(auth_context)
        report.behavioral, report.discovered_routes = await self._evaluate_behavioral_state(
            page, application_base_url, login_url
        )

        report.confidence_score, report.confidence_level = AuthConfidenceScore.compute(report)
        report.auth_validated = report.confidence_level in {"high", "critical"}

        logger.info(
            "Auth assertion result: score=%s level=%s login_detected=%s cookies=%s headers=%s",
            report.confidence_score,
            report.confidence_level,
            report.browser.get("login_page_detected"),
            report.network.get("has_cookies"),
            report.network.get("has_auth_header"),
        )

        return report

    async def _evaluate_browser_state(self, page: Page, login_url: str) -> dict[str, Any]:
        current_url = page.url
        browser_state = {
            "current_url": current_url,
            "login_page_detected": self._is_login_url(current_url),
            "authenticated_dom_markers": {},
            "page_title": (await page.title()) if page else None,
        }

        for selector in self.browser_markers:
            browser_state["authenticated_dom_markers"][selector] = await self._element_exists(page, selector)

        return browser_state

    def _is_login_url(self, url: str) -> bool:
        normalized = url.lower()
        if any(token in normalized for token in LOGIN_ROUTE_INDICATORS):
            return True
        return False

    async def _element_exists(self, page: Page, selector: str) -> bool:
        try:
            count = await page.locator(selector).count()
            return count > 0
        except Exception:
            return False

    def _evaluate_network_state(self, auth_context: AuthContext) -> dict[str, Any]:
        headers = auth_context.headers or {}
        cookies = auth_context.cookies or {}
        jwt_found = self._extract_jwt(auth_context)
        return {
            "has_cookies": bool(cookies),
            "cookie_names": list(cookies.keys()),
            "has_auth_header": bool(headers.get("Authorization") or headers.get("authorization")),
            "auth_headers": headers,
            "has_jwt": bool(jwt_found),
            "jwt": jwt_found,
            "refresh_token": bool(auth_context.refresh_token),
        }

    def _extract_jwt(self, auth_context: AuthContext) -> str | None:
        jwt_pattern = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
        candidates = []
        for source in [auth_context.headers, auth_context.cookies, auth_context.local_storage, auth_context.session_storage]:
            for value in source.values():
                if isinstance(value, str) and jwt_pattern.match(value):
                    return value
        return None

    async def _evaluate_behavioral_state(
        self,
        page: Page,
        application_base_url: str,
        login_url: str,
    ) -> tuple[dict[str, Any], list[str]]:
        behavioral: dict[str, Any] = {
            "checked_routes": {},
            "protected_routes_accessible": False,
            "api_me_success": False,
            "role_specific_routes_accessible": False,
        }
        discovered_routes: list[str] = []

        current_url = page.url
        if current_url and not self._is_login_url(current_url):
            discovered_routes.append(current_url)
            behavioral["protected_routes_accessible"] = True
            if any(pat in current_url for pat in ROLE_SPECIFIC_PATTERNS):
                behavioral["role_specific_routes_accessible"] = True

        for route in self.protected_routes:
            url = urljoin(application_base_url + "/", route.lstrip("/"))
            status = None
            destination = None
            accessible = False
            route_name = route

            if route.startswith("/api") or route.startswith("/graphql"):
                # Prefer client-side fetch for API endpoints to preserve SPA auth context.
                try:
                    result = await page.evaluate(
                        '''async (url) => {
                            try {
                                const res = await fetch(url, { credentials: 'include' });
                                return { status: res.status, redirected: res.redirected, url: res.url };
                            } catch (err) {
                                return { error: err.toString() };
                            }
                        }''',
                        url,
                    )
                    status = result.get("status") if isinstance(result, dict) else None
                    destination = result.get("url") if isinstance(result, dict) else url
                    accessible = bool(status and status < 400)
                except Exception as exc:
                    behavioral["checked_routes"][url] = {"status": "error", "error": str(exc)}
                    continue
            else:
                try:
                    response = await page.goto(url, wait_until="networkidle", timeout=20000)
                    status = response.status if response else None
                    destination = page.url
                    if destination and destination.rstrip("/") == url.rstrip("/") and not self._is_login_url(destination):
                        accessible = True
                    elif status and status < 400 and not self._is_login_url(destination):
                        accessible = True
                except Exception as exc:
                    behavioral["checked_routes"][url] = {"status": "error", "error": str(exc)}
                    continue

            behavioral["checked_routes"][url] = {
                "status": status,
                "destination": destination,
                "accessible": accessible,
            }

            if accessible:
                discovered_routes.append(url)
                behavioral["protected_routes_accessible"] = True
                if any(pat in route for pat in ROLE_SPECIFIC_PATTERNS):
                    behavioral["role_specific_routes_accessible"] = True
                if route in {"/api/me", "/api/user"}:
                    behavioral["api_me_success"] = True

        return behavioral, discovered_routes


class AuthenticatedSessionValidator:
    def __init__(self, application_base_url: str):
        self.application_base_url = application_base_url.rstrip("/")
        self.assertion_engine = AuthAssertionEngine()

    async def validate(self, auth_context: AuthContext, login_url: str | None = None) -> AuthAssertionReport:
        if not auth_context.browser_storage_state_path:
            report = AuthAssertionReport()
            report.browser = {"error": "missing_browser_storage_state_path"}
            report.confidence_level = "low"
            return report

        async with browser_context(auth_context.browser_storage_state_path) as context:
            page = await context.new_page()
            try:
                await page.goto(login_url or self.application_base_url, wait_until="networkidle", timeout=20000)
            except Exception as exc:
                report = AuthAssertionReport()
                report.browser = {"error": str(exc)}
                report.confidence_level = "low"
                return report

            report = await self.assertion_engine.validate(page, auth_context, self.application_base_url, login_url=login_url)
            return report
