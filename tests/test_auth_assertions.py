import pytest

from app.auth.assertions import AuthAssertionReport, AuthAssertionEngine, AuthConfidenceScore
from app.schemas.canonical import AuthContext


def test_auth_confidence_low_when_only_login_detected():
    report = AuthAssertionReport(
        browser={"login_page_detected": True, "authenticated_dom_markers": {}},
        network={"has_cookies": False, "has_auth_header": False, "has_jwt": False},
        behavioral={"api_me_success": False, "protected_routes_accessible": False, "role_specific_routes_accessible": False},
    )
    score, level = AuthConfidenceScore.compute(report)
    assert level == "low"
    assert score < 0.35


def test_auth_confidence_medium_when_tokens_present():
    report = AuthAssertionReport(
        browser={"login_page_detected": True, "authenticated_dom_markers": {}},
        network={"has_cookies": True, "has_auth_header": True, "has_jwt": True},
        behavioral={"api_me_success": False, "protected_routes_accessible": False, "role_specific_routes_accessible": False},
    )
    score, level = AuthConfidenceScore.compute(report)
    assert level == "medium"
    assert score >= 0.35


def test_auth_confidence_high_when_protected_routes_are_accessible():
    report = AuthAssertionReport(
        browser={"login_page_detected": False, "authenticated_dom_markers": {"button:has-text('Logout')": True}},
        network={"has_cookies": True, "has_auth_header": True, "has_jwt": True},
        behavioral={"api_me_success": True, "protected_routes_accessible": True, "role_specific_routes_accessible": False},
    )
    score, level = AuthConfidenceScore.compute(report)
    assert level == "critical"
    assert score >= 0.85


def test_auth_assertion_engine_identifies_login_routes():
    engine = AuthAssertionEngine()
    assert engine._is_login_url("https://example.com/login")
    assert engine._is_login_url("https://example.com/signin")
    assert engine._is_login_url("https://example.com/auth/callback")
    assert not engine._is_login_url("https://example.com/dashboard")
