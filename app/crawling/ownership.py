from __future__ import annotations

from dataclasses import dataclass


HIGH_OWNERSHIP_KEYS = {
    "account_id",
    "customer_id",
    "invoice_id",
    "order_id",
    "patient_id",
    "payment_id",
    "tenant_id",
    "user_id",
    "owner_id",
    "org_id",
    "workspace_id",
}
LOW_OWNERSHIP_HINTS = {"catalog", "static", "asset", "image", "css", "js", "public", "search"}
OWNERSHIP_PATH_HINTS = {"me", "profile", "account", "tenant", "billing", "invoice", "order", "admin"}


@dataclass(frozen=True)
class OwnershipSignal:
    score: float
    reasons: list[str]


class OwnershipInferenceEngine:
    def score(
        self,
        *,
        key: str | None,
        location: str,
        endpoint_path: str | None,
        identity_id: str | None,
        reference_type: str,
    ) -> OwnershipSignal:
        score = 0.1
        reasons: list[str] = []
        lowered_key = (key or "").lower()
        lowered_location = location.lower()
        lowered_path = (endpoint_path or "").lower()

        if identity_id:
            score += 0.2
            reasons.append("observed_in_authenticated_identity_context")
        if lowered_key in HIGH_OWNERSHIP_KEYS:
            score += 0.45
            reasons.append(f"high_confidence_ownership_key:{lowered_key}")
        if reference_type == "tenant":
            score += 0.35
            reasons.append("tenant_reference")
        if any(hint in lowered_path for hint in OWNERSHIP_PATH_HINTS):
            score += 0.2
            reasons.append("endpoint_path_contains_ownership_hint")
        if "response_body" in lowered_location and lowered_key in {"id", "uuid"}:
            score += 0.05
            reasons.append("response_identifier")
        if any(hint in lowered_path for hint in LOW_OWNERSHIP_HINTS):
            score -= 0.35
            reasons.append("public_or_static_resource_hint")

        return OwnershipSignal(score=max(0.0, min(score, 1.0)), reasons=reasons)
