from openai import OpenAI
from typing import Dict, Any
from app.core.config import settings
from app.schemas.canonical import Finding, ValidationResult, ReplayResult

class AITriageEngine:
    def __init__(self):
        self.client = OpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url
        )

    async def triage_finding(
        self,
        finding: Dict[str, Any] | Finding,
        replay_evidence: list[Dict[str, Any] | ReplayResult] | None = None,
        validation_results: list[Dict[str, Any] | ValidationResult] | None = None,
    ) -> Dict[str, Any]:
        finding_payload = (
            finding.redacted() if isinstance(finding, Finding) else finding
        )
        replay_payload = [
            item.redacted() if hasattr(item, "redacted") else item
            for item in (replay_evidence or [])
        ]
        validation_payload = [
            item.redacted() if hasattr(item, "redacted") else item
            for item in (validation_results or [])
        ]
        prompt = f"""
You are assisting triage for a security validation platform.

Scanner findings are untrusted hypotheses. Do not classify a finding as confirmed
unless replay or authorization validation evidence supports exploitability.

Normalized finding:
{finding_payload}

Replay evidence:
{replay_payload}

Validation results:
{validation_payload}

Return concise JSON with:
classification: one of confirmed exploitable, likely exploitable, false positive, informational, needs manual review
root_cause
remediation
exploitability_reasoning
confidence: 0.0 to 1.0
"""

        if not settings.openai_api_key:
            return self._deterministic_fallback(finding_payload, validation_payload)

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )

        analysis = response.choices[0].message.content

        # Parse response (simplified)
        return {
            'classification': 'needs manual review',  # placeholder
            'root_cause': analysis,
            'remediation': 'Review validation evidence and fix the vulnerable server-side control.',
            'exploitability_reasoning': analysis,
            'confidence': 0.7
        }

    def _deterministic_fallback(self, finding: Dict[str, Any], validation_results: list[Dict[str, Any]]) -> Dict[str, Any]:
        confirmed = any(item.get("exploitable") and item.get("confidence", 0) >= 0.8 for item in validation_results)
        likely = any(item.get("exploitable") for item in validation_results)
        classification = "confirmed exploitable" if confirmed else "likely exploitable" if likely else "needs manual review"
        confidence = 0.85 if confirmed else 0.65 if likely else 0.35
        return {
            "classification": classification,
            "root_cause": "AI triage disabled; classification derived from deterministic validation evidence.",
            "remediation": "Validate server-side authorization, input handling, and response controls for this endpoint.",
            "exploitability_reasoning": "Scanner output was treated as a hypothesis and weighted only after replay/validation evidence.",
            "confidence": confidence,
        }
