from openai import OpenAI
from typing import Dict, Any
from app.core.config import settings

class AITriageEngine:
    def __init__(self):
        self.client = OpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url
        )

    async def triage_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        prompt = f"""
Analyze this security finding and provide triage information:

Title: {finding.get('title')}
Description: {finding.get('description')}
Severity: {finding.get('severity')}
URL: {finding.get('url')}

Classify as: confirmed, likely exploitable, false positive, informational, needs manual review
Provide root cause analysis, remediation guidance, exploitability reasoning, and confidence score (0-1).
"""

        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )

        analysis = response.choices[0].message.content

        # Parse response (simplified)
        return {
            'classification': 'needs manual review',  # placeholder
            'root_cause': analysis,
            'remediation': 'Fix the issue',
            'confidence': 0.7
        }