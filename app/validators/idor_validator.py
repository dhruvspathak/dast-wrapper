from typing import Dict, Any, List
import re
from app.replay.replay_engine import ReplayEngine

class IDORValidator:
    def __init__(self, replay_engine: ReplayEngine):
        self.replay_engine = replay_engine

    async def validate_idor(self, request: Dict[str, Any], identifiers: List[str], auth_sessions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        # Extract identifiers from request
        extracted_ids = self._extract_identifiers(request, identifiers)

        if not extracted_ids:
            return {'vulnerable': False, 'reason': 'No identifiers found'}

        # Test across roles
        results = {}
        for role, session in auth_sessions.items():
            auth_headers = session.get('headers', {})
            # Swap identifiers and replay
            mutations = self._generate_mutations(extracted_ids)
            replay_results = await self.replay_engine.mutate_and_replay(request, mutations, auth_headers)
            results[role] = replay_results

        # Analyze results for privilege escalation
        analysis = self._analyze_privilege_escalation(results)

        return {
            'vulnerable': analysis['escalation_detected'],
            'confidence': analysis['confidence'],
            'evidence': analysis['evidence'],
            'recommendations': analysis['recommendations']
        }

    def _extract_identifiers(self, request: Dict[str, Any], identifier_names: List[str]) -> Dict[str, str]:
        ids = {}
        url = request.get('url', '')
        body = request.get('body', '')

        for name in identifier_names:
            # Search in URL
            match = re.search(rf'{name}=([^&]+)', url)
            if match:
                ids[name] = match.group(1)
                continue

            # Search in body
            match = re.search(rf'{name}["\']?\s*:\s*["\']?([^,"\'}}]+)', body)
            if match:
                ids[name] = match.group(1)

        return ids

    def _generate_mutations(self, ids: Dict[str, str]) -> List[Dict[str, Any]]:
        mutations = []
        for name, value in ids.items():
            # Generate mutations like swapping to different IDs
            # For demo, swap to '999' or something
            mutations.append({
                'param_swap': (name, value, '999')
            })
        return mutations

    def _analyze_privilege_escalation(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        # Compare responses across roles
        escalation_detected = False
        evidence = []
        confidence = 0.0

        # Simple logic: if lower role gets access that higher role should have exclusive
        # This is simplified; real logic would be more complex

        for role, replays in results.items():
            for replay in replays:
                if replay.get('status_code') == 200 and 'mutation' in replay:
                    # Check if unauthorized access
                    evidence.append(f"Role {role} accessed resource with mutation: {replay['mutation']}")
                    escalation_detected = True
                    confidence = 0.8

        return {
            'escalation_detected': escalation_detected,
            'confidence': confidence,
            'evidence': evidence,
            'recommendations': ['Implement proper authorization checks', 'Use ABAC/RBAC']
        }