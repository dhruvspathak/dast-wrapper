import httpx
from typing import Dict, Any, List, Optional
import asyncio
import time
import difflib

class ReplayEngine:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def replay_request(self, request_data: Dict[str, Any], auth_headers: Dict[str, str] = None) -> Dict[str, Any]:
        method = request_data.get('method', 'GET')
        url = request_data.get('url')
        headers = request_data.get('headers', {})
        body = request_data.get('body')

        if auth_headers:
            headers.update(auth_headers)

        start_time = time.time()
        try:
            response = await self.client.request(method, url, headers=headers, content=body)
            response_time = time.time() - start_time

            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'response_time': response_time,
                'success': True
            }
        except Exception as e:
            response_time = time.time() - start_time
            return {
                'error': str(e),
                'response_time': response_time,
                'success': False
            }

    async def mutate_and_replay(self, original_request: Dict[str, Any], mutations: List[Dict[str, Any]], auth_headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
        results = []
        for mutation in mutations:
            mutated_request = self._apply_mutation(original_request, mutation)
            result = await self.replay_request(mutated_request, auth_headers)
            result['mutation'] = mutation
            results.append(result)
        return results

    def _apply_mutation(self, request: Dict[str, Any], mutation: Dict[str, Any]) -> Dict[str, Any]:
        mutated = request.copy()
        # Apply mutation logic, e.g., change parameters, headers, etc.
        if 'param_swap' in mutation:
            # Swap parameter values
            param, old_val, new_val = mutation['param_swap']
            if 'body' in mutated and isinstance(mutated['body'], str):
                mutated['body'] = mutated['body'].replace(old_val, new_val)
            elif 'params' in mutated:
                if param in mutated['params']:
                    mutated['params'][param] = new_val

        return mutated

    def compare_responses(self, response1: Dict[str, Any], response2: Dict[str, Any]) -> Dict[str, Any]:
        if not response1.get('success') or not response2.get('success'):
            return {'comparable': False, 'difference': 'One or both responses failed'}

        content1 = response1.get('content', '')
        content2 = response2.get('content', '')

        diff = list(difflib.unified_diff(content1.splitlines(), content2.splitlines(), lineterm=''))

        return {
            'comparable': True,
            'status_diff': response1['status_code'] != response2['status_code'],
            'content_diff': len(diff) > 0,
            'time_diff': abs(response1.get('response_time', 0) - response2.get('response_time', 0)),
            'diff_details': diff
        }