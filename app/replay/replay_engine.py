import httpx
from typing import Dict, Any, List
import asyncio
import time
from urllib.parse import urlparse

from app.core.config import settings
from app.replay.diff_engine import ReplayDiffEngine
from app.schemas.canonical import AuthContext, RequestData, ResponseData, ReplayResult

class ReplayEngine:
    _semaphore = asyncio.Semaphore(settings.replay_max_concurrency)

    def __init__(self, timeout: int = settings.replay_timeout_seconds, allowed_hosts: set[str] | None = None):
        self.timeout = timeout
        self.allowed_hosts = allowed_hosts or set()
        self.diff_engine = ReplayDiffEngine()
        self.client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def replay_request(
        self,
        request_data: Dict[str, Any] | RequestData,
        auth_headers: Dict[str, str] | None = None,
        auth_context: AuthContext | None = None,
    ) -> Dict[str, Any]:
        replay = await self.replay_canonical(request_data, auth_headers, auth_context)
        return {
            **replay.replay_response.model_dump(mode="json"),
            "success": replay.success,
            "diff": replay.diff,
        }

    async def replay_canonical(
        self,
        request_data: Dict[str, Any] | RequestData,
        auth_headers: Dict[str, str] | None = None,
        auth_context: AuthContext | None = None,
        baseline_response: ResponseData | dict[str, Any] | None = None,
    ) -> ReplayResult:
        request = request_data if isinstance(request_data, RequestData) else RequestData(**request_data)
        self._enforce_scope(request.url)

        headers = dict(request.headers)
        cookies = dict(request.cookies)
        if auth_context:
            headers.update(auth_context.headers)
            cookies.update(auth_context.cookies)
        if auth_headers:
            headers.update(auth_headers)

        started = time.perf_counter()
        try:
            async with self._semaphore:
                response = await self.client.request(
                    request.method,
                    request.url,
                    headers=headers,
                    cookies=cookies,
                    params=request.query_params,
                    content=request.body if not isinstance(request.body, (dict, list)) else None,
                    json=request.body if isinstance(request.body, (dict, list)) else None,
                )
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            replay_response = ResponseData(
                status_code=response.status_code,
                headers=dict(response.headers),
                cookies=dict(response.cookies),
                body=response.text,
                elapsed_ms=elapsed_ms,
                content_length=len(response.content),
            )
            replay_response.fingerprint = self.diff_engine.fingerprint(replay_response)
            success = True
        except Exception as e:
            replay_response = ResponseData(
                error=str(e),
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            success = False

        baseline = None
        if isinstance(baseline_response, ResponseData):
            baseline = baseline_response
        elif baseline_response:
            baseline = ResponseData(**baseline_response)

        return ReplayResult(
            request=request,
            baseline_response=baseline,
            replay_response=replay_response,
            auth_context_id=auth_context.id if auth_context else None,
            role=auth_context.role if auth_context else None,
            success=success,
            diff=self.diff_engine.compare(baseline, replay_response),
        )

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
        left = ResponseData(
            status_code=response1.get("status_code"),
            headers=response1.get("headers", {}),
            body=response1.get("body") or response1.get("content", ""),
            elapsed_ms=response1.get("elapsed_ms") or response1.get("response_time"),
        )
        right = ResponseData(
            status_code=response2.get("status_code"),
            headers=response2.get("headers", {}),
            body=response2.get("body") or response2.get("content", ""),
            elapsed_ms=response2.get("elapsed_ms") or response2.get("response_time"),
        )
        return self.diff_engine.compare(left, right)

    def _enforce_scope(self, url: str) -> None:
        if not self.allowed_hosts:
            return
        host = urlparse(url).hostname
        if host not in self.allowed_hosts:
            raise ValueError(f"Replay target host {host!r} is outside configured scope")
