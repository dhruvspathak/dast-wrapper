from typing import Dict, Any, List
from app.replay.replay_engine import ReplayEngine
from app.schemas.canonical import AuthContext, RequestData
from app.validators.authorization_engine import AuthorizationValidationEngine

class IDORValidator:
    def __init__(self, replay_engine: ReplayEngine):
        self.replay_engine = replay_engine

    async def validate_idor(self, request: Dict[str, Any], identifiers: List[str], auth_sessions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        contexts = [
            AuthContext(
                application_id=session.get("application_id", "unknown"),
                role=role,
                headers=session.get("headers", {}),
                cookies=session.get("cookies", {}),
                local_storage=session.get("local_storage", session.get("localStorage", {})),
            )
            for role, session in auth_sessions.items()
        ]
        engine = AuthorizationValidationEngine(self.replay_engine)
        result = await engine.validate(RequestData(**request), contexts)
        return {
            "vulnerable": result.exploitable,
            "confidence": result.confidence,
            "status": result.status,
            "evidence": result.evidence,
            "recommendations": result.remediation,
        }
