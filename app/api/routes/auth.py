from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.auth.playwright_auth import PlaywrightAuthEngine
from app.db.base import get_db
from app.models.auth_session import AuthSession
from app.models.application import Application
from sqlalchemy import select
import asyncio

router = APIRouter()

class AuthenticateRequest(BaseModel):
    config_id: str
    role: str

@router.post("/authenticate")
async def authenticate(request: AuthenticateRequest):
    # Get app config
    async with get_db() as session:
        result = await session.execute(
            select(Application).where(Application.id == request.config_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
    
    config = app.config
    auth_config = config.get('authentication', {})
    users = auth_config.get('users', {})
    
    if request.role not in users:
        raise HTTPException(status_code=400, detail=f"Role {request.role} not found in config")
    
    user = users[request.role]
    login_url = auth_config.get('login_url')
    
    # Authenticate using Playwright
    async with PlaywrightAuthEngine() as auth_engine:
        auth_data = await auth_engine.authenticate(login_url, user['username'], user['password'])
    
    # Save session
    async with get_db() as session:
        session_obj = AuthSession(
            application_id=request.config_id,
            role=request.role,
            tokens=auth_data
        )
        session.add(session_obj)
        await session.commit()
        await session.refresh(session_obj)
    
    return {"message": "Authentication successful", "session_id": session_obj.id}