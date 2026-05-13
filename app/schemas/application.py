from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class UserCredentials(BaseModel):
    username: str
    password: str

class ApplicationInfo(BaseModel):
    name: str
    base_url: str

class Authentication(BaseModel):
    type: str = Field(..., description="Authentication type: playwright_jwt, etc.")
    login_url: str
    users: Dict[str, UserCredentials]  # role -> credentials

class AuthorizationTest(BaseModel):
    identifiers: List[str] = Field(default_factory=list, description="List of identifiers like user_id, plan_id")
    workflows: List[str] = Field(default_factory=list, description="List of workflows to test")

class ApplicationConfig(BaseModel):
    application: ApplicationInfo
    authentication: Authentication
    roles: List[str] = Field(default_factory=list)
    authorization_tests: AuthorizationTest

class ApplicationCreate(BaseModel):
    name: str
    base_url: str
    config: ApplicationConfig

class ApplicationResponse(BaseModel):
    id: str
    name: str
    base_url: str
    config: Dict[str, Any]
    created_at: str
    updated_at: str