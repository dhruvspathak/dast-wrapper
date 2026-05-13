#!/usr/bin/env python3
from sqlalchemy import create_engine
from app.db.base import Base
from app.core.config import settings
# Import all models to register them with Base
from app.models import Application, Scan, Finding, AuthSession, Report

def create_tables():
    engine = create_engine(settings.database_url.replace('+asyncpg', ''))
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully")

if __name__ == "__main__":
    create_tables()