"""
Database configuration using SQLAlchemy
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Create database engine
engine = create_engine(settings.DATABASE_URL, echo=settings.DEBUG)

# Create sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models
Base = declarative_base()

async def init_db():
    """Initialize database tables"""
    # Create required directories
    os.makedirs(settings.TEMP_DIR, exist_ok=True)
    os.makedirs(settings.SNAPSHOTS_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    
    # Create database tables
    Base.metadata.create_all(bind=engine)

def get_session():
    """Get database session"""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
