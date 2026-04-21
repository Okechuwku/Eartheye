import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker

# Update with your actual PostgreSQL credentials
SQLALCHEMY_DATABASE_URL = "postgresql+asyncpg://postgres:Scientist44%40.@localhost/eartheye"

DEFAULT_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost/eartheye"
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "false").strip().lower() == "true"

engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=SQLALCHEMY_ECHO)
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
