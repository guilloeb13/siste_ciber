"""Pytest configuration and fixtures."""

import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from backend.app.main import app
from backend.app.services.database import Base, get_db
from backend.app.config import settings


# Use SQLite for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Create test HTTP client."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    # Disable rate limiting by default so cumulative request counts across the
    # suite don't cause flaky 429s. The dedicated rate-limit test re-enables it.
    from backend.app.ratelimit import limiter
    limiter.enabled = False

    # base_url host must be present in settings.allowed_hosts so the
    # TrustedHostMiddleware accepts the request (localhost is allowed by default).
    async with AsyncClient(app=app, base_url="http://localhost") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def sample_metric_data():
    """Sample metric data for testing."""
    return {
        "metric_type": "cpu",
        "name": "cpu_usage_percent",
        "value": 75.5,
        "unit": "percent",
        "labels": {"core": "all"},
    }


@pytest.fixture
def sample_finding_data():
    """Sample finding data for testing."""
    return {
        "source": "bandit",
        "rule_id": "B101",
        "title": "Test finding",
        "description": "A test finding for unit tests",
        "severity": "medium",
        "file_path": "/app/test.py",
        "line_number": 42,
        "recommendation": "Fix the issue",
    }


@pytest.fixture
def sample_agent_data():
    """Sample agent registration data."""
    return {
        "name": "test-agent",
        "hostname": "test-host",
        "ip_address": "192.168.1.100",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04",
        "agent_version": "0.1.0",
        "tags": ["test", "development"],
    }
