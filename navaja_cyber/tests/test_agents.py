"""Test agent registration and management."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_agent(client: AsyncClient, sample_agent_data):
    """Test agent registration."""
    response = await client.post("/api/agents/register", json=sample_agent_data)
    assert response.status_code == 200

    data = response.json()
    assert "id" in data
    assert "token" in data
    assert data["message"] == "Agent registered successfully. Store this token securely - it cannot be retrieved again."


@pytest.mark.asyncio
async def test_register_agent_missing_fields(client: AsyncClient):
    """Test agent registration with missing required fields."""
    response = await client.post("/api/agents/register", json={
        "name": "incomplete-agent"
    })
    assert response.status_code == 422  # Validation error
