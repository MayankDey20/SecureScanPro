import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_settings(monkeypatch):
    monkeypatch.setattr(settings, "VERIFY_SSL", False)
    return settings
