from app.core.config import settings
import os

def test_settings_defaults():
    assert settings.APP_NAME == "SecureScan Pro API"
    assert settings.VERIFY_SSL is True
    assert settings.DEBUG is False

def test_secret_key_generation():
    assert settings.SECRET_KEY is not None
    assert len(settings.SECRET_KEY) > 0
