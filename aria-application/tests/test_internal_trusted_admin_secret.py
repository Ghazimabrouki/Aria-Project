import pytest
from fastapi import HTTPException
from api.routes.investigations import _validate_admin_access
from config.settings import get_settings


class TestInternalTrustedAdminSecret:
    def test_missing_admin_secret_header_raises_403(self, monkeypatch):
        monkeypatch.setenv("ARIA_ADMIN_SECRET", "secret-123")
        get_settings.cache_clear()
        with pytest.raises(HTTPException) as exc:
            _validate_admin_access("admin", None)
        assert exc.value.status_code == 403
        assert "X-ARIA-Admin-Secret" in exc.value.detail

    def test_wrong_admin_secret_raises_403(self, monkeypatch):
        monkeypatch.setenv("ARIA_ADMIN_SECRET", "secret-123")
        get_settings.cache_clear()
        with pytest.raises(HTTPException) as exc:
            _validate_admin_access("admin", "wrong-secret")
        assert exc.value.status_code == 403
        assert "Invalid admin secret" in exc.value.detail

    def test_correct_admin_secret_returns_actor(self, monkeypatch):
        monkeypatch.setenv("ARIA_ADMIN_SECRET", "secret-123")
        get_settings.cache_clear()
        result = _validate_admin_access("ghazi", "secret-123")
        assert result == "ghazi"

    def test_default_admin_secret_blocked(self, monkeypatch):
        for bad in ["changeme", "default", "admin", ""]:
            monkeypatch.setenv("ARIA_ADMIN_SECRET", bad)
            get_settings.cache_clear()
            with pytest.raises(HTTPException) as exc:
                _validate_admin_access("admin", bad)
            assert exc.value.status_code == 403
            assert "not configured" in exc.value.detail.lower()

    def test_decided_by_spoofing_alone_does_not_grant_access(self, monkeypatch):
        monkeypatch.setenv("ARIA_ADMIN_SECRET", "secret-123")
        get_settings.cache_clear()
        with pytest.raises(HTTPException) as exc:
            _validate_admin_access("admin", None)
        assert exc.value.status_code == 403
