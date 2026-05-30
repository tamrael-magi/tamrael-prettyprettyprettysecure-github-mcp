"""
Tests for secure_config.py — token storage & fail-closed behavior.

These tests mock the OS keyring and the GitHub API so they run anywhere
(CI included) with no real secrets and no network access.

Key behaviors under test:
  - Token is loaded from keyring (and ONLY keyring).
  - PrivateAttr token is never exposed via Pydantic serialization.
  - Missing token fails closed (raises MissingTokenError), never returns "".
  - Live token validation maps HTTP status codes correctly.
"""

import pytest

import secure_config as c


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Each test gets a fresh, un-cached SecureSettings."""
    c.get_secure_settings.cache_clear()
    yield
    c.get_secure_settings.cache_clear()


# ---------------------------------------------------------------------------
# Token loading from keyring
# ---------------------------------------------------------------------------
class TestTokenLoading:
    def test_loads_token_from_keyring(self, monkeypatch):
        monkeypatch.setattr(c.keyring, "get_password", lambda svc, user: "ghp_faketoken")
        settings = c.SecureSettings()
        assert settings.has_github_token is True
        assert settings.get_github_token_value() == "ghp_faketoken"

    def test_no_token_in_keyring_fails_closed(self, monkeypatch):
        monkeypatch.setattr(c.keyring, "get_password", lambda svc, user: None)
        settings = c.SecureSettings()
        assert settings.has_github_token is False
        with pytest.raises(c.MissingTokenError):
            settings.get_github_token_value()

    def test_keyring_exception_is_swallowed_and_fails_closed(self, monkeypatch):
        def boom(svc, user):
            raise RuntimeError("keyring backend unavailable")
        monkeypatch.setattr(c.keyring, "get_password", boom)
        settings = c.SecureSettings()
        # Should not crash the process; should simply have no token.
        assert settings.has_github_token is False
        with pytest.raises(c.MissingTokenError):
            settings.get_github_token_value()


# ---------------------------------------------------------------------------
# Token must never leak through serialization
# ---------------------------------------------------------------------------
class TestTokenNeverSerialized:
    def test_token_absent_from_model_dump(self, monkeypatch):
        monkeypatch.setattr(c.keyring, "get_password", lambda svc, user: "ghp_supersecret")
        settings = c.SecureSettings()
        dumped = settings.model_dump()
        assert "ghp_supersecret" not in str(dumped)
        assert "_github_token" not in dumped

    def test_token_absent_from_model_dump_json(self, monkeypatch):
        monkeypatch.setattr(c.keyring, "get_password", lambda svc, user: "ghp_supersecret")
        settings = c.SecureSettings()
        as_json = settings.model_dump_json()
        assert "ghp_supersecret" not in as_json

    def test_token_absent_from_repr(self, monkeypatch):
        monkeypatch.setattr(c.keyring, "get_password", lambda svc, user: "ghp_supersecret")
        settings = c.SecureSettings()
        assert "ghp_supersecret" not in repr(settings)


# ---------------------------------------------------------------------------
# Env var injection of the token must be impossible
# ---------------------------------------------------------------------------
class TestNoEnvVarTokenInjection:
    def test_github_token_env_var_is_ignored(self, monkeypatch):
        # An attacker setting GITHUB_TOKEN / INTERNAL_GITHUB_TOKEN must NOT
        # populate the private token field — keyring is the only source.
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_injected_via_env")
        monkeypatch.setenv("INTERNAL_GITHUB_TOKEN", "ghp_injected_via_env2")
        monkeypatch.setattr(c.keyring, "get_password", lambda svc, user: None)
        settings = c.SecureSettings()
        assert settings.has_github_token is False


# ---------------------------------------------------------------------------
# Live token validation — status code mapping (network mocked)
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {}

    def json(self):
        return self._json


class TestTokenValidation:
    def test_valid_token_200(self, monkeypatch):
        resp = _FakeResponse(
            200,
            {"login": "octocat"},
            {"X-OAuth-Scopes": "repo, read:org", "X-RateLimit-Remaining": "5000"},
        )
        monkeypatch.setattr(c, "_make_github_request", lambda token, timeout: resp)
        ok, msg = c._validate_token_with_github("ghp_x", required_scopes={"repo"})
        assert ok is True
        assert "octocat" in msg

    def test_missing_scope_warns(self, monkeypatch):
        resp = _FakeResponse(
            200,
            {"login": "octocat"},
            {"X-OAuth-Scopes": "read:org"},  # 'repo' missing
        )
        monkeypatch.setattr(c, "_make_github_request", lambda token, timeout: resp)
        ok, msg = c._validate_token_with_github("ghp_x", required_scopes={"repo"})
        assert ok is True
        assert "missing scopes" in msg.lower()

    def test_invalid_token_401(self, monkeypatch):
        resp = _FakeResponse(401)
        monkeypatch.setattr(c, "_make_github_request", lambda token, timeout: resp)
        ok, msg = c._validate_token_with_github("ghp_x")
        assert ok is False
        assert "401" in msg

    def test_forbidden_403(self, monkeypatch):
        resp = _FakeResponse(403)
        monkeypatch.setattr(c, "_make_github_request", lambda token, timeout: resp)
        ok, msg = c._validate_token_with_github("ghp_x")
        assert ok is False
        assert "403" in msg

    def test_timeout_handled(self, monkeypatch):
        def raise_timeout(token, timeout):
            raise c.httpx.TimeoutException("timed out")
        monkeypatch.setattr(c, "_make_github_request", raise_timeout)
        ok, msg = c._validate_token_with_github("ghp_x")
        assert ok is False
        assert "timed out" in msg.lower()
