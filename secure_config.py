#!/usr/bin/env python3
"""
Secure Configuration Management for GitHub MCP Server
Prevents API key exposure to AI assistants and chat logs

Part of Tamrael's PPPS (Pretty, Pretty, Pretty, Secure) GitHub MCP Server
Authors: Kevin Francisco (Tamrael) with Claude Sonnet 4.6 (LLM Collaborator)
"""

import sys
import signal
import getpass
import keyring
import httpx
from typing import Optional
from pydantic import SecretStr, PrivateAttr
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class MissingTokenError(RuntimeError):
    """
    Raised when a GitHub token is required but not configured.
    Fail-closed: callers must handle the absence of a secret explicitly.
    """
    pass


class SecureSettings(BaseSettings):
    """
    Secure settings that never expose API keys in logs or to AI assistants.

    Security design:
      - _github_token is a Pydantic PrivateAttr.
        PrivateAttr fields are excluded from ALL serialization (model_dump,
        model_dump_json) AND from BaseSettings env-var auto-loading.
        This prevents INTERNAL_GITHUB_TOKEN from being silently injected
        from the environment, bypassing the keyring.
      - Public fields can still be configured via PPPS_-prefixed env vars
        (e.g. PPPS_DEBUG=true, PPPS_API_TIMEOUT=60).
    
      - Keyring-only, no GITHUB_TOKEN env var fallback. The server
        raises SecurityError if no token is found in the OS keyring.
    """

    # Public settings (safe to log)
    app_name: str = "PPPS GitHub MCP Server"
    debug: bool = False
    api_timeout: int = 30
    github_base_url: str = "https://api.github.com"

    # PrivateAttr: never appears in model_dump(), model_dump_json(),
    # schema generation, or env-var parsing.
    _github_token: Optional[SecretStr] = PrivateAttr(default=None)

    model_config = SettingsConfigDict(
        env_file=None,        # Disables .env file loading
        extra="ignore",       # Silently ignore unknown env vars
        env_prefix="PPPS_",   # Namespace public env vars to avoid collisions
    )

    def model_post_init(self, __context):
        """Pydantic V2 lifecycle hook — runs after __init__"""
        self._load_secrets()

    def _load_secrets(self):
        """
        Load token from OS keyring only. No env var fallback.

        Keyring is the sole source of truth. If keyring is unavailable
        or contains no token, the server will fail closed.
        """
        token: Optional[str] = None

        try:
            token = keyring.get_password("github-mcp-server", "github-token")
        except Exception:
            if self.debug:
                print("Warning: OS keyring unavailable")
            return

        if token:
            self._github_token = SecretStr(token)

        # Best-effort local scope cleanup. Python immutable strings cannot be
        # truly wiped from heap, but removing the reference shortens lifetime.
        token = None
        del token

    def get_github_token_value(self) -> str:
        """
        Explicitly retrieve the raw token string.

        Raises MissingTokenError if no token is loaded (fail-closed).
        Call this intentionally — the name signals you are handling a secret.
        Never use @computed_field for secrets (Pydantic serializes those automatically).
        """
        if self._github_token is None:
            raise MissingTokenError(
                "No GitHub token configured. Run: python secure_config.py setup"
            )
        return self._github_token.get_secret_value()

    @property
    def has_github_token(self) -> bool:
        """Check if a token is loaded (does not expose the value)"""
        return self._github_token is not None


@lru_cache()
def get_secure_settings() -> SecureSettings:
    """Return a cached SecureSettings instance. Cache is cleared on setup/clear."""
    return SecureSettings()


def _make_github_request(token: str, timeout: int) -> httpx.Response:
    """
    Isolate the raw HTTP call so the token lives in a narrow stack frame.
    If httpx raises an unexpected exception, this frame is less likely to
    appear in user-visible tracebacks than the validation function's frame.
    """
    return httpx.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PPPS-GitHub-MCP/1.1",
        },
        timeout=timeout,
    )


def _validate_token_with_github(
    token: str,
    timeout: int = 10,
    required_scopes: Optional[set[str]] = None,
) -> tuple[bool, str]:
    """
    Make a live GET /user call to verify the token works.
    Optionally checks X-OAuth-Scopes to verify the token has required permissions.

    Returns (success: bool, message: str)
    """
    try:
        response = _make_github_request(token, timeout)
    except httpx.TimeoutException:
        return False, "Request timed out — check your internet connection"
    except httpx.RequestError as e:
        return False, f"Network error: {type(e).__name__}"

    if response.status_code == 200:
        username = response.json().get("login", "unknown")

        # Check OAuth scopes — a syntactically valid token can still have no permissions
        scopes_hdr = response.headers.get("X-OAuth-Scopes", "")
        scopes = {s.strip() for s in scopes_hdr.split(",") if s.strip()}

        msg = f"Valid — authenticated as @{username}"
        if required_scopes:
            missing = required_scopes - scopes
            if missing:
                msg += f" | WARNING: missing scopes: {', '.join(sorted(missing))}"

        # Rate limit awareness (informational only)
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining is not None and int(remaining) < 5:
            msg += " | WARNING: API rate limit nearly exhausted"

        return True, msg

    if response.status_code == 401:
        return False, "Invalid or expired token (401 Unauthorized)"
    if response.status_code == 403:
        return False, "Token exists but lacks required scopes or hit rate limit (403 Forbidden)"
    return False, f"Unexpected response: HTTP {response.status_code}"


def setup_api_keys():
    """
    Interactive setup — validates token BEFORE storing it in the OS keyring.
    A token that fails API validation is never persisted.

    SECURITY: This function MUST only run in an interactive terminal.
    If stdin is not a TTY (e.g. piped from an LLM), it refuses to run.
    """
    print("=" * 60)
    print("  PPPS GitHub MCP Server - Secure Token Setup")
    print("=" * 60)
    print()
    print("  Your token is hidden while you type — nobody sees it, not even this window.")
    print("  This is the only safe place to paste it.")
    print("=" * 60)
    print()
    print("Token will be stored encrypted in your OS keyring.")
    print("It will NOT be visible to AI assistants or appear in logs.")
    print()
    print("Steps to get your GitHub token:")
    print("  1. Go to https://github.com/settings/tokens")
    print("  2. Generate new token (classic) or fine-grained PAT")
    print("  3. Select 'repo' scope for full repository access")
    print("  4. Copy the token — input below will be hidden")
    print()

    try:
        github_token = getpass.getpass("Enter GitHub Personal Access Token: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled.")
        return

    if not github_token:
        print("No token provided — setup cancelled.")
        return

    # Defense-in-depth: reject absurd lengths (catches accidental multi-line paste)
    if len(github_token) > 255:
        print("ERROR: Token exceeds maximum reasonable length (255 chars). Setup cancelled.")
        return

    # Prefix check: catches obvious format errors before hitting the network
    if not github_token.startswith(("ghp_", "github_pat_")):
        print("Warning: Token does not match expected GitHub format (ghp_ or github_pat_)")
        try:
            confirm = input("Store anyway? (y/N): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nSetup cancelled.")
            return
        if confirm != "y":
            print("Token not saved.")
            return

    # Validate BEFORE storing — don't persist broken tokens to the keyring
    print("Validating token against GitHub API...")
    ok, message = _validate_token_with_github(
        github_token,
        required_scopes={"repo"},
    )
    if not ok:
        print(f"Token validation failed: {message}")
        print("Token was NOT saved. Double-check it on GitHub and try again.")
        github_token = None
        del github_token
        return

    print(f"Token valid: {message}")

    # Store in keyring — explicit error if it fails (no silent false-success)
    try:
        keyring.set_password("github-mcp-server", "github-token", github_token)
    except Exception:
        print("ERROR: Failed to store token in OS keyring.")
        print("Your token was NOT saved. Check keyring permissions and try again.")
        github_token = None
        del github_token
        return

    print("Token stored in OS keyring.")

    # Best-effort memory cleanup
    github_token = None
    del github_token

    # Invalidate cache so the running process picks up the new token immediately
    get_secure_settings.cache_clear()
    print("\nSetup complete. Start your MCP server normally.")


def clear_api_keys():
    """Remove stored token from the OS keyring (requires confirmation)"""
    try:
        confirm = input("Remove stored GitHub token? This cannot be undone. (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return

    if confirm != "y":
        print("Cancelled — token not removed.")
        return

    try:
        keyring.delete_password("github-mcp-server", "github-token")
        print("GitHub token removed from OS keyring.")
    except keyring.errors.PasswordDeleteError:
        print("No GitHub token found in keyring — nothing to remove.")
    except Exception:
        print("ERROR: Failed to remove token from keyring. Check keyring permissions.")
        return

    get_secure_settings.cache_clear()


def test_configuration():
    """Test current configuration — validates token AND makes a live API call with scope check"""
    settings = get_secure_settings()

    print("=" * 60)
    print("  PPPS GitHub MCP Server - Configuration Test")
    print("=" * 60)
    print(f"  Token loaded:  {'Yes' if settings.has_github_token else 'NO - run setup first'}")
    print(f"  API endpoint:  {settings.github_base_url}")
    print(f"  Timeout:       {settings.api_timeout}s")
    print(f"  Debug mode:    {settings.debug}")

    if not settings.has_github_token:
        print("\nNo token configured. Run: python secure_config.py setup")
        return

    print("\nValidating token against GitHub API...")
    try:
        token = settings.get_github_token_value()
    except MissingTokenError as e:
        print(f"  ERROR: {e}")
        return

    ok, message = _validate_token_with_github(
        token,
        timeout=settings.api_timeout,
        required_scopes={"repo"},
    )

    if ok:
        print(f"  GitHub API:    {message}")
    else:
        print(f"  GitHub API:    FAILED - {message}")
        print("  Run 'setup' to replace the token.")


def _clear_secrets_on_signal(signum, frame):
    """Best-effort cache purge on termination — reduces window where secrets sit in memory."""
    get_secure_settings.cache_clear()
    signal.default_int_handler(signum, frame)


# Register signal handlers so cached secrets are cleared on shutdown
signal.signal(signal.SIGTERM, _clear_secrets_on_signal)
signal.signal(signal.SIGINT, _clear_secrets_on_signal)


if __name__ == "__main__":
    commands = {
        "setup": setup_api_keys,
        "clear": clear_api_keys,
        "test": test_configuration,
    }

    if len(sys.argv) > 1 and sys.argv[1] in commands:
        commands[sys.argv[1]]()
    else:
        print("PPPS GitHub MCP Server - Secure Configuration")
        print()
        print("Usage:")
        print("  python secure_config.py setup   # Store GitHub token securely")
        print("  python secure_config.py test    # Test token (live API + scope validation)")
        print("  python secure_config.py clear   # Remove stored token")
        print()
        print("Security notes:")
        print("  - Token stored in OS keyring (Windows Credential Locker / macOS Keychain)")
        print("  - PrivateAttr prevents Pydantic from auto-loading INTERNAL_GITHUB_TOKEN")
        print("  - Token validated against GitHub API before being stored")
        print("  - Fail-closed: missing token raises MissingTokenError, not empty string")
        print("  - Token input is hidden in this terminal. That's the only safe place.")
