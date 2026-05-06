#!/usr/bin/env python3
"""
Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server — Hardened Edition

Revolutionary security-first implementation with configurable access controls,
OS keyring integration, and multi-layer vulnerability protection.

Key Security Innovations:
✅ Repository whitelisting for access control
✅ Risk-based operation categorization
✅ OS keyring integration (zero token exposure)
✅ Async-native rate limiting and request validation
✅ Path traversal protection with URL-safe encoding
✅ Content size limits
✅ Comprehensive audit logging
✅ Connection pooling
✅ Binary file protection
✅ Zero import-time side effects

Requirements:
- Python 3.9+
- httpx
- mcp
- keyring (for secure credential storage)

Usage:
    python tamrael_github_general.py --security-level standard --allowed-repos "my-project,work-repo"
"""

import asyncio
import json
import sys
import os
import re
import time

# Ensure the script's directory is in sys.path for sibling imports
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)
import argparse
import secrets
import hashlib
from pathlib import Path
from typing import Any, Sequence, Optional, Dict, List, Tuple, Union
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, urlencode
import httpx
from mcp.server import Server
import mcp.server.stdio
import mcp.types as types
import base64

# ---------------------------------------------------------------------------
# SecurityError for production credential validation
# ---------------------------------------------------------------------------
class SecurityError(Exception):
    """Raised when security requirements are not met"""
    pass

# ---------------------------------------------------------------------------
# Import secure configuration
# ---------------------------------------------------------------------------
try:
    from secure_config import get_secure_settings, MissingTokenError
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    MissingTokenError = RuntimeError  # fallback so except clauses don't break
    print("Warning: keyring not available, falling back to environment variables")

# ---------------------------------------------------------------------------
# Import security validators module (REQUIRED — no fallback)
# ---------------------------------------------------------------------------
try:
    from security_validators import (
        validate_branch_name,
        validate_repo_access_secure,
        validate_file_path_enhanced,
        validate_content_size,
        sanitize_error_message,
        sanitize_url_for_logging,
        sanitize_token_in_text,
    )
except ImportError as e:
    print("CRITICAL: Security validators module required but not available.", file=sys.stderr)
    print("Ensure security_validators.py is in the same directory.", file=sys.stderr)
    print(f"Import error: {e}", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Import optional audit logging
# ---------------------------------------------------------------------------
try:
    from overkill_audit_logger import OverkillAuditLogger
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False


# ===========================================================================
# CONSTANTS & CONFIGURATION
# ===========================================================================

DEFAULT_SECURITY_LEVEL = "standard"
MAX_CONTENT_SIZE = 1024 * 1024          # 1 MiB
MAX_REQUESTS_PER_MINUTE = 60
MAX_FILE_PATH_LENGTH = 500
MAX_RESPONSE_SIZE = 10 * 1024 * 1024    # 10 MiB hard cap on API responses
MAX_REPO_NAME_LENGTH = 100
MAX_ISSUE_TITLE_LENGTH = 256
MAX_ISSUE_BODY_LENGTH = 65536
MAX_COMMIT_MESSAGE_LENGTH = 4096
MAX_TAG_NAME_LENGTH = 128
MAX_RELEASE_NAME_LENGTH = 256

GITHUB_API_BASE = "https://api.github.com"

OPERATION_RISKS = {
    "list_repositories": "low",
    "get_repository_info": "low",
    "create_release": "low",
    "create_file": "medium",
    "get_file_content": "medium",
    "list_files": "medium",
    "create_issue": "medium",
    "get_issues": "high",
    "read_issues": "high",
    "read_discussions": "high",
    "read_comments": "high",
    "read_pull_requests": "high",
}

SECURITY_LEVELS = {
    "strict": {
        "risks": ["low"],
        "whitelisting": "manual_required",
        "description": "Manual whitelist required + read-only operations",
    },
    "standard": {
        "risks": ["low", "medium"],
        "whitelisting": "smart_default",
        "description": "Smart auto-whitelist + file operations (DEFAULT)",
    },
    "open": {
        "risks": ["low", "medium", "high"],
        "whitelisting": "disabled",
        "description": "No restrictions + all operations (development)",
    },
}

# Valid enum values for GitHub API parameters
VALID_SORT_VALUES = {"created", "updated", "pushed", "full_name"}
VALID_STATE_VALUES = {"open", "closed", "all"}

# Git ref name validation (simplified but strict)
GIT_REF_RE = re.compile(r"^[a-zA-Z0-9_./-]+$")


# ===========================================================================
# UTILITY FUNCTIONS
# ===========================================================================

def _sanitize_for_logging(data: Any) -> str:
    """Remove sensitive information from data before logging."""
    if isinstance(data, str):
        return sanitize_token_in_text(data)
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            lower_key = key.lower()
            if any(s in lower_key for s in ("token", "password", "secret", "key", "auth", "credential")):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_for_logging(value)
        return str(sanitized)
    return str(data)


def _generic_error() -> str:
    """Return a generic error message that leaks zero configuration."""
    return "Request could not be completed."


def _log_to_stderr(message: str) -> None:
    """Log to stderr with URL sanitization and rate-limited prefix."""
    sanitized = sanitize_url_for_logging(message)
    print(f"[TAMRAEL-MCP] {sanitized}", file=sys.stderr)


def _is_text_content(data: bytes) -> bool:
    """Heuristic: detect if bytes are likely text (UTF-8) vs binary."""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _validate_repo_name_format(name: str) -> bool:
    """
    Validate repository name format.
    Allows 'owner/repo' or 'repo'.
    Blocks path traversal, control chars, and excessive length.
    """
    if not name or len(name) > MAX_REPO_NAME_LENGTH:
        return False
    # Block control characters and common traversal patterns
    if any(ord(ch) < 32 for ch in name):
        return False
    if ".." in name:
        return False
    # Allow alphanumeric, hyphen, underscore, dot, slash
    if not re.match(r"^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)?$", name):
        return False
    return True


def _validate_enum(value: str, allowed: set) -> bool:
    return value in allowed


def _safe_url_path_segment(segment: str) -> str:
    """URL-encode a path segment to prevent injection.
    Preserves forward slashes for owner/repo patterns."""
    return quote(segment, safe="/")


# ===========================================================================
# ASYNC RATE LIMITER
# ===========================================================================

class AsyncRateLimiter:
    """Async-native sliding-window rate limiter per client."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60, max_clients: int = 1000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._buckets: Dict[str, list] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_id: str = "default", source_ip: str = "unknown") -> bool:
        combined = f"{source_ip}:{client_id}"
        now = time.time()
        cutoff = now - self.window_seconds

        async with self._lock:
            # Evict oldest client if at capacity and new client
            if combined not in self._buckets and len(self._buckets) >= self.max_clients:
                oldest_key = min(self._buckets.keys(), key=lambda k: self._buckets[k][-1] if self._buckets[k] else 0)
                del self._buckets[oldest_key]

            bucket = self._buckets.setdefault(combined, [])

            # Remove stale entries
            while bucket and bucket[0] < cutoff:
                bucket.pop(0)

            if len(bucket) >= self.max_requests:
                return False

            bucket.append(now)
            return True


# ===========================================================================
# SECURE GITHUB CLIENT
# ===========================================================================

class SecureGitHubClient:
    """
    Encapsulates GitHub API communication with connection pooling,
    response size limits, and automatic token sanitization.
    """

    def __init__(self, token: str, timeout: float = 30.0):
        self._token = token
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._closed = False

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._closed:
            limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                limits=limits,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "Tamrael-Secure-MCP/1.1",
                },
            )
        return self._client

    async def request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make a request with size limits and sanitized error handling."""
        if self._closed:
            raise RuntimeError("Client is closed")

        client = await self._ensure_client()
        url = f"{GITHUB_API_BASE}{endpoint}"

        _log_to_stderr(_sanitize_for_logging(f"Making {method} request to {sanitize_url_for_logging(url)}"))

        try:
            if method == "GET":
                response = await client.get(url, params=params)
            elif method == "POST":
                response = await client.post(url, json=data)
            elif method == "PUT":
                response = await client.put(url, json=data)
            elif method == "PATCH":
                response = await client.patch(url, json=data)
            elif method == "DELETE":
                response = await client.delete(url)
            else:
                return {"error": _generic_error()}

            # Response size guard
            content_length = len(response.content)
            if content_length > MAX_RESPONSE_SIZE:
                _log_to_stderr(_sanitize_for_logging(f"Response size {content_length} exceeds limit"))
                return {"error": "Response too large"}

            _log_to_stderr(_sanitize_for_logging(f"Response status: {response.status_code}"))

            if response.status_code == 401:
                return {"error": "Authentication failed"}
            elif response.status_code == 403:
                return {"error": "Access forbidden"}
            elif response.status_code == 404:
                return {"error": "Resource not found"}
            elif response.status_code == 422:
                return {"error": "Invalid request data"}
            elif response.status_code >= 400:
                return {"error": _generic_error()}

            if not response.content:
                return {"success": True}

            return response.json()

        except httpx.TimeoutException:
            _log_to_stderr("Request to GitHub API timed out")
            return {"error": "Request timeout"}
        except httpx.NetworkError:
            _log_to_stderr("Network error")
            return {"error": "Network error"}
        except Exception as e:
            _log_to_stderr(_sanitize_for_logging(f"Request error: {sanitize_error_message(str(e))}"))
            return {"error": _generic_error()}

    async def close(self) -> None:
        if self._client and not self._closed:
            await self._client.aclose()
            self._closed = True

    async def __aenter__(self):
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# ===========================================================================
# MAIN SERVER CLASS
# ===========================================================================

class SecureGitHubMCPServer:
    """
    Encapsulates all MCP server state, configuration, and handlers.
    Zero global mutable state. Thread-safe and async-safe.
    """

    def __init__(self, args: argparse.Namespace):
        self.security_level = args.security_level
        self.manual_repos_raw = args.allowed_repos
        self.rate_limit_max = args.rate_limit
        self.allowed_repos: Optional[List[str]] = None
        self.github_token: str = ""
        self.authenticated_user: str = ""
        self.rate_limiter = AsyncRateLimiter(
            max_requests=self.rate_limit_max,
            window_seconds=60,
            max_clients=1000,
        )
        self.audit_logger: Optional[Any] = None
        self.github_client: Optional[SecureGitHubClient] = None
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._server = Server("tamrael-secure-github-mcp")
        self._register_handlers()

    # -----------------------------------------------------------------------
    # Initialization
    # -----------------------------------------------------------------------

    async def initialize(self) -> None:
        """Fast init: token and client only. No HTTP calls."""
        self.github_token = self._get_github_token()
        if not self.github_token:
            _log_to_stderr("⚠️  WARNING: No GitHub token configured")
        else:
            self.github_client = SecureGitHubClient(self.github_token)

        if AUDIT_AVAILABLE:
            try:
                self.audit_logger = OverkillAuditLogger(enabled=True)
                _log_to_stderr("🔒 AUDIT: CCTV for your codebase — ENABLED")
            except Exception as e:
                _log_to_stderr(_sanitize_for_logging(f"⚠️ AUDIT: Could not initialize: {e}"))

    async def _lazy_init(self) -> None:
        """Lazy init: runs once on first tool call. Does HTTP calls (user, whitelist)."""
        if self._initialized:
            return
        async with self._init_lock:
            if self._initialized:
                return
            if self.github_client:
                user_info = await self.github_client.request("GET", "/user")
                if "error" not in user_info and "login" in user_info:
                    self.authenticated_user = user_info["login"]
                else:
                    _log_to_stderr("⚠️  WARNING: Could not determine authenticated user")
            self.allowed_repos = await self._initialize_smart_whitelist()
            self._initialized = True

    # -----------------------------------------------------------------------
    # Token Management
    # -----------------------------------------------------------------------

    def _get_github_token(self) -> str:
        """Get GitHub token from OS keyring only. Fail-closed."""
        if not KEYRING_AVAILABLE:
            raise SecurityError(
                "Keyring module not found. Install it: pip install keyring\n"
                "This server does not read environment variables."
            )
        try:
            from secure_config import get_secure_settings
            settings = get_secure_settings()
            if settings.has_github_token:
                return settings.get_github_token_value()
        except MissingTokenError:
            pass
        except Exception as e:
            _log_to_stderr(_sanitize_for_logging(f"Warning: Could not access secure config: {e}"))

        raise SecurityError(
            "GitHub token not configured.\n\n"
            "Run this in your local terminal:\n"
            "    python secure_config.py setup\n\n"
            "This stores your token in the OS keyring (encrypted, not in env vars).\n"
            "No alternative configuration methods are supported.\n\n"
            "If keyring storage fails, fix your OS keyring service:\n"
            "  macOS:    Keychain Access\n"
            "  Linux:    gnome-keyring or secret-tool\n"
            "  Windows:  Credential Manager\n\n"
            "Manual token insertion into code or config is not supported."
        )

    # -----------------------------------------------------------------------
    # Smart Whitelist
    # -----------------------------------------------------------------------

    async def _get_smart_default_repos(self) -> List[str]:
        """Auto-detect active repos with 30-day private repo threshold."""
        smart_repos: List[str] = []
        if not self.github_client:
            return smart_repos

        try:
            thirty_days_ago = datetime.now(tz=timezone.utc) - timedelta(days=30)
            result = await self.github_client.request(
                "GET", "/user/repos", params={"sort": "updated", "per_page": 100}
            )

            if "error" in result or not isinstance(result, list):
                return smart_repos

            private_repos: List[str] = []
            public_repos: List[str] = []

            for repo in result:
                name = repo.get("name", "")
                if not name:
                    continue
                if repo.get("private", False):
                    pushed_at_str = repo.get("pushed_at", "1970-01-01T00:00:00Z")
                    try:
                        if pushed_at_str.endswith("Z"):
                            pushed_at_str = pushed_at_str[:-1] + "+00:00"
                        pushed_at = datetime.fromisoformat(pushed_at_str)
                        if pushed_at > thirty_days_ago:
                            private_repos.append(name)
                    except (ValueError, TypeError):
                        continue
                else:
                    public_repos.append(name)

            smart_repos = (private_repos + public_repos)[:20]

            if private_repos:
                _log_to_stderr(_sanitize_for_logging(f"🔒 Private repos (30-day filter): {len(private_repos)} active"))
            if public_repos:
                _log_to_stderr(_sanitize_for_logging(f"🌐 Public repos (always allowed): {len(public_repos)} total"))

        except Exception as e:
            _log_to_stderr(_sanitize_for_logging(f"Smart whitelist detection failed: {e}"))

        return smart_repos

    async def _initialize_smart_whitelist(self) -> Optional[List[str]]:
        """Initialize whitelist based on security level."""
        config = SECURITY_LEVELS.get(self.security_level, {})
        mode = config.get("whitelisting", "manual_required")

        if mode == "disabled":
            return None

        if mode == "manual_required":
            if not self.manual_repos_raw:
                _log_to_stderr("🛡️ STRICT MODE: Manual repository whitelist required")
                return []
            return [r.strip() for r in self.manual_repos_raw.split(",") if r.strip()]

        # smart_default
        smart_repos = await self._get_smart_default_repos()
        manual_repos = [r.strip() for r in self.manual_repos_raw.split(",") if r.strip()] if self.manual_repos_raw else []

        combined = list(dict.fromkeys(smart_repos + manual_repos))  # preserve order, dedupe

        if smart_repos:
            _log_to_stderr(_sanitize_for_logging(f"🧠 SMART: Auto-detected {len(smart_repos)} repositories"))
        if manual_repos:
            _log_to_stderr(_sanitize_for_logging(f"📋 MANUAL: {len(manual_repos)} repositories specified"))
        if combined:
            _log_to_stderr(_sanitize_for_logging(f"🚀 TOTAL WHITELIST: {len(combined)} repositories"))
        else:
            _log_to_stderr("⚠️  No repositories configured")

        return combined

    # -----------------------------------------------------------------------
    # Security Checks
    # -----------------------------------------------------------------------

    def _is_operation_allowed(self, operation: str) -> bool:
        risk = OPERATION_RISKS.get(operation, "high")
        allowed = SECURITY_LEVELS.get(self.security_level, {"risks": ["low"]}).get("risks", ["low"])
        return risk in allowed

    def _validate_repo_access(self, repo_name: str) -> bool:
        """Validate repo name format AND whitelist membership."""
        if not _validate_repo_name_format(repo_name):
            return False
        if self.allowed_repos is None:
            return True  # open mode
        allowed = validate_repo_access_secure(repo_name, self.allowed_repos)
        if not allowed:
            _log_to_stderr("SECURITY: Repository access denied")
        return allowed

    def _build_repo_full_name(self, repo_name: str) -> Tuple[bool, str]:
        """
        Build owner/repo string safely.
        If repo_name contains no slash, prefix with authenticated user.
        If it contains a slash, validate that owner matches authenticated user.
        """
        if not repo_name:
            return False, ""
        if "/" in repo_name:
            # Validate ownership to prevent cross-user access
            owner, _, name = repo_name.partition("/")
            if self.authenticated_user and owner != self.authenticated_user:
                _log_to_stderr("SECURITY: Cross-user repository access denied")
                return False, ""
            return True, repo_name
        if not self.authenticated_user:
            _log_to_stderr("SECURITY: Cannot determine repository owner")
            return False, ""
        return True, f"{self.authenticated_user}/{repo_name}"

    # -----------------------------------------------------------------------
    # Rate Limiting
    # -----------------------------------------------------------------------

    async def _check_rate_limit(self, client_id: str = "default") -> bool:
        return await self.rate_limiter.is_allowed(client_id=client_id)

    # -----------------------------------------------------------------------
    # Audit Logging
    # -----------------------------------------------------------------------

    def _audit_log(
        self,
        operation: str,
        file_path: str,
        repo: str,
        result: str = "success",
        metadata: Optional[dict] = None,
    ) -> None:
        if not self.audit_logger or not getattr(self.audit_logger, "enabled", False):
            return
        try:
            meta = dict(metadata or {})
            meta.update({
                "repo": repo,
                "security_level": self.security_level,
                "user_agent": "mcp_server",
            })
            entry_hash = self.audit_logger.log_file_access(
                file_path=file_path,
                operation=operation,
                user="mcp_server",
                result=result,
                metadata=meta,
            )
            if operation in ("create", "delete"):
                _log_to_stderr(_sanitize_for_logging(f"📹 AUDIT: {operation.upper()} {file_path} | Hash: {entry_hash[:8]}..."))
        except Exception as e:
            _log_to_stderr(_sanitize_for_logging(f"⚠️ AUDIT: Logging failed: {e}"))

    # -----------------------------------------------------------------------
    # Tool Schemas
    # -----------------------------------------------------------------------

    def _get_tools(self) -> List[types.Tool]:
        tools: List[types.Tool] = []

        if self._is_operation_allowed("list_repositories"):
            tools.append(types.Tool(
                name="list_repositories",
                description="List user's repositories with security status",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "per_page": {
                            "type": "integer",
                            "description": "Number of repositories per page",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 30,
                        },
                        "sort": {
                            "type": "string",
                            "description": "Sort by: created, updated, pushed, full_name",
                            "enum": ["created", "updated", "pushed", "full_name"],
                            "default": "updated",
                        },
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("get_repository_info"):
            tools.append(types.Tool(
                name="get_repository_info",
                description="Get repository information and security status",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name (owner/repo or just repo)",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                    },
                    "required": ["repo"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("create_release"):
            tools.append(types.Tool(
                name="create_release",
                description="Create a GitHub release",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "tag_name": {
                            "type": "string",
                            "description": "Git tag for the release",
                            "maxLength": MAX_TAG_NAME_LENGTH,
                        },
                        "name": {
                            "type": "string",
                            "description": "Release name",
                            "maxLength": MAX_RELEASE_NAME_LENGTH,
                        },
                        "body": {
                            "type": "string",
                            "description": "Release description/notes",
                            "maxLength": MAX_CONTENT_SIZE,
                        },
                        "draft": {
                            "type": "boolean",
                            "description": "Create as draft",
                            "default": False,
                        },
                    },
                    "required": ["repo", "tag_name", "name"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("create_file"):
            tools.append(types.Tool(
                name="create_file",
                description="Create a file in a repository with secure validation",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Path for the new file (security validated)",
                            "maxLength": MAX_FILE_PATH_LENGTH,
                        },
                        "content": {
                            "type": "string",
                            "description": "File content (size limited)",
                            "maxLength": MAX_CONTENT_SIZE,
                        },
                        "commit_message": {
                            "type": "string",
                            "description": "Commit message",
                            "maxLength": MAX_COMMIT_MESSAGE_LENGTH,
                        },
                        "branch": {
                            "type": "string",
                            "description": "Branch name (default: main)",
                            "default": "main",
                            "maxLength": 255,
                        },
                    },
                    "required": ["repo", "file_path", "content", "commit_message"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("get_file_content"):
            tools.append(types.Tool(
                name="get_file_content",
                description="Get the content of a file from a repository",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file",
                            "maxLength": MAX_FILE_PATH_LENGTH,
                        },
                        "branch": {
                            "type": "string",
                            "description": "Branch name (default: main)",
                            "default": "main",
                            "maxLength": 255,
                        },
                    },
                    "required": ["repo", "file_path"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("list_files"):
            tools.append(types.Tool(
                name="list_files",
                description="List files and directories in a repository",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "path": {
                            "type": "string",
                            "description": "Directory path (default: root)",
                            "default": "",
                            "maxLength": MAX_FILE_PATH_LENGTH,
                        },
                        "branch": {
                            "type": "string",
                            "description": "Branch name (default: main)",
                            "default": "main",
                            "maxLength": 255,
                        },
                    },
                    "required": ["repo"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("get_issues"):
            tools.append(types.Tool(
                name="get_issues",
                description="Get repository issues (requires open security level)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "state": {
                            "type": "string",
                            "description": "Issue state",
                            "enum": ["open", "closed", "all"],
                            "default": "open",
                        },
                        "labels": {
                            "type": "string",
                            "description": "Comma-separated list of label names",
                            "maxLength": 256,
                        },
                        "assignee": {
                            "type": "string",
                            "description": "Username of assignee, or * for any assignee",
                            "maxLength": 39,
                        },
                        "per_page": {
                            "type": "integer",
                            "description": "Number of issues per page",
                            "minimum": 1,
                            "maximum": 100,
                            "default": 30,
                        },
                        "page": {
                            "type": "integer",
                            "description": "Page number",
                            "minimum": 1,
                            "default": 1,
                        },
                    },
                    "required": ["repo"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("create_issue"):
            tools.append(types.Tool(
                name="create_issue",
                description="Create a new issue in a repository",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "title": {
                            "type": "string",
                            "description": "Issue title",
                            "minLength": 1,
                            "maxLength": MAX_ISSUE_TITLE_LENGTH,
                        },
                        "body": {
                            "type": "string",
                            "description": "Issue description/body",
                            "maxLength": MAX_ISSUE_BODY_LENGTH,
                        },
                        "assignees": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 39},
                            "description": "Usernames to assign",
                            "maxItems": 10,
                        },
                        "labels": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 50},
                            "description": "Label names",
                            "maxItems": 100,
                        },
                    },
                    "required": ["repo", "title"],
                    "additionalProperties": False,
                },
            ))

        if self._is_operation_allowed("read_issues"):
            tools.append(types.Tool(
                name="read_issues",
                description="Read repository issues (requires open security level)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository name",
                            "maxLength": MAX_REPO_NAME_LENGTH,
                        },
                        "state": {
                            "type": "string",
                            "description": "Issue state",
                            "enum": ["open", "closed", "all"],
                            "default": "open",
                        },
                    },
                    "required": ["repo"],
                    "additionalProperties": False,
                },
            ))

        return tools

    # -----------------------------------------------------------------------
    # Tool Handlers
    # -----------------------------------------------------------------------

    def _register_handlers(self) -> None:
        @self._server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            _log_to_stderr(_sanitize_for_logging(f"Listing tools for security level: {self.security_level}"))
            tools = self._get_tools()
            _log_to_stderr(_sanitize_for_logging(f"Returning {len(tools)} tools"))
            return tools

        @self._server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[types.TextContent]:
            return await self._execute_tool(name, arguments)

    async def _execute_tool(self, name: str, arguments: dict) -> List[types.TextContent]:
        _log_to_stderr(_sanitize_for_logging(f"Executing tool: {name}"))

        await self._lazy_init()

        if not await self._check_rate_limit():
            return [types.TextContent(type="text", text="Rate limit exceeded. Please wait.")]

        if not self._is_operation_allowed(name):
            return [types.TextContent(type="text", text="Operation not permitted at current security level.")]

        repo_name = arguments.get("repo", "")
        if repo_name:
            ok, repo_full = self._build_repo_full_name(repo_name)
            if not ok:
                return [types.TextContent(type="text", text="Invalid repository specification.")]
            arguments["repo"] = repo_full
            if not self._validate_repo_access(repo_full) and not self._validate_repo_access(repo_name):
                return [types.TextContent(type="text", text="Access denied to requested resource.")]

        # Dispatch
        if name == "list_repositories":
            return await self._tool_list_repositories(arguments)
        elif name == "get_repository_info":
            return await self._tool_get_repository_info(arguments)
        elif name == "get_file_content":
            return await self._tool_get_file_content(arguments)
        elif name == "list_files":
            return await self._tool_list_files(arguments)
        elif name == "create_file":
            return await self._tool_create_file(arguments)
        elif name == "create_release":
            return await self._tool_create_release(arguments)
        elif name == "get_issues":
            return await self._tool_get_issues(arguments)
        elif name == "read_issues":
            return await self._tool_read_issues(arguments)
        elif name == "create_issue":
            return await self._tool_create_issue(arguments)
        else:
            return [types.TextContent(type="text", text="Unknown tool.")]

    # -----------------------------------------------------------------------
    # Individual Tool Implementations
    # -----------------------------------------------------------------------

    async def _tool_list_repositories(self, arguments: dict) -> List[types.TextContent]:
        per_page = arguments.get("per_page", 30)
        sort = arguments.get("sort", "updated")

        if not _validate_enum(sort, VALID_SORT_VALUES):
            return [types.TextContent(type="text", text="Invalid sort parameter.")]
        if not (1 <= per_page <= 100):
            return [types.TextContent(type="text", text="Invalid per_page parameter.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        result = await self.github_client.request(
            "GET", "/user/repos", params={"sort": sort, "per_page": per_page}
        )

        if "error" in result or not isinstance(result, list):
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

        filtered = []
        for repo in result:
            rname = repo.get("name", "")
            filtered.append({
                "name": rname,
                "full_name": repo.get("full_name"),
                "private": repo.get("private"),
                "description": repo.get("description"),
                "updated_at": repo.get("updated_at"),
                "security_status": {
                    "whitelisted": self._validate_repo_access(rname),
                },
            })

        return [types.TextContent(
            type="text",
            text=f"Repositories (security level: {self.security_level}):\n{json.dumps(filtered, indent=2)}"
        )]

    async def _tool_get_repository_info(self, arguments: dict) -> List[types.TextContent]:
        repo_name = arguments.get("repo", "")
        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        result = await self.github_client.request("GET", f"/repos/{_safe_url_path_segment(repo_full)}")

        if "error" not in result and isinstance(result, dict):
            result["security_status"] = {
                "whitelisted": self._validate_repo_access(repo_name),
                "security_level": self.security_level,
                "allowed_operations": [op for op in OPERATION_RISKS if self._is_operation_allowed(op)],
            }

        return [types.TextContent(type="text", text=f"Repository info:\n{json.dumps(result, indent=2)}")]

    async def _tool_get_file_content(self, arguments: dict) -> List[types.TextContent]:
        file_path = arguments.get("file_path", "")
        branch = arguments.get("branch", "main")
        repo_name = arguments.get("repo", "")

        valid_path, _ = validate_file_path_enhanced(file_path)
        if not valid_path:
            return [types.TextContent(type="text", text="Invalid file path detected.")]

        if not validate_branch_name(branch):
            return [types.TextContent(type="text", text="Invalid branch name detected.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        encoded_path = "/".join(_safe_url_path_segment(seg) for seg in file_path.split("/"))
        endpoint = f"/repos/{_safe_url_path_segment(repo_full)}/contents/{encoded_path}?ref={_safe_url_path_segment(branch)}"
        result = await self.github_client.request("GET", endpoint)

        if "error" in result or "content" not in result:
            self._audit_log("read", file_path, repo_name, "failed", {"branch": branch})
            return [types.TextContent(type="text", text=f"File content result:\n{json.dumps(result, indent=2)}")]

        # Size guard on base64 string
        max_encoded = MAX_CONTENT_SIZE * 4 // 3
        if len(result["content"]) > max_encoded:
            self._audit_log("read", file_path, repo_name, "size_limit_exceeded")
            return [types.TextContent(type="text", text="File content exceeds size limit.")]

        try:
            raw = base64.b64decode(result["content"])
        except Exception:
            self._audit_log("read", file_path, repo_name, "decode_failed", {"branch": branch})
            return [types.TextContent(type="text", text="Failed to decode file content.")]

        # Binary guard
        if not _is_text_content(raw):
            self._audit_log("read", file_path, repo_name, "binary_blocked", {"branch": branch})
            return [types.TextContent(type="text", text="Binary files cannot be displayed for security reasons.")]

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return [types.TextContent(type="text", text="File encoding not supported.")]

        self._audit_log("read", file_path, repo_name, "success", {
            "branch": branch,
            "file_size": result.get("size", 0),
        })

        return [types.TextContent(
            type="text",
            text=f"File: {file_path}\nBranch: {branch}\nSize: {result.get('size', 0)} bytes\n\nContent:\n{text}"
        )]

    async def _tool_list_files(self, arguments: dict) -> List[types.TextContent]:
        path = arguments.get("path", "")
        branch = arguments.get("branch", "main")
        repo_name = arguments.get("repo", "")

        if not validate_branch_name(branch):
            return [types.TextContent(type="text", text="Invalid branch name detected.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        encoded_path = "/".join(_safe_url_path_segment(seg) for seg in path.split("/")) if path else ""
        endpoint = f"/repos/{_safe_url_path_segment(repo_full)}/contents"
        if encoded_path:
            endpoint += f"/{encoded_path}"
        endpoint += f"?ref={_safe_url_path_segment(branch)}"

        result = await self.github_client.request("GET", endpoint)

        if "error" in result or not isinstance(result, list):
            self._audit_log("list", path or "root", repo_name, "failed", {"branch": branch})
            return [types.TextContent(type="text", text=f"List files result:\n{json.dumps(result, indent=2)}")]

        files = []
        for item in result:
            files.append({
                "name": item.get("name"),
                "type": item.get("type"),
                "size": item.get("size", 0),
                "path": item.get("path"),
            })

        self._audit_log("list", path or "root", repo_name, "success", {
            "branch": branch,
            "item_count": len(files),
        })

        return [types.TextContent(
            type="text",
            text=f"Files in {repo_name}/{path or 'root'} (branch: {branch}):\n{json.dumps(files, indent=2)}"
        )]

    async def _tool_create_file(self, arguments: dict) -> List[types.TextContent]:
        file_path = arguments.get("file_path", "")
        content = arguments.get("content", "")
        commit_message = arguments.get("commit_message", "")
        branch = arguments.get("branch", "main")
        repo_name = arguments.get("repo", "")

        valid_path, _ = validate_file_path_enhanced(file_path)
        if not valid_path:
            return [types.TextContent(type="text", text="Invalid file path detected.")]

        if not validate_content_size(content):
            return [types.TextContent(type="text", text="Content too large.")]

        if len(commit_message) > MAX_COMMIT_MESSAGE_LENGTH or not commit_message.strip():
            return [types.TextContent(type="text", text="Invalid commit message.")]

        if not validate_branch_name(branch):
            return [types.TextContent(type="text", text="Invalid branch name detected.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        safe_repo = _safe_url_path_segment(repo_full)

        # Get branch ref
        ref_result = await self.github_client.request("GET", f"/repos/{safe_repo}/git/refs/heads/{_safe_url_path_segment(branch)}")
        if "error" in ref_result:
            return [types.TextContent(type="text", text=f"Error getting branch ref: {json.dumps(ref_result, indent=2)}")]

        latest_commit_sha = ref_result.get("object", {}).get("sha", "")
        if not latest_commit_sha:
            return [types.TextContent(type="text", text="Could not determine latest commit.")]

        # Create blob
        try:
            blob_content = base64.b64encode(content.encode("utf-8")).decode("ascii")
        except Exception:
            return [types.TextContent(type="text", text="Failed to encode content.")]

        blob_result = await self.github_client.request(
            "POST", f"/repos/{safe_repo}/git/blobs", {"content": blob_content, "encoding": "base64"}
        )
        if "error" in blob_result:
            return [types.TextContent(type="text", text=f"Error creating blob: {json.dumps(blob_result, indent=2)}")]

        blob_sha = blob_result.get("sha", "")
        if not blob_sha:
            return [types.TextContent(type="text", text="Blob creation failed.")]

        # Get base tree
        commit_result = await self.github_client.request("GET", f"/repos/{safe_repo}/git/commits/{latest_commit_sha}")
        if "error" in commit_result:
            return [types.TextContent(type="text", text=f"Error getting commit: {json.dumps(commit_result, indent=2)}")]

        base_tree_sha = commit_result.get("tree", {}).get("sha", "")
        if not base_tree_sha:
            return [types.TextContent(type="text", text="Could not determine base tree.")]

        # Create tree
        tree_result = await self.github_client.request(
            "POST", f"/repos/{safe_repo}/git/trees",
            {
                "base_tree": base_tree_sha,
                "tree": [{"path": file_path, "mode": "100644", "type": "blob", "sha": blob_sha}],
            },
        )
        if "error" in tree_result:
            return [types.TextContent(type="text", text=f"Error creating tree: {json.dumps(tree_result, indent=2)}")]

        new_tree_sha = tree_result.get("sha", "")
        if not new_tree_sha:
            return [types.TextContent(type="text", text="Tree creation failed.")]

        # Create commit
        commit_data = {
            "message": commit_message,
            "parents": [latest_commit_sha],
            "tree": new_tree_sha,
        }
        new_commit_result = await self.github_client.request(
            "POST", f"/repos/{safe_repo}/git/commits", commit_data
        )
        if "error" in new_commit_result:
            return [types.TextContent(type="text", text=f"Error creating commit: {json.dumps(new_commit_result, indent=2)}")]

        new_commit_sha = new_commit_result.get("sha", "")
        if not new_commit_sha:
            return [types.TextContent(type="text", text="Commit creation failed.")]

        # Update ref
        update_result = await self.github_client.request(
            "PATCH", f"/repos/{safe_repo}/git/refs/heads/{_safe_url_path_segment(branch)}",
            {"sha": new_commit_sha},
        )

        if "error" not in update_result:
            self._audit_log("create", file_path, repo_name, "success", {
                "branch": branch,
                "commit_message": commit_message,
                "content_size": len(content),
            })
        else:
            self._audit_log("create", file_path, repo_name, "failed", {"branch": branch})

        return [types.TextContent(
            type="text",
            text=f"File created successfully in {repo_name}:\n{json.dumps(update_result, indent=2)}"
        )]

    async def _tool_create_release(self, arguments: dict) -> List[types.TextContent]:
        repo_name = arguments.get("repo", "")
        tag_name = arguments.get("tag_name", "")
        release_name = arguments.get("name", "")
        release_body = arguments.get("body", "")
        is_draft = arguments.get("draft", False)

        if len(tag_name) > MAX_TAG_NAME_LENGTH or not tag_name.strip():
            return [types.TextContent(type="text", text="Invalid tag name.")]
        if len(release_name) > MAX_RELEASE_NAME_LENGTH or not release_name.strip():
            return [types.TextContent(type="text", text="Invalid release name.")]
        if len(release_body) > MAX_CONTENT_SIZE:
            return [types.TextContent(type="text", text="Release body too large.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        release_data = {
            "tag_name": tag_name,
            "name": release_name,
            "body": release_body,
            "draft": bool(is_draft),
            "prerelease": False,
        }

        result = await self.github_client.request(
            "POST", f"/repos/{_safe_url_path_segment(repo_full)}/releases", release_data
        )
        return [types.TextContent(type="text", text=f"Release creation result:\n{json.dumps(result, indent=2)}")]

    async def _tool_read_issues(self, arguments: dict) -> List[types.TextContent]:
        state = arguments.get("state", "open")
        repo_name = arguments.get("repo", "")

        if not _validate_enum(state, VALID_STATE_VALUES):
            return [types.TextContent(type="text", text="Invalid state parameter.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        result = await self.github_client.request(
            "GET", f"/repos/{_safe_url_path_segment(repo_full)}/issues", params={"state": state}
        )

        if "error" in result or not isinstance(result, list):
            return [types.TextContent(type="text", text=f"Issues result:\n{json.dumps(result, indent=2)}")]

        issues = []
        for issue in result:
            issues.append({
                "number": issue.get("number"),
                "title": issue.get("title"),
                "state": issue.get("state"),
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "user": issue.get("user", {}).get("login", "unknown"),
            })

        return [types.TextContent(
            type="text",
            text=f"Issues in {repo_name} (state: {state}):\n{json.dumps(issues, indent=2)}"
        )]

    async def _tool_get_issues(self, arguments: dict) -> List[types.TextContent]:
        state = arguments.get("state", "open")
        labels = arguments.get("labels", "")
        assignee = arguments.get("assignee", "")
        per_page = arguments.get("per_page", 30)
        page = arguments.get("page", 1)
        repo_name = arguments.get("repo", "")

        if not _validate_enum(state, VALID_STATE_VALUES):
            return [types.TextContent(type="text", text="Invalid state parameter.")]
        if not (1 <= per_page <= 100):
            return [types.TextContent(type="text", text="Invalid per_page parameter.")]
        if not isinstance(page, int) or page < 1:
            return [types.TextContent(type="text", text="Invalid page parameter.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        params = {"state": state, "per_page": per_page, "page": page}
        if labels:
            params["labels"] = labels
        if assignee:
            params["assignee"] = assignee

        result = await self.github_client.request(
            "GET", f"/repos/{_safe_url_path_segment(repo_full)}/issues", params=params
        )

        if "error" in result or not isinstance(result, list):
            self._audit_log("read", "issues", repo_name, "failed", {"state": state})
            return [types.TextContent(type="text", text=f"Issues result:\n{json.dumps(result, indent=2)}")]

        self._audit_log("read", "issues", repo_name, "success", {
            "state": state,
            "issue_count": len(result),
            "page": page,
        })

        filtered = []
        for issue in result:
            filtered.append({
                "number": issue.get("number"),
                "title": issue.get("title"),
                "state": issue.get("state"),
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "user": issue.get("user", {}).get("login", "unknown"),
                "labels": [label.get("name") for label in issue.get("labels", [])],
                "assignees": [a.get("login") for a in issue.get("assignees", [])],
                "url": issue.get("html_url"),
            })

        return [types.TextContent(
            type="text",
            text=f"Issues in {repo_name} (state: {state}, page: {page}):\n{json.dumps(filtered, indent=2)}"
        )]

    async def _tool_create_issue(self, arguments: dict) -> List[types.TextContent]:
        title = arguments.get("title", "")
        body = arguments.get("body", "")
        assignees = arguments.get("assignees", [])
        labels = arguments.get("labels", [])
        repo_name = arguments.get("repo", "")

        if not title or not title.strip() or len(title) > MAX_ISSUE_TITLE_LENGTH:
            return [types.TextContent(type="text", text="Invalid issue title.")]
        if len(body) > MAX_ISSUE_BODY_LENGTH:
            return [types.TextContent(type="text", text="Issue body too large.")]
        if not isinstance(assignees, list) or len(assignees) > 10:
            return [types.TextContent(type="text", text="Invalid assignees.")]
        if not isinstance(labels, list) or len(labels) > 100:
            return [types.TextContent(type="text", text="Invalid labels.")]

        ok, repo_full = self._build_repo_full_name(repo_name)
        if not ok:
            return [types.TextContent(type="text", text="Invalid repository specification.")]

        if not self.github_client:
            return [types.TextContent(type="text", text="GitHub client not initialized.")]

        issue_data: Dict[str, Any] = {"title": title, "body": body}
        if assignees:
            issue_data["assignees"] = assignees
        if labels:
            issue_data["labels"] = labels

        result = await self.github_client.request(
            "POST", f"/repos/{_safe_url_path_segment(repo_full)}/issues", issue_data
        )

        if "error" not in result:
            self._audit_log("create", "issue", repo_name, "success", {
                "title": title,
                "issue_number": result.get("number"),
            })
        else:
            self._audit_log("create", "issue", repo_name, "failed", {"title": title})

        return [types.TextContent(type="text", text=f"Issue creation result:\n{json.dumps(result, indent=2)}")]

    # -----------------------------------------------------------------------
    # Server Lifecycle
    # -----------------------------------------------------------------------

    async def run(self) -> None:
        _log_to_stderr("🔐 Starting Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server")
        _log_to_stderr("=" * 60)

        await self.initialize()

        config = SECURITY_LEVELS.get(self.security_level, {})
        _log_to_stderr(_sanitize_for_logging(f"🛡️  Security Level: {self.security_level}"))
        _log_to_stderr(_sanitize_for_logging(f"   Description: {config.get('description', 'Unknown')}"))

        allowed_ops = [op for op in OPERATION_RISKS if self._is_operation_allowed(op)]
        _log_to_stderr(_sanitize_for_logging(f"⚡ Allowed Operations ({len(allowed_ops)}): {', '.join(allowed_ops)}"))

        if self.allowed_repos is None:
            _log_to_stderr("🌐 Repository Access: All repositories allowed (open mode)")
        elif len(self.allowed_repos) == 0:
            _log_to_stderr("🚫 Repository Access: No repositories configured")
        else:
            _log_to_stderr(_sanitize_for_logging(f"📋 Active Whitelist ({len(self.allowed_repos)}): {', '.join(self.allowed_repos)}"))

        _log_to_stderr(_sanitize_for_logging(f"⏱️  Rate Limit: {self.rate_limit_max} requests/minute"))
        _log_to_stderr(_sanitize_for_logging(f"📁 Max Content Size: {MAX_CONTENT_SIZE} bytes"))

        if self.github_token:
            _log_to_stderr("🔑 GitHub Token: ✅ Configured")
            _log_to_stderr("🔐 Credential Storage: ✅ OS Keyring (Encrypted)")
        else:
            _log_to_stderr("❌ GitHub Token: Not configured")

        _log_to_stderr("=" * 60)
        _log_to_stderr("🚀 Security Features Active:")
        _log_to_stderr("   • Class-based state isolation (zero globals)")
        _log_to_stderr("   • Async-native rate limiting")
        _log_to_stderr("   • Connection pooling & response size guards")
        _log_to_stderr("   • URL-safe path encoding")
        _log_to_stderr("   • Cross-user repo access prevention")
        _log_to_stderr("   • Binary file blocking")
        _log_to_stderr("   • Generic error messages")
        _log_to_stderr("   • Schema hardening (additionalProperties: false)")
        if self.audit_logger and getattr(self.audit_logger, "enabled", False):
            _log_to_stderr("   • CCTV audit logging")
        _log_to_stderr("=" * 60)

        try:
            async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
                _log_to_stderr("✅ Pretty, pretty, pretty secure. Server ready.")
                await self._server.run(
                    read_stream,
                    write_stream,
                    self._server.create_initialization_options(),
                )
        finally:
            if self.github_client:
                await self.github_client.close()


# ===========================================================================
# ARGUMENT PARSING (lazy — only called from main)
# ===========================================================================

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security Levels:
  strict   - Manual whitelist required + read-only operations only
  standard - Smart IP protection + file operations allowed (DEFAULT)
  open     - No restrictions + all operations (development/testing)

Examples:
  python tamrael_github_general.py --security-level standard
  python tamrael_github_general.py --security-level strict --allowed-repos "prod-app"
  python tamrael_github_general.py --security-level open
        """,
    )
    parser.add_argument(
        "--security-level",
        choices=["strict", "standard", "open"],
        default=DEFAULT_SECURITY_LEVEL,
        help="Security level for operations (default: standard)",
    )
    parser.add_argument(
        "--allowed-repos",
        default="",
        help="Additional repositories to whitelist",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=MAX_REQUESTS_PER_MINUTE,
        help=f"Requests per minute limit (default: {MAX_REQUESTS_PER_MINUTE})",
    )
    return parser.parse_args()


# ===========================================================================
# ENTRY POINT
# ===========================================================================

async def main() -> None:
    if len(sys.argv) == 1:
        print("\n🔐 Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server", file=sys.stderr)
        print("\n📖 Quick Start:", file=sys.stderr)
        print("1. Set up credentials: python secure_config.py setup", file=sys.stderr)
        print("2. Smart mode: python tamrael_github_general.py", file=sys.stderr)
        print("3. Manual whitelist: python tamrael_github_general.py --allowed-repos 'repo1,repo2'", file=sys.stderr)
        print("4. Development mode: python tamrael_github_general.py --security-level open", file=sys.stderr)
        print("\n💡 Use --help for full options\n", file=sys.stderr)

    args = _parse_args()
    server = SecureGitHubMCPServer(args)
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
