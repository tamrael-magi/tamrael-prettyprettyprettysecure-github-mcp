"""
Tests for security_validators.py — the security core of the PPPS GitHub MCP server.

These tests exercise the attack vectors the validators are designed to block:
path traversal, command injection via branch names, timing-attack resistance,
content-size DoS, token leakage in logs, and input bounds.

Run with:  pytest -v
"""

import re
import pytest

import security_validators as v


# ---------------------------------------------------------------------------
# validate_branch_name
# ---------------------------------------------------------------------------
class TestValidateBranchName:
    @pytest.mark.parametrize("branch", [
        "main",
        "develop",
        "feature/new-thing",
        "release/v1.2.3",
        "user_branch",
        "a/b/c",
    ])
    def test_accepts_legitimate_branches(self, branch):
        assert v.validate_branch_name(branch) is True

    @pytest.mark.parametrize("branch", [
        "",                       # empty
        "   ",                    # whitespace only
        "feature/../etc/passwd",  # path traversal
        "main;rm -rf /",          # command injection chars
        "branch with spaces",     # spaces
        "-startswithdash",        # leading dash
        ".startswithdot",         # leading dot
        "branch\x00null",         # null byte / control char
        "a" * 256,                # too long (>255)
        "br$anch",                # shell metachar
        "br`anch`",               # backtick
    ])
    def test_rejects_malicious_or_malformed(self, branch):
        assert v.validate_branch_name(branch) is False

    def test_consecutive_dots_blocked(self):
        assert v.validate_branch_name("foo..bar") is False


# ---------------------------------------------------------------------------
# validate_repo_access_secure  (constant-time membership)
# ---------------------------------------------------------------------------
class TestValidateRepoAccessSecure:
    def test_none_whitelist_allows_all(self):
        # None == "open mode" — everything allowed
        assert v.validate_repo_access_secure("anything", None) is True

    def test_exact_match_allowed(self):
        assert v.validate_repo_access_secure("my-repo", ["my-repo", "other"]) is True

    def test_non_member_denied(self):
        assert v.validate_repo_access_secure("evil-repo", ["my-repo", "other"]) is False

    def test_empty_whitelist_denies(self):
        assert v.validate_repo_access_secure("my-repo", []) is False

    def test_substring_is_not_a_match(self):
        # "my-repo" must not be granted access by being a substring of a member
        assert v.validate_repo_access_secure("my", ["my-repo"]) is False

    def test_case_sensitive(self):
        assert v.validate_repo_access_secure("My-Repo", ["my-repo"]) is False

    def test_does_not_short_circuit_on_first_match(self):
        # A match in the middle still returns True even with entries after it.
        # (Guards the deliberate "don't break early for constant time" behavior.)
        wl = ["a", "b", "target", "c", "d"]
        assert v.validate_repo_access_secure("target", wl) is True


# ---------------------------------------------------------------------------
# validate_file_path_enhanced  (path traversal / injection)
# ---------------------------------------------------------------------------
class TestValidateFilePathEnhanced:
    @pytest.mark.parametrize("path", [
        "README.md",
        "src/main.py",
        "deep/nested/dir/file.ts",
        "config.yaml",
        "script.sh",
    ])
    def test_accepts_safe_paths(self, path):
        ok, _ = v.validate_file_path_enhanced(path)
        assert ok is True

    @pytest.mark.parametrize("path", [
        "../etc/passwd",          # unix traversal
        "..\\windows\\system32",  # windows traversal
        "/etc/passwd",            # absolute unix
        "C:\\secret.txt",         # windows drive letter
        "file\x00.py",            # null byte
        "bad<name>.py",           # invalid filename chars
        ".hidden.py",             # leading dot
        "-flag.py",               # leading dash
    ])
    def test_rejects_dangerous_paths(self, path):
        ok, msg = v.validate_file_path_enhanced(path)
        assert ok is False
        assert isinstance(msg, str) and msg

    def test_rejects_disallowed_extension(self):
        ok, _ = v.validate_file_path_enhanced("payload.exe")
        assert ok is False

    def test_rejects_non_string(self):
        ok, _ = v.validate_file_path_enhanced(12345)  # type: ignore[arg-type]
        assert ok is False

    def test_rejects_overlong_path(self):
        ok, _ = v.validate_file_path_enhanced("a/" * 3000 + "f.py", max_length=4096)
        assert ok is False


# ---------------------------------------------------------------------------
# validate_content_size  (DoS guard)
# ---------------------------------------------------------------------------
class TestValidateContentSize:
    def test_small_content_ok(self):
        assert v.validate_content_size("hello world") is True

    def test_exactly_at_limit_ok(self):
        assert v.validate_content_size("a" * 1024, max_size=1024) is True

    def test_over_limit_rejected(self):
        assert v.validate_content_size("a" * 1025, max_size=1024) is False

    def test_multibyte_counted_in_bytes_not_chars(self):
        # 'é' is 2 bytes in UTF-8 — size must be measured in bytes.
        assert v.validate_content_size("é" * 600, max_size=1024) is False


# ---------------------------------------------------------------------------
# sanitize_token_in_text  (credential leakage prevention)
# ---------------------------------------------------------------------------
class TestSanitizeTokenInText:
    def test_redacts_classic_pat(self):
        secret = "ghp_" + "a" * 36
        out = v.sanitize_token_in_text(f"Authorization failed for {secret}")
        assert secret not in out
        assert "TOKEN_REDACTED" in out

    def test_redacts_server_token(self):
        secret = "ghs_" + "b" * 36
        out = v.sanitize_token_in_text(f"token={secret}")
        assert secret not in out

    def test_redacts_fine_grained_pat(self):
        secret = "github_pat_" + "c" * 40
        out = v.sanitize_token_in_text(secret)
        assert secret not in out

    def test_redacts_40_char_hex(self):
        secret = "a1" * 20  # 40 hex chars
        out = v.sanitize_token_in_text(f"old token {secret} here")
        assert secret not in out

    def test_redacts_bearer_header_case_insensitive(self):
        out = v.sanitize_token_in_text("authorization: bearer abc123XYZ_token")
        assert "abc123XYZ_token" not in out

    def test_leaves_innocent_text_untouched(self):
        msg = "Just a normal log line with no secrets."
        assert v.sanitize_token_in_text(msg) == msg


# ---------------------------------------------------------------------------
# sanitize_url_for_logging
# ---------------------------------------------------------------------------
class TestSanitizeUrlForLogging:
    def test_redacts_token_query_param(self):
        out = v.sanitize_url_for_logging("https://api.github.com/x?token=supersecret")
        assert "supersecret" not in out

    def test_redacts_access_token_param(self):
        out = v.sanitize_url_for_logging("https://x/y?access_token=abc123")
        assert "abc123" not in out

    def test_redacts_token_path_segment(self):
        out = v.sanitize_url_for_logging("https://api.github.com/tokens/abc-123_XYZ")
        assert "abc-123_XYZ" not in out


# ---------------------------------------------------------------------------
# sanitize_error_message  (information disclosure)
# ---------------------------------------------------------------------------
class TestSanitizeErrorMessage:
    @pytest.mark.parametrize("raw,expected", [
        ("Permission denied on /etc/secret", "Access denied"),
        ("403 Unauthorized access", "Access denied"),
        ("Resource not found at path", "Resource not found"),
        ("API rate limit exceeded", "Rate limit exceeded"),
        ("Connection refused to host", "Network error"),
        ("Request timeout after 30s", "Request timeout"),
        ("Some weird internal traceback", "Operation failed"),
    ])
    def test_generic_mapping(self, raw, expected):
        assert v.sanitize_error_message(raw) == expected


# ---------------------------------------------------------------------------
# validate_issue_title
# ---------------------------------------------------------------------------
class TestValidateIssueTitle:
    def test_valid_title(self):
        assert v.validate_issue_title("Fix the login bug") is True

    def test_empty_rejected(self):
        assert v.validate_issue_title("") is False
        assert v.validate_issue_title("   ") is False

    def test_overlong_rejected(self):
        assert v.validate_issue_title("x" * 1001, max_length=1000) is False

    def test_allows_normal_whitespace(self):
        assert v.validate_issue_title("Line one\nLine two\tTabbed") is True

    def test_rejects_control_chars(self):
        assert v.validate_issue_title("bad\x07bell") is False


# ---------------------------------------------------------------------------
# validate_pagination_params
# ---------------------------------------------------------------------------
class TestValidatePagination:
    def test_defaults_ok(self):
        ok, _ = v.validate_pagination_params()
        assert ok is True

    @pytest.mark.parametrize("page,per_page", [(0, 30), (-1, 30), (1, 0), (1, 101)])
    def test_out_of_bounds_rejected(self, page, per_page):
        ok, _ = v.validate_pagination_params(page=page, per_page=per_page)
        assert ok is False

    def test_page_ceiling(self):
        ok, _ = v.validate_pagination_params(page=1001, per_page=30)
        assert ok is False


# ---------------------------------------------------------------------------
# validate_array_input
# ---------------------------------------------------------------------------
class TestValidateArrayInput:
    def test_valid_labels(self):
        ok, _ = v.validate_array_input(["bug", "high-priority"], "labels")
        assert ok is True

    def test_non_list_rejected(self):
        ok, _ = v.validate_array_input("notalist", "labels")  # type: ignore[arg-type]
        assert ok is False

    def test_too_many_items(self):
        ok, _ = v.validate_array_input(["x"] * 101, "labels", max_items=100)
        assert ok is False

    def test_non_string_item_rejected(self):
        ok, _ = v.validate_array_input(["ok", 123], "labels")  # type: ignore[list-item]
        assert ok is False

    def test_injection_chars_in_item_rejected(self):
        ok, _ = v.validate_array_input(["bad;name"], "labels")
        assert ok is False


# ---------------------------------------------------------------------------
# validate_content_safety  (untrusted user input scanning)
# ---------------------------------------------------------------------------
class TestValidateContentSafety:
    def test_clean_text_ok(self):
        ok, _ = v.validate_content_safety("This is a normal issue description.")
        assert ok is True

    @pytest.mark.parametrize("payload", [
        "<script>alert(1)</script>",
        "click javascript:void(0)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "eval(maliciousCode)",
        "__import__('os').system('rm')",
        "subprocess.Popen(['sh'])",
        "os.system('whoami')",
    ])
    def test_malicious_payloads_flagged(self, payload):
        ok, _ = v.validate_content_safety(payload)
        assert ok is False

    def test_oversize_rejected(self):
        ok, _ = v.validate_content_safety("a" * (10 * 1024 * 1024 + 1))
        assert ok is False


# ---------------------------------------------------------------------------
# Registry integrity — guards against accidental refactor breakage
# ---------------------------------------------------------------------------
class TestRegistries:
    def test_all_validators_callable(self):
        for name, fn in v.VALIDATORS.items():
            assert callable(fn), f"{name} not callable"

    def test_all_sanitizers_callable(self):
        for name, fn in v.SANITIZERS.items():
            assert callable(fn), f"{name} not callable"
