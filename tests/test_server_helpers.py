"""
Tests for server-level helpers in tamrael_github_general.py.

Covers the pure / easily-isolated logic:
  - repository name format validation
  - URL-safe path segment encoding (injection prevention)
  - enum validation
  - binary vs text content detection
  - the async sliding-window rate limiter

Network and MCP stdio are never touched here.
"""

import asyncio
import pytest

import tamrael_github_general as g


# ---------------------------------------------------------------------------
# _validate_repo_name_format
# ---------------------------------------------------------------------------
class TestValidateRepoNameFormat:
    @pytest.mark.parametrize("name", [
        "my-repo",
        "owner/my-repo",
        "repo_with_underscore",
        "repo.with.dots",
        "a/b",
    ])
    def test_accepts_valid(self, name):
        assert g._validate_repo_name_format(name) is True

    @pytest.mark.parametrize("name", [
        "",                       # empty
        "a" * 101,                # too long (>100)
        "../etc",                 # traversal
        "owner/../repo",          # traversal in middle
        "repo with space",        # space
        "owner/repo/extra",       # too many segments
        "bad\x00name",            # control char
        "repo;rm",                # shell char
    ])
    def test_rejects_invalid(self, name):
        assert g._validate_repo_name_format(name) is False


# ---------------------------------------------------------------------------
# _safe_url_path_segment  (encodes injection chars, preserves slash)
# ---------------------------------------------------------------------------
class TestSafeUrlPathSegment:
    def test_preserves_owner_repo_slash(self):
        assert g._safe_url_path_segment("owner/repo") == "owner/repo"

    def test_encodes_spaces(self):
        assert "%20" in g._safe_url_path_segment("my repo")

    def test_encodes_query_injection(self):
        out = g._safe_url_path_segment("repo?ref=evil")
        assert "?" not in out  # the '?' must be percent-encoded

    def test_encodes_hash(self):
        out = g._safe_url_path_segment("repo#frag")
        assert "#" not in out


# ---------------------------------------------------------------------------
# _validate_enum
# ---------------------------------------------------------------------------
class TestValidateEnum:
    def test_member_allowed(self):
        assert g._validate_enum("updated", g.VALID_SORT_VALUES) is True

    def test_non_member_rejected(self):
        assert g._validate_enum("evil", g.VALID_SORT_VALUES) is False

    def test_state_enum(self):
        assert g._validate_enum("open", g.VALID_STATE_VALUES) is True
        assert g._validate_enum("sideways", g.VALID_STATE_VALUES) is False


# ---------------------------------------------------------------------------
# _is_text_content  (binary file blocking heuristic)
# ---------------------------------------------------------------------------
class TestIsTextContent:
    def test_utf8_text_is_text(self):
        assert g._is_text_content("hello world".encode("utf-8")) is True

    def test_binary_bytes_are_not_text(self):
        # Invalid UTF-8 byte sequence (lone continuation bytes)
        assert g._is_text_content(b"\xff\xfe\x00\x01\x80\x81") is False


# ---------------------------------------------------------------------------
# AsyncRateLimiter  (sliding-window, per-client)
# ---------------------------------------------------------------------------
class TestAsyncRateLimiter:
    def test_allows_up_to_limit(self):
        async def run():
            rl = g.AsyncRateLimiter(max_requests=3, window_seconds=60)
            results = [await rl.is_allowed("client-a") for _ in range(3)]
            return results
        assert all(asyncio.run(run()))

    def test_blocks_over_limit(self):
        async def run():
            rl = g.AsyncRateLimiter(max_requests=2, window_seconds=60)
            await rl.is_allowed("client-a")
            await rl.is_allowed("client-a")
            return await rl.is_allowed("client-a")  # 3rd should be blocked
        assert asyncio.run(run()) is False

    def test_separate_clients_have_separate_buckets(self):
        async def run():
            rl = g.AsyncRateLimiter(max_requests=1, window_seconds=60)
            a = await rl.is_allowed("client-a")
            b = await rl.is_allowed("client-b")  # different client, fresh bucket
            return a, b
        a, b = asyncio.run(run())
        assert a is True and b is True

    def test_window_expiry_refills(self):
        async def run():
            # window of 0 seconds => stale entries cleared immediately
            rl = g.AsyncRateLimiter(max_requests=1, window_seconds=0)
            await rl.is_allowed("client-a")
            # tiny sleep so 'now - window' moves past the prior timestamp
            await asyncio.sleep(0.01)
            return await rl.is_allowed("client-a")
        assert asyncio.run(run()) is True


# ---------------------------------------------------------------------------
# Operation risk / security-level gating logic
# ---------------------------------------------------------------------------
class TestSecurityLevelGating:
    def test_strict_only_allows_low_risk(self):
        # strict allows only "low" risk ops
        low_ops = [op for op, r in g.OPERATION_RISKS.items() if r == "low"]
        high_ops = [op for op, r in g.OPERATION_RISKS.items() if r == "high"]
        strict_risks = g.SECURITY_LEVELS["strict"]["risks"]
        assert all(g.OPERATION_RISKS[o] in strict_risks for o in low_ops)
        assert all(g.OPERATION_RISKS[o] not in strict_risks for o in high_ops)

    def test_open_allows_everything(self):
        open_risks = g.SECURITY_LEVELS["open"]["risks"]
        assert all(r in open_risks for r in g.OPERATION_RISKS.values())

    def test_unknown_operation_defaults_to_high(self):
        # OPERATION_RISKS.get(unknown, "high") — strict must NOT allow it
        assert g.OPERATION_RISKS.get("totally_unknown_op", "high") == "high"
        assert "high" not in g.SECURITY_LEVELS["strict"]["risks"]
