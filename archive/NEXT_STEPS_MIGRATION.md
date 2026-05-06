# PPPS GitHub MCP Server — Chat Migration & Next Steps
# Date: 2026-05-04

---

## Current State Summary

### Files in MCP_Pretty (hardened versions, NOT yet deployed to repo)

| File | Version | Status |
|---|---|---|
| secure_config.py | v1.2.0 | Hardened — NOT on repo yet |
| security_validators.py | v1.1.0 | Hardened — NOT on repo yet |
| tamrael_github_general.py | — | NOT saved to folder yet, needs compatibility fixes |
| CHANGELOG_secure_config.md | v1.2.0 | Local only |

### Live Repo Files (tamrael-magi/tamrael-prettyprettyprettysecure-github-mcp)

| File | Version | Known Issues |
|---|---|---|
| secure_config.py | v1.0.3 | Old — internal_github_token field, .github_token property |
| security_validators.py | v1.0.4 | Old — duplicate function, regex flag bug |
| tamrael_github_general.py | v1.0.4 | Calls .github_token (breaks with new secure_config), validate_file_path_enhanced returns bool mismatch |
| overkill_audit_logger.py | v1.0.3 | Not reviewed yet |

---

## What Was Hardened This Session

### secure_config.py — v1.0.3 -> v1.2.0

Rounds of review: Perplexity/GPT, Gemini (original), Claude Sonnet 4.6, Kimi K2.6

Key changes:
- v1.1.0: Removed @computed_field (serialization leak), added getpass, fixed keyring.set_password() error handling, added live API validation (GET /user), added clear confirmation prompt, cache invalidation on setup/clear
- v1.2.0: PrivateAttr replaces internal_github_token field (prevents INTERNAL_GITHUB_TOKEN env injection via BaseSettings), MissingTokenError fail-closed (was returning "" on missing token), validate-before-store (don't persist broken tokens), OAuth scope checking via X-OAuth-Scopes header, signal handlers (SIGTERM/SIGINT cache clear), token length guard (255 chars), env_prefix="PPPS_", User-Agent header, _make_github_request() narrow scope isolation

### security_validators.py — v1.0.4 -> v1.1.0

Key changes:
- Fixed duplicate validate_file_path_enhanced (dead code, type mismatch — was bool, now Tuple[bool, str])
- Fixed re.sub flag bug on Bearer and Authorization patterns (re.IGNORECASE was being passed as count=2)
- Added github_pat_ token pattern to sanitize_token_in_text
- Added validate_content_safety scope warning (NOT for source code, only user input)
- Added all missing validators to VALIDATORS registry
- Added Tuple return types throughout

---

## Compatibility Break — MUST FIX Before Deploying

tamrael_github_general.py is incompatible with both hardened modules:

### Break 1 — secure_config.py API change
Old call (line 311 in downloaded file):
    return settings.github_token

New API (v1.2.0 removed .github_token property):
    return settings.get_github_token_value()

Also need to handle MissingTokenError in get_github_token().

### Break 2 — security_validators.py return type change
Old calls (lines 1010, 1135):
    if not validate_file_path_enhanced(file_path):

validate_file_path_enhanced now returns Tuple[bool, str] not bool.
Non-empty tuple is always truthy — path validation currently never blocks anything.

Fix pattern:
    valid, reason = validate_file_path_enhanced(file_path)
    if not valid:
        return [types.TextContent(type="text", text=f"SECURITY: {reason}")]

---

## Other Issues Found in tamrael_github_general.py (Standalone Review)

| Line | Issue | Severity |
|---|---|---|
| 311 | settings.github_token — old property, breaks with v1.2.0 | High |
| 1010, 1135 | validate_file_path_enhanced bool mismatch — validation never blocks | High |
| 380 | pushed_at > thirty_days_ago — compares aware datetime to naive ISO string | Medium |
| 1489 | token_preview printed at startup — contradicts secure_config hardening | Low |
| 935 | whitelist_info assigned but never used — dead code | Low |

---

## Next Steps (In Order)

### Step 1 — Fix tamrael_github_general.py
- Update get_github_token() to call settings.get_github_token_value() and catch MissingTokenError
- Update validate_file_path_enhanced calls to unpack Tuple[bool, str]
- Fix datetime comparison bug (line 380) — compare datetime objects not strings
- Remove token_preview from startup logs (line 1489)
- Remove dead whitelist_info variable (line 935)
- Save to MCP_Pretty folder

### Step 2 — Review overkill_audit_logger.py
- Not reviewed at all yet
- Changelog says atomic file operations were added (tempfile + os.replace)
- Verify those are actually in the current repo version
- Check for any issues

### Step 3 — Deploy to repo
All three files ready:
- secure_config.py (v1.2.0)
- security_validators.py (v1.1.0)
- tamrael_github_general.py (fixed, compatible)

### Step 4 — Update repo CHANGELOG.md
- Add v1.1.0 and v1.2.0 entries for secure_config.py
- Add v1.1.0 entry for security_validators.py
- Add version entry for tamrael_github_general.py fixes

---

## File Locations

Local hardened files:
    C:\Users\Kevin\Desktop\Senku_v3\Senku_3\MCP_Pretty\

Downloaded originals:
    C:\Users\Kevin\Downloads\tamrael_github_general.py

Repo:
    github.com/tamrael-magi/tamrael-prettyprettyprettysecure-github-mcp

---

## Key Decisions Made This Session

- validate_file_path_enhanced returns Tuple[bool, str] not bool — callers must unpack
- get_github_token_value() is the new API — .github_token property removed
- MissingTokenError is fail-closed — callers must handle explicitly
- validate-before-store in setup — broken tokens never reach keyring
- env_prefix="PPPS_" namespaces public fields to prevent env var collisions
- PrivateAttr is the correct Pydantic v2 pattern for secrets in BaseSettings
- validate_content_safety is for USER INPUT ONLY — not source code files

---

## Reviewers This Session

- Perplexity/GPT — caught @computed_field serialization leak, env_file=None doesn't block env vars
- Gemini — caught V1/V2 mismatch, input() echo, fallback logic bug (original code)
- Claude Sonnet 4.6 (this session) — caught keyring.set_password() silent failure, clear confirmation, live API validation, token preview leak
- Kimi K2.6 — caught INTERNAL_GITHUB_TOKEN env injection via BaseSettings, fail-open "" return, validate-before-store, scope checking
