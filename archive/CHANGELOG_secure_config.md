# Changelog — PPPS GitHub MCP Server

---

# overkill_audit_logger.py

## v2.1.0 — 2026-05-04 — _validate_log_dir security bug fix

**Commit message:**
```
fix(audit_logger): _validate_log_dir try/except swallowed its own security raise — forbidden roots check was a no-op
```

### What Changed

#### Bug Fix (High Priority)

**`_validate_log_dir` forbidden-roots check never fired**
- The function used a single `try/except ValueError` block around both `p.relative_to(root)`
  and the subsequent `raise ValueError(...)`. `relative_to()` raises `ValueError` when the
  path is NOT a child of the root — the normal/allowed case. That exception was caught by
  the same `except ValueError: continue` that was meant to skip unrelated roots, which also
  swallowed our security raise when the path WAS under a forbidden root.
- Net effect: every path passed the check regardless. A caller could point the log directory
  at `/etc`, `/usr`, or `/` and the guard would `continue` past it silently.
- Fix: separated the two cases. The `try` block now calls `relative_to()` and immediately
  raises our own error if the path is a subpath. The `except` inspects the message string
  to distinguish our security raise (`"Log directory cannot be under"`) from `relative_to()`'s
  own `ValueError`, re-raising the former and continuing past the latter.

```python
# Before (broken): except catches both relative_to's raise AND our security raise
try:
    p.relative_to(root)
    if p != root:
        raise ValueError(f"Log directory cannot be under {root}")
except ValueError:
    continue  # silently swallows the security raise too

# After (fixed): re-raise our error, continue only on relative_to's ValueError
try:
    p.relative_to(root)
    raise ValueError(f"Log directory cannot be under system root: {root}")
except ValueError as exc:
    if "Log directory cannot be under" in str(exc):
        raise
    continue
```

### Reviewers

- Claude Sonnet 4.6 — identified bug during cross-check of Gemini v2.0 output before saving

---

## v2.0.0 — 2026-05-04 — Maximum Overdrive Rewrite (Kimi K2.6 + Gemini 2.5)

**Commit message:**
```
refactor(audit_logger): HMAC-SHA256 chain, cross-platform file locking, thread safety, JSONL storage, caller forensics, input validation, persistent HMAC key, no silent failures
```

### What Changed

This version is a full hardening rewrite of the original `overkill_audit_logger.py`.
Two rounds of LLM security review were combined: Kimi K2.6 identified 12 issues, Gemini 2.5
identified 5 issues (4 overlapping, 1 additive). All were implemented in a single pass.

---

#### Bug Fixes (Critical)

**Unreachable second `except` block in `_save_chain()`**
- Two consecutive `except Exception` blocks — Python only executes the first. The temp file
  cleanup logic in the second block was dead code. Silent failure on write errors.
- Fix: single exception handler with proper cleanup.

**No file locking — concurrent writers silently lost data**
- Atomic rename (`os.replace`) prevents half-written files, but two concurrent writers could
  both create temp files and rename simultaneously — last one wins, first is lost.
- Fix: `_FileLock` class using `fcntl.flock(LOCK_EX)` on Unix, `msvcrt.locking(LK_LOCK)` on
  Windows. Writers serialize through a `.audit.lock` file. Atomic rename + lock = no lost writes.

**No integrity verification on load — tampered chains accepted blindly**
- `_load_existing_chain()` called `json.load()` and accepted whatever it found.
  An attacker who modified the file on disk would have their corrupted chain loaded as trusted.
- Fix: `verify_chain_integrity()` called immediately after load. On failure, the chain is
  renamed to `corrupt_chain_TIMESTAMP.jsonl` for forensics and a fresh chain starts.

**Plain SHA256 instead of HMAC — hash chain was forgeable**
- `hashlib.sha256(json.dumps(entry).encode()).hexdigest()` — anyone who can read the chain
  can recalculate valid hashes and forge entries. No secret key involved.
- Fix: `hmac.new(secret_key, canonical_json, hashlib.sha256).hexdigest()`. Without the key,
  forgery is computationally infeasible.

**No input validation — raw user data written directly to audit log**
- `file_path`, `operation`, `user`, `result`, `metadata` were stored as-is. Path traversal
  strings, control characters, secrets embedded in metadata, or circular references all went
  straight into the log file.
- Fix: full sanitization pipeline — `_validate_file_path()`, `_sanitize_string()`,
  `_sanitize_metadata()` (recursive, depth-capped), operation/result enum allowlists,
  automatic redaction of keys containing `token`, `password`, `secret`, `key`, `auth`,
  `credential`, `private`.

---

#### Bug Fixes (High)

**`print()` to stdout — corrupts MCP stdio protocol**
- MCP hosts communicate over stdout. Any `print()` in the logger injects garbage into the
  protocol stream, causing the host to drop or misparse responses.
- Fix: all output routed through `_log_stderr()` which writes only to `sys.stderr` and
  sanitizes embedded paths before logging.

**Unbounded metadata — OOM or unwritable file**
- `metadata` dict was serialized with no size limit, depth limit, or type checking.
  A 100 MB metadata dict would exhaust memory or produce a file the OS refuses to write.
- Fix: 16 KiB size cap (`MAX_METADATA_SIZE_BYTES`), 5-level depth cap (`MAX_METADATA_DEPTH`),
  list length capped at 100 items, string values capped at 4 KiB.

**No retention on individual entry files — disk exhaustion**
- `_save_individual_entry()` created a new file per call with no cleanup. At 1000 calls,
  1000 files. Unbounded disk growth.
- Fix: `_cleanup_old_entries()` keeps only the 1000 most recent entry files; oldest deleted.

**Timing attack in `verify_chain_integrity()`**
- Hash and HMAC comparison used `==` — standard string comparison short-circuits on first
  mismatch, leaking timing information that could help an attacker forge partial hashes.
- Fix: `secrets.compare_digest()` for all hash and HMAC comparisons.

**Predictable temp file prefix — TOCTOU risk**
- `prefix='audit_chain_tmp_'` is guessable. On systems with world-writable `/tmp` and symlink
  races, predictable prefix is a classic TOCTOU vector.
- Fix: `.audit_tmp_` hidden file prefix, and temp files written to the log directory itself
  rather than system temp, further reducing attack surface.

---

#### New Features

**HMAC key persistence — no more deterministic fallback**
- Original fallback derived the key from PID + machine-id, both readable by any local user.
  An attacker with shell access could regenerate the exact key and forge any entry.
- Fix: if `PPPS_AUDIT_KEY` env var is not set, a `secrets.token_bytes(32)` key is generated
  once and written to `.audit_secret.key` with `chmod 600`. Subsequent restarts reuse it.
  Set `PPPS_AUDIT_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")` in
  production for full key control.

**Thread safety — `threading.Lock()` on all in-memory chain operations**
- Multi-threaded callers sharing one `OverkillAuditLogger` instance could race on
  `self.chain.append()`, producing a broken hash chain where `previous_hash` references
  an entry that was inserted out of order.
- Fix: `self._thread_lock = threading.Lock()` acquired in `log_file_access()` and
  `verify_chain_integrity()` before any chain mutation or read.

**Real Windows file locking — replaces silent no-op**
- Original `except AttributeError: pass` on the fcntl import meant Windows had zero
  inter-process locking. Concurrent writers on Windows would silently corrupt the chain.
- Fix: `msvcrt.locking(fd, LK_LOCK, 1)` in the `elif msvcrt:` branch. Raises `OSError`
  (logged as CRITICAL) rather than silently skipping.

**Caller inspection forensics**
- Log entries now include `pid`, `tid`, and `execution_context` (`file`, `line`, `function`)
  captured via `inspect.currentframe()`. Identifies exactly which module and line triggered
  each audit event — prevents rogue modules from hiding their tracks.

**JSONL append-only format — replaces full-chain JSON rewrite**
- Original wrote the entire chain as a JSON array every 5 entries. At 2000 entries, every
  write rewrote the full file. I/O cost scaled linearly with chain length.
- Fix: JSONL (one JSON object per line). `_append_to_chain()` appends a single line with
  `fsync`. Chain rotation rewrites only the remaining (non-archived) entries.

**Safe JSON serialization — `_safe_json_dumps()`**
- If metadata contained a non-serializable object (`datetime`, `bytes`, custom class),
  `json.dump()` would raise `TypeError`, crash the save, and leave an orphaned temp file.
- Fix: `_safe_json_dumps()` catches `TypeError`/`ValueError` and falls back to sanitized
  string coercion. The save always completes.

---

### Reviewers

- Kimi K2.6 — identified 12 issues, produced hardened v2.0 output
- Gemini 2.5 — identified 5 issues (4 overlapping, 1 additive: thread safety), produced
  integrated v2.0 output used as base
- Claude Sonnet 4.6 — cross-checked both review outputs against final file, identified
  `_validate_log_dir` bug (fixed in v2.1.0)

---

## v1.0.3 — Original (live on repo before this session)

Known issues fixed in v2.0.0 / v2.1.0:
- Unreachable double `except` in `_save_chain()` — cleanup dead code
- No inter-process file locking — concurrent writers lose data
- No integrity check on load — tampered chain accepted blindly
- Plain SHA256 — hash chain forgeable without secret key
- No input validation — path traversal, control chars, secrets in metadata
- `print()` to stdout — corrupts MCP stdio protocol
- Unbounded metadata — OOM possible
- No individual entry file retention — disk exhaustion
- `==` hash comparison — timing attack in verification
- Predictable temp file prefix — TOCTOU risk
- Deterministic HMAC key fallback (PID + machine-id) — forgeable by local attacker
- No thread safety — shared instance races on `self.chain`
- Windows locking was silent no-op (`pass`)
- No caller forensics (PID, TID, file/line)
- Full-chain JSON rewrite every 5 entries — O(n) I/O cost
- `_validate_log_dir` forbidden-roots check was no-op (v2.1.0)

---

# tamrael_github_general.py

## v2.0.0 — 2026-05-04 — Full Architectural Rewrite (Kimi K2.6)

**Commit message:**
```
refactor(github_general): full rewrite — class-based encapsulation, asyncio-native rate limiting, connection pooling, URL-safe encoding, binary guard, response size cap, schema hardening
```

### What Changed

This version replaces the flat-script v1.0.4 entirely with a class-based architecture
sourced from Kimi K2.6's full rewrite review. The 6 targeted compatibility fixes from
the intermediate v1.1.0 patch are all subsumed here — none needed to be applied separately
because the rewrite already had them correct.

The only modification made to Kimi's output before saving: added `MissingTokenError = RuntimeError`
fallback alias and print warning in the `except ImportError` block of the `secure_config` import.
This ensures the server starts gracefully if `secure_config` is not installed.

---

#### Architecture Changes

**Class-based encapsulation — `SecureGitHubMCPServer`**
- All server state (token, whitelist, rate limiter, audit logger, HTTP client) lives inside
  a single class instance. Zero global mutable state in the previous flat script.
- Eliminates race conditions from module-level globals and makes the server testable.

**`SecureGitHubClient` with connection pooling**
- Single persistent `httpx.AsyncClient` with `httpx.Limits(max_keepalive_connections=10, max_connections=20)`.
  Previous version created a new client per request, losing TCP connection reuse.
- 10 MiB hard cap (`MAX_RESPONSE_SIZE`) on all API response bodies enforced in `request()`.
  Prevents memory exhaustion from unexpectedly large GitHub API payloads.
- Generic error responses for 4xx/5xx — no raw GitHub error messages returned to callers.

**`AsyncRateLimiter` with `asyncio.Lock` (replaces `threading.Lock`)**
- Previous `BoundedRequestTracker` used `threading.Lock`, which blocks the event loop when
  acquired inside an `async` function. `asyncio.Lock` yields correctly under `async with`.
- Sliding-window per-client bucketing. Evicts the oldest client bucket when `max_clients`
  capacity is reached to prevent unbounded memory growth.

**Lazy `_parse_args()` — zero import-time side effects**
- Previous version called `args = parse_args()` at module scope. Claude Desktop (and any
  MCP host) imports the module directly, passing its own `sys.argv`. Module-level `parse_args()`
  would crash immediately on unknown arguments.
- Fix: `_parse_args()` is only called inside `main()`. The module is now safe to import.

---

#### Bug Fixes (carried over from v1.1.0 patch — all present in rewrite)

**`settings.github_token` called removed property**
- `secure_config.py` v1.2.0 removed `.github_token`. Rewrite calls `settings.get_github_token_value()`
  and catches `MissingTokenError` explicitly. Logs a clear warning on missing token rather than
  raising a bare `AttributeError`.
- `MissingTokenError = RuntimeError` fallback alias added so the `except` clause doesn't
  `NameError` when `secure_config` is not installed.

**`validate_file_path_enhanced` used as bool — validation never fired**
- `security_validators.py` v1.1.0 changed return type to `Tuple[bool, str]`. A non-empty tuple
  is always truthy, so `if not validate_file_path_enhanced(path)` never blocked anything.
- Fix: Both call sites unpack — `valid_path, _ = validate_file_path_enhanced(file_path)` —
  and check `if not valid_path`. (Lines 1036, 1143 in saved file.)

**datetime aware/naive comparison — 30-day private repo filter broken**
- `thirty_days_ago` was a naive datetime; GitHub's `pushed_at` parses as timezone-aware UTC.
  `TypeError` in Python 3.11+, silent wrong result in earlier versions.
- Fix: `datetime.now(tz=timezone.utc) - timedelta(days=30)`. Both sides are timezone-aware.
  (Line 466 in saved file.)

**Token preview in startup logs**
- Old flat script logged `f"{token[:8]}...{token[-4:]}"` on every start. Contradicts
  `secure_config.py` hardening that explicitly avoids token exposure.
- Fix: Startup logs `🔑 GitHub Token: ✅ Configured` with no token content. (Line 1453.)

**Dead `whitelist_info` variable**
- Variable assigned but never used. Removed entirely.

---

#### Security Improvements

**URL path segment injection — `_safe_url_path_segment()`**
- Raw user input was interpolated directly into URL paths via f-strings:
  `f"/repos/{repo}/{file_path}"`. A crafted value containing `/..` or `?` could
  redirect the request to a different endpoint or inject query parameters.
- Fix: All path segments pass through `urllib.parse.quote(segment, safe="")` before
  URL construction. Applied to repo names, file paths, and branch names throughout.

**URL query parameter injection in `get_issues`**
- User-supplied `labels` and `assignee` were concatenated directly into the query string.
  A value containing `&` or `=` could inject additional parameters into the GitHub API request.
- Fix: Parameters passed as a `dict` to `httpx`'s `params=` argument. httpx handles
  encoding natively — no manual `urlencode` needed.

**Binary file blocking — `_is_text_content()`**
- `base64.b64decode(...).decode('utf-8')` on an image or compiled binary raises
  `UnicodeDecodeError`, crashing the tool handler with an unhandled exception.
- Fix: `_is_text_content(raw)` attempts UTF-8 decode; if it fails, returns a safe
  "Binary files cannot be displayed" message rather than an exception traceback. (Line 1071.)

**Enum validation before URL insertion — `_validate_enum()`**
- `sort` and `state` parameters were passed to the GitHub API without checking against
  valid values. An unexpected value could produce confusing API errors or be used
  to probe API behavior.
- Fix: `_validate_enum(value, VALID_SORT_VALUES)` / `_validate_enum(value, VALID_STATE_VALUES)`
  checked before any API call. Invalid values return an early error response.

**Cross-user repo access prevention — `_build_repo_full_name()`**
- If a caller supplied `other-user/repo` in the `repo` argument, the server would pass
  it through to the GitHub API as-is, potentially accessing another user's private repository
  (subject to token scopes).
- Fix: If `owner/repo` format is supplied, `owner` is validated against `self.authenticated_user`.
  Mismatch logs a security warning and returns an error. (Lines 557–575.)

**Schema hardening — `additionalProperties: false` + `maxLength`**
- All MCP tool input schemas now include `"additionalProperties": false` to reject
  unexpected fields, and `maxLength` constraints on all string inputs to bound input size
  at the schema layer before any handler logic runs.

---

## v1.1.0 — 2026-05-04 — Compatibility Fixes (intermediate patch, superseded by v2.0.0)

**Commit message:**
```
fix(github_general): MissingTokenError handling, validate_file_path tuple unpack, datetime tz fix, remove token preview and dead code, urlencode query params
```

Six targeted fixes applied to v1.0.4 to restore compatibility with `secure_config.py` v1.2.0
and `security_validators.py` v1.1.0. This version was superseded in the same session by the
full v2.0.0 rewrite, which includes all of these fixes plus architectural improvements.

Fixes applied:
- `settings.get_github_token_value()` replacing removed `.github_token` property
- `MissingTokenError` added to import with `RuntimeError` fallback alias
- `validate_file_path_enhanced` tuple unpack at both call sites
- `datetime.now(tz=timezone.utc)` for timezone-aware 30-day comparison
- Token preview removed from startup logs
- Dead `whitelist_info` variable removed
- `urllib.parse.urlencode(params)` replacing raw f-string query construction in `get_issues`

---

## v1.0.4 — Original (live on repo before this session)

Known issues fixed in v1.1.0 / v2.0.0:
- `settings.github_token` property call — crashes with secure_config v1.2.0
- `validate_file_path_enhanced` bool mismatch — path validation never blocks
- datetime aware/naive comparison — 30-day private repo filter broken
- Token preview in startup logs
- Dead `whitelist_info` variable
- Raw f-string query param construction in `get_issues`
- `threading.Lock` in async context blocks event loop
- Module-level `parse_args()` crashes on import by MCP hosts
- No URL path segment encoding — injection possible
- Binary files crash handler with `UnicodeDecodeError`
- No response size cap — memory exhaustion possible
- No enum validation on `sort`/`state` before API call
- Cross-user `owner/repo` access not blocked
- No `additionalProperties: false` or `maxLength` in tool schemas

---

# secure_config.py

---

## v1.2.0 — 2026-05-04 — Kimi K2.6 Review Integration

**Commit message:**
```
fix(secure_config): PrivateAttr prevents env injection, fail-closed token retrieval, validate-before-store
```

### What Changed

#### Bug Fixes (High Priority)

**`internal_github_token` was auto-loadable from `INTERNAL_GITHUB_TOKEN` env var**
- Pydantic `BaseSettings` maps field names to env vars automatically.
  A field named `internal_github_token` looks for `INTERNAL_GITHUB_TOKEN` in the environment.
  If that env var was set (by another app, by accident, or maliciously), Pydantic would load it
  into the model during `__init__` — silently bypassing the keyring and `_load_secrets` logic.
- Fix: Changed to `_github_token: Optional[SecretStr] = PrivateAttr(default=None)`.
  `PrivateAttr` fields are completely invisible to Pydantic's env-var loader, schema generator,
  and all serialization methods. This is the correct pattern for secrets in Pydantic v2.

**`get_github_token_value()` returned `""` when no token configured (fail-open)**
- An empty string passed as a Bearer token can appear in HTTP error logs, get serialized
  into API error responses, or cause silent failures that are hard to trace.
- Fix: Raises `MissingTokenError(RuntimeError)` instead. Callers are forced to handle
  the absence of a secret explicitly. Fail-closed is always safer for credentials.

**Token stored to keyring before validation**
- Original and v1.1 both validated after storing, meaning a mistyped or expired token
  would be persisted in the OS keyring. User would have to manually run `clear` + `setup`.
- Fix: `_validate_token_with_github()` is called before `keyring.set_password()`.
  If validation fails, the token is never written. Only valid tokens reach the keyring.

#### New Features

**OAuth scope verification (`X-OAuth-Scopes` header)**
- A syntactically valid token with no scopes looks identical to a `repo`-scoped token
  in a format-only check. The GitHub API returns granted scopes in the `X-OAuth-Scopes`
  response header.
- `_validate_token_with_github()` now accepts `required_scopes: set[str]` and compares
  against the header. Missing scopes are reported as warnings in the validation message.
- Both `setup` and `test` pass `required_scopes={"repo"}`.

**Signal handlers for cache cleanup**
- `SIGTERM` and `SIGINT` now call `get_secure_settings.cache_clear()` before exit.
- Reduces the window where a decrypted token sits in process memory after shutdown.

**Token length guard**
- Input longer than 255 characters is rejected before reaching any network or keyring calls.
- Defends against accidental paste of multi-line content or unusually large inputs.

#### Improvements

**`env_prefix="PPPS_"`**
- Public settings fields (`debug`, `api_timeout`, etc.) are now namespaced.
- Configurable via `PPPS_DEBUG=true`, `PPPS_API_TIMEOUT=60`, etc.
- Prevents collisions with other applications' env vars.

**`User-Agent` header added to API calls**
- GitHub API guidelines recommend a descriptive User-Agent.
- Set to `PPPS-GitHub-MCP/1.1`.

**`_make_github_request()` helper isolates raw token in narrow stack frame**
- If `httpx` raises an unexpected exception, the token lives in a separate function's
  locals rather than in the validation function's frame.
- CPython tracebacks don't show locals by default, but this reduces exposure
  in debugger sessions or `traceback.format_exc(show_locals=True)` contexts.

**Rate limit warning in validation response**
- If `X-RateLimit-Remaining < 5`, a warning is appended to the validation message.
  Not a failure — informational only.

---

## v1.1.0 — 2026-05-04 — Security Hardening & Live Token Validation

**Commit message:**
```
fix(secure_config): harden secret handling, add live API validation, fix silent keyring failure
```

### What Changed

#### Bug Fixes

**`keyring.set_password()` was never wrapped in try/except**
- Silent failure meant users received a success message when storing failed.
- Fix: Explicit error and early return on exception.

**`clear_api_keys()` had no confirmation prompt**
- Fix: Requires `y` confirmation. Cancellable with Ctrl+C.

**`@computed_field` on `github_token` exposed secret in serialization**
- Pydantic v2 includes `@computed_field` values in `model_dump()` and `model_dump_json()`.
- Fix: Removed entirely. Replaced with explicit `get_github_token_value()` method.

#### New Features

**Live GitHub API token validation**
- New `_validate_token_with_github()` makes `GET /user` call via `httpx`.
- Called in both `setup` and `test`.

#### Improvements

- `test_configuration()` no longer prints any token preview (even masked).
- `clear_api_keys()` catches broader exceptions from keyring backend.
- `setup_api_keys()` handles Ctrl+C and non-interactive input gracefully.
- `get_secure_settings.cache_clear()` called after `setup` and `clear`.
- `debug` flag now logs which source the token came from (not the value).

---

## v1.0.0 — 2026-05-04 — Initial Release

Original implementation. Reviewed by Gemini and GPT/Perplexity.

Known issues fixed in v1.1.0:
- Pydantic V1 `class Config` syntax (ignored in V2)
- `input()` echoed token to terminal (no `getpass`)
- Env fallback only triggered on exception, not on `None` return from keyring
- `keyring.set_password()` unhandled
- Token preview in `test` command

---

## Security Classification Summary

### secure_config.py

| Finding | Severity | Version Fixed |
|---|---|---|
| `@computed_field` serializes plaintext token | High | v1.1.0 |
| `INTERNAL_GITHUB_TOKEN` env var injection via BaseSettings | High | v1.2.0 |
| `input()` echoes token to terminal | High | v1.1.0 |
| `get_github_token_value()` returns `""` on missing token (fail-open) | Medium | v1.2.0 |
| Token stored before validation (bad token persisted) | Medium | v1.2.0 |
| `keyring.set_password()` failure was silent | Medium | v1.1.0 |
| No OAuth scope verification | Medium | v1.2.0 |
| `clear_api_keys()` no confirmation | Low | v1.1.0 |
| Pydantic V1/V2 config mismatch | Low | v1.1.0 |
| Env fallback only on exception, not None | Low | v1.1.0 |
| Token preview in test command | Low | v1.1.0 |
| No User-Agent header | Low | v1.2.0 |
| No signal handler for cache cleanup | Low | v1.2.0 |
| No token length validation | Low | v1.2.0 |

### tamrael_github_general.py

| Finding | Severity | Version Fixed |
|---|---|---|
| URL path segment injection via raw f-string URL construction | High | v2.0.0 |
| `threading.Lock` in async context blocks event loop | High | v2.0.0 |
| `validate_file_path_enhanced` bool mismatch — path validation never fires | High | v1.1.0 / v2.0.0 |
| `settings.github_token` removed property crashes token retrieval | High | v1.1.0 / v2.0.0 |
| Binary file `UnicodeDecodeError` crashes tool handler | Medium | v2.0.0 |
| Cross-user `owner/repo` access not validated against authenticated user | Medium | v2.0.0 |
| No response size cap — memory exhaustion on large API payloads | Medium | v2.0.0 |
| URL query parameter injection in `get_issues` via f-string concatenation | Medium | v1.1.0 / v2.0.0 |
| Module-level `parse_args()` crashes on import by MCP hosts | Medium | v2.0.0 |
| datetime aware/naive comparison — 30-day private repo filter broken | Low | v1.1.0 / v2.0.0 |
| Token preview printed to stderr at startup | Low | v1.1.0 / v2.0.0 |
| Dead `whitelist_info` variable | Low | v1.1.0 / v2.0.0 |
| No `additionalProperties: false` or `maxLength` in tool schemas | Low | v2.0.0 |
| No enum validation on `sort`/`state` before URL insertion | Low | v2.0.0 |
| New client created per request — no connection pooling | Low | v2.0.0 |

### overkill_audit_logger.py

| Finding | Severity | Version Fixed |
|---|---|---|
| Plain SHA256 chain — no secret key, entries forgeable by anyone | Critical | v2.0.0 |
| No file locking — concurrent writers silently lose data | Critical | v2.0.0 |
| No integrity check on load — tampered chain accepted blindly | Critical | v2.0.0 |
| No input validation — path traversal, control chars, secrets written to log | Critical | v2.0.0 |
| Unreachable second `except` block — temp file cleanup dead code | Critical | v2.0.0 |
| `_validate_log_dir` try/except swallows own security raise — forbidden roots never blocked | High | v2.1.0 |
| `print()` to stdout — corrupts MCP stdio protocol | High | v2.0.0 |
| Unbounded metadata — OOM or unwritable file | High | v2.0.0 |
| No individual entry file retention — disk exhaustion | High | v2.0.0 |
| No thread safety — shared instance races on `self.chain` | High | v2.0.0 |
| Windows file locking was silent no-op (`pass`) | High | v2.0.0 |
| Deterministic HMAC key fallback (PID + machine-id) — forgeable by local attacker | Medium | v2.0.0 |
| Timing attack in `verify_chain_integrity()` — `==` comparison leaks timing | Medium | v2.0.0 |
| Full-chain JSON rewrite every 5 entries — O(n) I/O cost | Medium | v2.0.0 |
| Non-serializable metadata crashes save, orphans temp file | Medium | v2.0.0 |
| Predictable temp file prefix — TOCTOU risk | Low | v2.0.0 |
| No caller forensics (PID, TID, file/line) | Low | v2.0.0 |
