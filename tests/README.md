# PPPS Test Suite

Security-focused unit tests for the Pretty, Pretty, Pretty Secure GitHub MCP Server.

**129 tests** covering the security-critical logic — no network access, no real
GitHub token, and no OS keyring required (keyring + GitHub API are mocked).

## What's tested

| File | What it locks down |
|------|--------------------|
| `test_security_validators.py` | Path traversal, branch-name command injection, timing-safe whitelist membership, content-size DoS limits, GitHub token redaction in logs/URLs, error-message sanitization, input bounds. |
| `test_secure_config.py` | Token loads from keyring only, fail-closed `MissingTokenError`, token never appears in `model_dump()` / JSON / `repr`, env-var token injection is impossible, live-validation status-code mapping. |
| `test_server_helpers.py` | Repo-name format rules, URL-safe path encoding, enum validation, binary-file detection, the async sliding-window rate limiter, and security-level operation gating. |

## Running

```bash
pip install -r requirements-dev.txt
pytest -v
```

With coverage:

```bash
pytest --cov=security_validators --cov=secure_config --cov-report=term-missing
```

Current coverage: **90% on `security_validators.py`** (the security core).
The uncovered lines in `secure_config.py` are the interactive CLI prompts
(`setup` / `clear` / `test`), which require a live TTY by design.
