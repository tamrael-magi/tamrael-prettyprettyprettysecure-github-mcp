"""Pytest bootstrap: ensure the repo root is importable.

The source modules (security_validators.py, secure_config.py,
tamrael_github_general.py) live at the repository root, while the tests
live in tests/. When pytest collects files under tests/, the repo root
is not guaranteed to be on sys.path (notably in CI, where pytest is
invoked from the repo root but rootdir insertion differs across versions).

`pythonpath = .` in pytest.ini handles this for pytest >= 7, and this
conftest provides a belt-and-suspenders fallback for any environment.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
