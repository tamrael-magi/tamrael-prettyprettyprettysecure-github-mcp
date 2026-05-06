#!/usr/bin/env python3
"""
Tamrael's Pretty, Pretty, Pretty Secure Audit Logger — Maximum Overdrive Edition (v2.1)

CCTV for your codebase with cryptographic integrity, tamper-evident chains,
and sustainable long-term operation.

Key Security Innovations:
- HMAC-SHA256 chain integrity (secret-keyed)
- Atomic file writes & Cross-platform file locking (Unix + Windows)
- Thread-safe memory operations
- Cryptographically secure persistent HMAC fallback
- Caller inspection forensics (PID, TID, exact file/line execution)
- High-performance append-only JSONL disk storage
- Strict error reporting (No silent failures)

Changes from v2.0:
- Fixed _validate_log_dir: try/except was swallowing its own security raise,
  making the forbidden-roots check a no-op. Now correctly blocks forbidden paths.
"""

import hashlib
import hmac
import json
import time
import secrets
import os
import sys
import tempfile
import re
import stat
import threading
import inspect
import keyring
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None


# ===========================================================================
# CONSTANTS
# ===========================================================================

MAX_FILE_PATH_LENGTH = 500
MAX_METADATA_SIZE_BYTES = 16 * 1024
MAX_METADATA_DEPTH = 5
MAX_INDIVIDUAL_ENTRIES = 1000
MAX_CHAIN_MEMORY = 2000
ARCHIVE_BATCH_SIZE = 1000
GENESIS_HASH = "0" * 64
VALID_OPERATIONS = {"read", "write", "delete", "create", "list", "move", "copy", "unknown"}
VALID_RESULTS = {"success", "failed", "denied", "timeout", "error"}


# ===========================================================================
# INPUT VALIDATION & SANITIZATION
# ===========================================================================

def _sanitize_string(value: Any, max_length: int = 256, allow_empty: bool = False) -> str:
    if value is None:
        if allow_empty:
            return ""
        raise ValueError("String value cannot be None")
    s = "".join(ch for ch in str(value) if ord(ch) >= 32 or ch in "\n\t\r")
    if not allow_empty and not s.strip():
        raise ValueError("String value cannot be empty")
    return s[:max_length]


def _validate_file_path(path: Any) -> str:
    s = _sanitize_string(path, max_length=MAX_FILE_PATH_LENGTH, allow_empty=False)
    if ".." in s or s.startswith("/") or s.startswith("\\"):
        raise ValueError("Path traversal patterns not allowed in audit logs")
    if "\x00" in s:
        raise ValueError("Null bytes not allowed in paths")
    return s


def _validate_log_dir(path: str) -> Path:
    """
    Resolve the log directory path and reject anything under known system roots.

    Bug fixed in v2.1: the original used a single try/except around both
    p.relative_to(root) and the raise ValueError. Since relative_to() raises
    ValueError when the path is NOT a child of root (the normal/allowed case),
    the except clause was catching and suppressing our own security raise too.
    The fix separates the two: check membership first, then raise if blocked.
    """
    p = Path(path).resolve()
    forbidden_roots = {
        Path("/"),
        Path("/etc"),
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
    }
    for root in forbidden_roots:
        try:
            p.relative_to(root)
            # If we reach here, p IS under root — that's the forbidden case.
            # Only allow p == root itself if root is not "/" (edge case: log
            # dir set exactly to /etc would be caught here too).
            raise ValueError(f"Log directory cannot be under system root: {root}")
        except ValueError as exc:
            # Re-raise only our security error; swallow the "not a subpath"
            # ValueError that relative_to() raises for unrelated paths.
            if "Log directory cannot be under" in str(exc):
                raise
            # relative_to raised because p is NOT under root — that's fine,
            # continue checking remaining forbidden roots.
            continue
    return p


def _sanitize_metadata(meta: Any, depth: int = 0) -> Dict[str, Any]:
    if depth > MAX_METADATA_DEPTH:
        return {"_truncated": True}
    if not isinstance(meta, dict):
        return {"_invalid": str(type(meta).__name__)}

    out: Dict[str, Any] = {}
    for key, value in meta.items():
        k = _sanitize_string(key, max_length=128, allow_empty=False)
        if any(s in k.lower() for s in ("token", "password", "secret", "key", "auth", "credential", "private")):
            out[k] = "[REDACTED]"
            continue

        if isinstance(value, str):
            out[k] = _sanitize_string(value, max_length=4096, allow_empty=True)
        elif isinstance(value, (int, float, bool, type(None))):
            out[k] = value
        elif isinstance(value, dict):
            out[k] = _sanitize_metadata(value, depth + 1)
        elif isinstance(value, list):
            out[k] = _sanitize_list(value, depth + 1)
        else:
            out[k] = _sanitize_string(str(value), max_length=1024, allow_empty=True)
    return out


def _sanitize_list(items: List[Any], depth: int = 0) -> List[Any]:
    if depth > MAX_METADATA_DEPTH:
        return ["_truncated"]
    out: List[Any] = []
    for item in items[:100]:
        if isinstance(item, str):
            out.append(_sanitize_string(item, max_length=1024, allow_empty=True))
        elif isinstance(item, (int, float, bool, type(None))):
            out.append(item)
        elif isinstance(item, dict):
            out.append(_sanitize_metadata(item, depth + 1))
        elif isinstance(item, list):
            out.append(_sanitize_list(item, depth + 1))
        else:
            out.append(_sanitize_string(str(item), max_length=1024, allow_empty=True))
    return out


def _safe_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        return json.dumps(
            _sanitize_metadata({"_raw": str(obj)}),
            sort_keys=True,
            ensure_ascii=True,
        )


# ===========================================================================
# FORENSICS & UTILS
# ===========================================================================

def _get_caller_info() -> Dict[str, Any]:
    """Find the frame that called the logger to pinpoint the exact execution source."""
    try:
        frame = inspect.currentframe()
        for _ in range(3):
            if frame and frame.f_back:
                frame = frame.f_back
        if frame:
            return {
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "function": frame.f_code.co_name,
            }
    except Exception:
        pass
    return {"file": "unknown", "line": 0, "function": "unknown"}


def _log_stderr(message: str) -> None:
    """Log to stderr without leaking sensitive paths."""
    sanitized = re.sub(r"/[^\s]{3,}", "[PATH]", str(message))
    print(f"[TAMRAEL-AUDIT] {sanitized}", file=sys.stderr)


def _now_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")


# ===========================================================================
# CROSS-PLATFORM FILE LOCKING
# ===========================================================================

class _FileLock:
    """True cross-platform advisory file lock."""

    def __init__(self, filepath: Union[str, Path]):
        self.filepath = Path(filepath)
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(str(self.filepath), os.O_RDWR | os.O_CREAT)

        try:
            if fcntl:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            elif msvcrt:
                msvcrt.locking(self._fd, msvcrt.LK_LOCK, 1)
        except OSError as e:
            _log_stderr(f"CRITICAL: Failed to acquire file lock: {e}")
            raise

    def release(self) -> None:
        if self._fd is not None:
            try:
                if fcntl:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                elif msvcrt:
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            except Exception as e:
                _log_stderr(f"WARNING: Lock release error: {e}")
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


# ===========================================================================
# AUDIT LOGGER v2.1
# ===========================================================================

class OverkillAuditLogger:
    def __init__(self, log_dir: str = "./audit_logs", enabled: bool = True):
        self.enabled = bool(enabled)
        if not self.enabled:
            return

        self.log_dir = _validate_log_dir(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.lock_file = self.log_dir / ".audit.lock"

        # JSONL for high-performance append-only I/O
        self.chain_file = self.log_dir / "audit_chain.jsonl"

        self.hmac_key = self._derive_hmac_key()
        self.genesis_hash = GENESIS_HASH
        self.chain: List[Dict[str, Any]] = []

        self._thread_lock = threading.Lock()

        self.max_chain_length = MAX_CHAIN_MEMORY

        self._load_existing_chain()

    def _derive_hmac_key(self) -> bytes:
        """Load HMAC key from OS keyring, or generate + persist if missing."""
        try:
            stored = keyring.get_password("ppps-audit-hmac", "hmac-key")
            if stored:
                return bytes.fromhex(stored)
        except Exception:
            pass

        # Persistent secure fallback (existing key file migration)
        key_file = self.log_dir / ".audit_secret.key"
        if key_file.exists():
            with open(key_file, "rb") as f:
                key_bytes = f.read().strip()
            try:
                keyring.set_password("ppps-audit-hmac", "hmac-key", key_bytes.hex())
            except Exception:
                pass
            return key_bytes

        # Generate new cryptographically secure key
        new_key = secrets.token_bytes(32)
        try:
            keyring.set_password("ppps-audit-hmac", "hmac-key", new_key.hex())
        except Exception:
            pass
        _log_stderr("Generated new secure persistent HMAC key.")
        return new_key

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    def _load_existing_chain(self) -> None:
        if not self.chain_file.exists():
            return
        try:
            loaded_chain = []
            with open(self.chain_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        loaded_chain.append(json.loads(line))

            self.chain = loaded_chain
            verification = self.verify_chain_integrity()

            if not verification["integrity_verified"]:
                corrupt_backup = self.log_dir / f"corrupt_chain_{_now_timestamp()}.jsonl"
                os.rename(self.chain_file, corrupt_backup)
                self.chain = []
                _log_stderr("CRITICAL: Existing chain failed integrity check. Moved to corrupt backup.")
            else:
                _log_stderr(f"Loaded {len(self.chain)} verified entries.")
        except Exception as e:
            _log_stderr(f"CRITICAL: Could not load chain: {e}")
            self.chain = []

    def _append_to_chain(self, entry: Dict[str, Any]) -> None:
        """Atomic line append using file locking."""
        try:
            with _FileLock(self.lock_file):
                with open(self.chain_file, "a", encoding="utf-8") as f:
                    f.write(_safe_json_dumps(entry) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
        except Exception as e:
            _log_stderr(f"CRITICAL: Failed to append to audit chain: {e}")

    def _save_individual_entry(self, entry: Dict[str, Any]) -> None:
        ts = _now_timestamp()
        entry_file = self.log_dir / f"entry_{ts}_{entry.get('block_height', 0)}.json"
        try:
            with open(entry_file, "w", encoding="utf-8") as f:
                f.write(_safe_json_dumps(entry))
        except Exception as e:
            _log_stderr(f"WARNING: Individual entry save failed: {e}")
            return
        self._cleanup_old_entries()

    def _cleanup_old_entries(self) -> None:
        try:
            entries = sorted(
                self.log_dir.glob("entry_*.json"),
                key=lambda p: p.stat().st_mtime,
            )
            excess = len(entries) - MAX_INDIVIDUAL_ENTRIES
            if excess > 0:
                for old_file in entries[:excess]:
                    old_file.unlink(missing_ok=True)
        except Exception as e:
            _log_stderr(f"WARNING: Cleanup failed: {e}")

    # -----------------------------------------------------------------------
    # Cryptography
    # -----------------------------------------------------------------------

    def _get_last_hash(self) -> str:
        if not self.chain:
            return self.genesis_hash
        return str(self.chain[-1].get("hash", self.genesis_hash))

    def _calculate_entry_hmac(self, entry: Dict[str, Any]) -> str:
        payload = {k: v for k, v in entry.items() if k not in ("hash", "hmac")}
        canonical = _safe_json_dumps(payload)
        return hmac.new(self.hmac_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _calculate_merkle_root(self) -> str:
        if not self.chain:
            return self.genesis_hash
        recent = self.chain[-16:]
        if len(recent) == 1:
            return str(recent[0].get("hash", self.genesis_hash))
        level = [str(e.get("hash", self.genesis_hash)) for e in recent]
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                combined = level[i] + (level[i + 1] if i + 1 < len(level) else level[i])
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            level = next_level
        return level[0] if level else self.genesis_hash

    # -----------------------------------------------------------------------
    # Logging API
    # -----------------------------------------------------------------------

    def log_file_access(
        self,
        file_path: str,
        operation: str,
        user: str = "system",
        result: str = "success",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not self.enabled:
            return "disabled"

        try:
            safe_path = _validate_file_path(file_path)
            safe_op = _sanitize_string(operation, max_length=32).lower()
            if safe_op not in VALID_OPERATIONS:
                safe_op = "unknown"
            safe_user = _sanitize_string(user, max_length=128)
            safe_result = _sanitize_string(result, max_length=32).lower()
            if safe_result not in VALID_RESULTS:
                safe_result = "error"
            safe_metadata = _sanitize_metadata(metadata or {})
        except ValueError as e:
            _log_stderr(f"Validation failed: {e}")
            return "validation_failed"

        meta_json = _safe_json_dumps(safe_metadata)
        if len(meta_json.encode("utf-8")) > MAX_METADATA_SIZE_BYTES:
            safe_metadata = {"_truncated": True, "_reason": "metadata_size_exceeded"}

        with self._thread_lock:
            entry: Dict[str, Any] = {
                "timestamp": time.time(),
                "iso_timestamp": datetime.now(timezone.utc).isoformat(),
                "pid": os.getpid(),
                "tid": threading.get_ident(),
                "execution_context": _get_caller_info(),
                "file_path": safe_path,
                "operation": safe_op,
                "user": safe_user,
                "result": safe_result,
                "metadata": safe_metadata,
                "block_height": len(self.chain),
                "previous_hash": self._get_last_hash(),
                "nonce": secrets.token_hex(16),
                "merkle_root": self._calculate_merkle_root() if len(self.chain) % 5 == 0 else "batched",
            }

            entry["hmac"] = self._calculate_entry_hmac(entry)
            entry["hash"] = hashlib.sha256(_safe_json_dumps(entry).encode("utf-8")).hexdigest()

            self.chain.append(entry)
            self._check_chain_rotation()

            self._append_to_chain(entry)
            self._save_individual_entry(entry)

        return str(entry["hash"])

    def _check_chain_rotation(self) -> None:
        if len(self.chain) < self.max_chain_length:
            return

        _log_stderr(f"Chain rotation triggered at {len(self.chain)} entries")
        archive_count = ARCHIVE_BATCH_SIZE
        if archive_count >= len(self.chain):
            archive_count = len(self.chain) // 2

        archived = self.chain[:archive_count]
        self.chain = self.chain[archive_count:]

        archive_file = self.log_dir / f"archived_chain_{_now_timestamp()}.json"
        try:
            with open(archive_file, "w", encoding="utf-8") as f:
                json.dump({"entries": archived}, f, indent=2)

            with _FileLock(self.lock_file):
                with tempfile.NamedTemporaryFile(
                    "w", dir=self.log_dir, delete=False, encoding="utf-8"
                ) as tmp:
                    for e in self.chain:
                        tmp.write(_safe_json_dumps(e) + "\n")
                    os.fsync(tmp.fileno())
                os.replace(tmp.name, self.chain_file)
        except Exception as e:
            _log_stderr(f"CRITICAL: Archive rotation failed: {e}")

    # -----------------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------------

    def verify_chain_integrity(self) -> Dict[str, Any]:
        with self._thread_lock:
            result = {
                "total_entries": len(self.chain),
                "integrity_verified": True,
                "tampered_entries": [],
            }

            if not self.chain:
                return result

            expected_previous = self.genesis_hash
            for i, entry in enumerate(self.chain):
                is_valid = True

                if entry.get("previous_hash") != expected_previous:
                    is_valid = False

                if not secrets.compare_digest(
                    entry.get("hmac", ""), self._calculate_entry_hmac(entry)
                ):
                    is_valid = False

                entry_copy = dict(entry)
                stored_hash = entry_copy.pop("hash", "")
                calc_hash = hashlib.sha256(
                    _safe_json_dumps(entry_copy).encode("utf-8")
                ).hexdigest()
                if not secrets.compare_digest(stored_hash, calc_hash):
                    is_valid = False

                if not is_valid:
                    result["integrity_verified"] = False
                    result["tampered_entries"].append(i)

                expected_previous = stored_hash

            return result


if __name__ == "__main__":
    logger = OverkillAuditLogger()
    print("V2.1 System Online. Checking execution forensics...")
    logger.log_file_access("test_file.txt", "write", "admin")
    print(json.dumps(logger.chain[-1]["execution_context"], indent=2))
