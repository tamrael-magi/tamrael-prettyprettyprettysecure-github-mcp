#!/usr/bin/env python3
"""
Security Validators Module - Tamrael GitHub MCP Server

Contains all security validation functions to prevent various attack vectors:
- Timing attacks (constant-time comparisons)
- Command injection (branch name validation)
- Path traversal (enhanced file path validation)
- Input sanitization (content validation)

Separated from main server for better modularity and testing.

Part of Tamrael's PPPS (Pretty, Pretty, Pretty, Secure) GitHub MCP Server
Authors: Kevin Francisco (Tamrael) with Claude Sonnet 4.6 (LLM Collaborator)
"""

import re
import secrets
from pathlib import Path
from typing import List, Optional, Tuple


def validate_branch_name(branch: str) -> bool:
    """Validate branch name to prevent command injection attacks.

    Only allows safe characters to prevent injection through branch parameters
    in GitHub API calls.

    Args:
        branch: Branch name to validate

    Returns:
        True if branch name is safe, False otherwise

    Security Notes:
        - Prevents command injection via branch parameters
        - Blocks path traversal attempts in branch names
        - Limits length to prevent DoS attacks
    """
    if not branch or not branch.strip():
        return False

    if len(branch) > 255:
        return False

    pattern = re.compile(r'^[a-zA-Z0-9/_.-]+$')
    if not pattern.match(branch):
        return False

    if '..' in branch:
        return False

    if branch.startswith('.') or branch.startswith('-'):
        return False

    if any(ord(c) < 32 for c in branch):
        return False

    return True


def validate_repo_access_secure(repo_name: str, allowed_repos: Optional[List[str]]) -> bool:
    """Check repository access with timing-attack resistance.

    Uses constant-time comparison to prevent timing attacks that could leak
    repository names in the whitelist.

    Security Note: secrets.compare_digest short-circuits on length mismatch
    before performing the constant-time comparison. For strict timing safety,
    inputs are encoded to bytes before comparison, but callers should be aware
    that length differences are still observable at the network level.
    """
    if allowed_repos is None:
        return True

    allowed = False
    repo_bytes = repo_name.encode('utf-8')
    for allowed_repo in allowed_repos:
        if secrets.compare_digest(repo_bytes, allowed_repo.encode('utf-8')):
            allowed = True
            # DON'T BREAK — continue checking all repos for constant time

    return allowed


def validate_file_path_enhanced(file_path: str, max_length: int = 4096) -> Tuple[bool, str]:
    """Enhanced file path validation to prevent path traversal attacks.

    Validates file paths with comprehensive security checks to prevent
    various path traversal and injection attempts.

    Args:
        file_path: File path to validate
        max_length: Maximum allowed path length (default 4096)

    Returns:
        Tuple of (is_valid: bool, message: str)

    Security Notes:
        - Prevents path traversal attacks (../, ..\\)
        - Blocks absolute paths (Unix and Windows)
        - Prevents Windows drive letter access
        - Checks for null bytes and control characters
        - Limits path length to prevent DoS
        - Restricts to known-safe file extensions
    """
    if not isinstance(file_path, str):
        return False, "File path must be a string"

    if not file_path or len(file_path) > max_length:
        return False, "Invalid file path length"

    security_patterns = [
        (r'\.\.[\\/]', "Path traversal detected"),
        (r'^[\\/]', "Absolute paths not allowed"),
        (r'^[a-zA-Z]:', "Windows drive letters not allowed"),
        (r'\x00', "Null bytes not allowed"),
        (r'[<>:"|?*]', "Invalid filename characters"),
    ]

    for pattern, message in security_patterns:
        if re.search(pattern, file_path):
            return False, f"File path contains security risk: {message}"

    if any(ord(c) < 32 for c in file_path):
        return False, "File path contains control characters"

    if file_path.startswith('.') or file_path.startswith('-'):
        return False, "File path cannot start with '.' or '-'"

    allowed_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.md', '.txt', '.json', '.yaml', '.yml',
        '.xml', '.csv', '.sql', '.html', '.css', '.scss', '.less', '.vue', '.go',
        '.rs', '.cpp', '.c', '.h', '.hpp', '.java', '.kt', '.swift', '.rb', '.php',
        '.sh', '.bash', '.zsh', '.ps1', '.dockerfile', '.gitignore', '.env',
    }

    file_ext = Path(file_path).suffix.lower()
    if file_ext and file_ext not in allowed_extensions:
        return False, f"File type not allowed: {file_ext}"

    return True, "Valid file path"


def validate_content_size(content: str, max_size: int = 1024 * 1024) -> bool:
    """Validate content size to prevent DoS attacks.

    Args:
        content: Content to validate
        max_size: Maximum allowed size in bytes (default 1MB)

    Returns:
        True if content size is acceptable, False otherwise
    """
    return len(content.encode('utf-8')) <= max_size


def sanitize_error_message(error: str) -> str:
    """Sanitize error messages to prevent information disclosure.

    Args:
        error: Original error message

    Returns:
        Sanitized error message safe for logging/display

    Security Notes:
        - Prevents sensitive information leakage
        - Standardizes error responses
        - Reduces attack surface for information gathering
    """
    error_lower = error.lower()

    if any(word in error_lower for word in ['permission', 'unauthorized', 'forbidden']):
        return "Access denied"
    if 'not found' in error_lower:
        return "Resource not found"
    if 'rate limit' in error_lower:
        return "Rate limit exceeded"
    if any(word in error_lower for word in ['network', 'connection']):
        return "Network error"
    if 'timeout' in error_lower:
        return "Request timeout"

    return "Operation failed"


def sanitize_url_for_logging(url: str) -> str:
    """Remove sensitive information from URLs for safe logging.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL safe for logging

    Security Notes:
        - Removes tokens and authentication info
        - Prevents credential leakage in logs
        - Maintains useful debugging information
    """
    sanitized = re.sub(r'[?&]token=[^&]*', '?token=***', url)
    sanitized = re.sub(r'[?&]access_token=[^&]*', '?access_token=***', sanitized)
    sanitized = re.sub(r'/tokens/[a-zA-Z0-9_-]+', '/tokens/***', sanitized)
    return sanitized


def validate_issue_title(title: str, max_length: int = 1000) -> bool:
    """Validate issue title to prevent injection attacks.

    Args:
        title: Issue title to validate
        max_length: Maximum allowed title length

    Returns:
        True if title is safe, False otherwise
    """
    if not title or not title.strip():
        return False

    if len(title) > max_length:
        return False

    if any(ord(c) < 32 and c not in ['\t', '\n', '\r'] for c in title):
        return False

    return True


def sanitize_token_in_text(text: str) -> str:
    """Remove GitHub tokens from any text content.

    Args:
        text: Text that may contain GitHub tokens

    Returns:
        Text with tokens replaced by placeholders

    Security Notes:
        - Removes classic PATs (ghp_), server tokens (ghs_), fine-grained PATs (github_pat_)
        - Removes classic 40-character hex tokens
        - Removes Bearer token headers (case-insensitive, all occurrences)
        - Removes Authorization header tokens
    """
    # GitHub classic PATs (ghp_) and server-to-server tokens (ghs_)
    text = re.sub(r'gh[ps]_[a-zA-Z0-9]{36}', 'TOKEN_REDACTED', text)

    # GitHub fine-grained PATs (github_pat_...)
    text = re.sub(r'github_pat_[a-zA-Z0-9_]{36,}', 'TOKEN_REDACTED', text)

    # Classic GitHub tokens (40 hex characters)
    text = re.sub(r'\b[a-fA-F0-9]{40}\b', 'TOKEN_REDACTED', text)

    # Bearer tokens in authorization headers — flags= keyword required
    # (4th positional arg to re.sub is count, not flags)
    text = re.sub(r'Bearer\s+[a-zA-Z0-9_-]+', 'Bearer TOKEN_REDACTED', text, flags=re.IGNORECASE)

    # Authorization header tokens
    text = re.sub(r'Authorization:\s*[a-zA-Z0-9_-]+', 'Authorization: TOKEN_REDACTED', text, flags=re.IGNORECASE)

    return text


def validate_pagination_params(page: int = 1, per_page: int = 30) -> Tuple[bool, str]:
    """Validate pagination parameters with bounds checking.

    Args:
        page: Page number (must be positive integer, max 1000)
        per_page: Items per page (must be 1-100)

    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if not isinstance(page, int) or page < 1:
        return False, "Invalid page number - must be positive integer"
    if not isinstance(per_page, int) or per_page < 1 or per_page > 100:
        return False, "Invalid per_page value - must be 1-100"
    if page > 1000:
        return False, "Page number too high - maximum 1000 pages"
    return True, "Valid pagination parameters"


def validate_array_input(data: list, field_name: str, max_items: int = 100) -> Tuple[bool, str]:
    """Validate array inputs like assignees and labels with bounds checking.

    Args:
        data: List to validate
        field_name: Name of the field (used in error messages)
        max_items: Maximum number of items allowed

    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if not isinstance(data, list):
        return False, f"Invalid {field_name} - must be array"
    if len(data) > max_items:
        return False, f"Too many {field_name} items - maximum {max_items}"

    for item in data:
        if not isinstance(item, str):
            return False, f"Invalid {field_name} item - must be string"
        if len(item) > 200:
            return False, f"Invalid {field_name} item - too long (max 200 chars)"
        if not re.match(r'^[a-zA-Z0-9_.-]+$', item):
            return False, f"Invalid {field_name} item - contains invalid characters"

    return True, f"Valid {field_name} array"


def validate_content_safety(content: str) -> Tuple[bool, str]:
    """Validate user-submitted form input for malicious payloads.

    IMPORTANT: This validator is intended for untrusted user input such as
    issue bodies, comments, or form fields — NOT for source code file content.
    Applying it to repository files will produce false positives on legitimate
    Python, shell, or web code.

    Args:
        content: User-submitted string to validate

    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if not isinstance(content, str):
        return False, "Content must be string"

    # Check content size (prevent DoS) — 10MB limit
    if len(content) > 10 * 1024 * 1024:
        return False, "Content too large - maximum 10MB"

    suspicious_patterns = [
        (r'<script[^>]*>.*?</script>', "Script tags"),
        (r'javascript:', "JavaScript URLs"),
        (r'data:.*base64', "Base64 data URLs"),
        (r'eval\s*\(', "Eval functions"),
        (r'exec\s*\(', "Exec functions"),
        (r'__import__\s*\(', "Python imports"),
        (r'subprocess\.', "Subprocess calls"),
        (r'os\.system\s*\(', "OS system calls"),
    ]

    for pattern, label in suspicious_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return False, f"Content contains potentially malicious code: {label}"

    return True, "Content validation passed"


def validate_branch_name_enhanced(branch_name: str) -> Tuple[bool, str]:
    """Enhanced branch name validation with comprehensive Git rules.

    Covers all Git branch naming restrictions beyond the basic validator.

    Args:
        branch_name: Branch name to validate

    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if not isinstance(branch_name, str):
        return False, "Branch name must be string"

    if not branch_name or len(branch_name) > 250:
        return False, "Invalid branch name length"

    invalid_patterns = [
        (r'^\.', "Cannot start with dot"),
        (r'\.$', "Cannot end with dot"),
        (r'\.\.', "Cannot contain consecutive dots"),
        (r'[\x00-\x1f\x7f]', "No control characters"),
        (r' $', "Cannot end with space"),
        (r'^-', "Cannot start with dash"),
        (r'[~^:?*\[\]\\]', "Invalid Git characters"),
        (r'@{', "No @{ sequence"),
        (r'//', "No consecutive slashes"),
    ]

    for pattern, message in invalid_patterns:
        if re.search(pattern, branch_name):
            return False, f"Invalid branch name format: {message}"

    return True, "Valid branch name"


# Validation registry — for easy testing, introspection, and maintenance
VALIDATORS = {
    'branch_name': validate_branch_name,
    'branch_name_enhanced': validate_branch_name_enhanced,
    'repo_access': validate_repo_access_secure,
    'file_path': validate_file_path_enhanced,
    'content_size': validate_content_size,
    'content_safety': validate_content_safety,
    'issue_title': validate_issue_title,
    'pagination': validate_pagination_params,
    'array_input': validate_array_input,
}

# Sanitizer registry
SANITIZERS = {
    'error_message': sanitize_error_message,
    'url_logging': sanitize_url_for_logging,
    'token_text': sanitize_token_in_text,
}
