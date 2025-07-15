#!/usr/bin/env python3
"""
Security Validators Module - Tamrael GitHub MCP Server

Contains all security validation functions to prevent various attack vectors:
- Timing attacks (constant-time comparisons)
- Command injection (branch name validation)  
- Path traversal (enhanced file path validation)
- Input sanitization (content validation)

Separated from main server for better modularity and testing.
"""

import re
import secrets
from typing import List, Optional


def validate_branch_name(branch: str) -> bool:
    """Validate branch name to prevent command injection attacks
    
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
    
    # Check length - reasonable limit for branch names
    if len(branch) > 255:
        return False
    
    # Only allow alphanumeric, hyphens, underscores, forward slashes, and dots
    # but prevent dangerous patterns
    pattern = re.compile(r'^[a-zA-Z0-9/_.-]+$')
    if not pattern.match(branch):
        return False
    
    # Prevent path traversal in branch names
    if '..' in branch:
        return False
    
    # Prevent branches starting with dangerous characters
    if branch.startswith('.') or branch.startswith('-'):
        return False
    
    # Prevent null bytes and control characters
    if any(ord(c) < 32 for c in branch):
        return False
    
    return True


def validate_repo_access_secure(repo_name: str, allowed_repos: Optional[List[str]]) -> bool:
    """Check repository access with timing-attack resistance
    
    Uses constant-time comparison to prevent timing attacks that could leak
    repository names in the whitelist.
    
    Args:
        repo_name: Repository name to check
        allowed_repos: List of allowed repositories, or None for no restrictions
        
    Returns:
        True if access is allowed, False otherwise
        
    Security Notes:
        - Uses secrets.compare_digest() for constant-time comparison
        - Prevents timing side-channel attacks
        - Does not leak repository names in validation process
    """
    if allowed_repos is None:
        # No whitelist configured - allow all repos
        return True
    
    # Constant-time comparison to prevent timing attacks
    allowed = False
    for allowed_repo in allowed_repos:
        if secrets.compare_digest(repo_name.encode('utf-8'), allowed_repo.encode('utf-8')):
            allowed = True
            break
    
    return allowed


def validate_file_path_enhanced(file_path: str, max_length: int = 500) -> bool:
    """Enhanced file path validation to prevent path traversal attacks
    
    Validates file paths with comprehensive security checks to prevent
    various path traversal and injection attempts.
    
    Args:
        file_path: File path to validate
        max_length: Maximum allowed path length
        
    Returns:
        True if path is safe, False otherwise
        
    Security Notes:
        - Prevents path traversal attacks (../, ..\\)
        - Blocks absolute paths
        - Prevents Windows drive letter access
        - Checks for null bytes and control characters
        - Limits path length to prevent DoS
    """
    if not file_path:
        return False
    
    # Check for path traversal attempts
    if '..' in file_path:
        return False
    
    # Check for absolute paths (Unix and Windows)
    if file_path.startswith('/') or file_path.startswith('\\'):
        return False
    
    # Check for Windows drive letters (C:, D:, etc.)
    if len(file_path) > 1 and file_path[1] == ':':
        return False
    
    # Check path length
    if len(file_path) > max_length:
        return False
    
    # Check for null bytes and other dangerous characters
    if '\x00' in file_path:
        return False
    
    # Check for control characters (except tab and newline in content)
    if any(ord(c) < 32 for c in file_path):
        return False
    
    # Prevent paths starting with dangerous characters
    if file_path.startswith('.') or file_path.startswith('-'):
        return False
    
    return True


def validate_content_size(content: str, max_size: int = 1024 * 1024) -> bool:
    """Validate content size to prevent DoS attacks
    
    Args:
        content: Content to validate
        max_size: Maximum allowed size in bytes
        
    Returns:
        True if content size is acceptable, False otherwise
    """
    return len(content.encode('utf-8')) <= max_size


def sanitize_error_message(error: str) -> str:
    """Sanitize error messages to prevent information disclosure
    
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
    
    # Common error patterns mapped to safe responses
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
    
    # For other errors, return generic message to prevent info leakage
    return "Operation failed"


def sanitize_url_for_logging(url: str) -> str:
    """Remove sensitive information from URLs for safe logging
    
    Args:
        url: URL to sanitize
        
    Returns:
        Sanitized URL safe for logging
        
    Security Notes:
        - Removes tokens and authentication info
        - Prevents credential leakage in logs
        - Maintains useful debugging information
    """
    # Remove tokens from URL parameters
    sanitized = re.sub(r'[?&]token=[^&]*', '?token=***', url)
    sanitized = re.sub(r'[?&]access_token=[^&]*', '?access_token=***', sanitized)
    # Remove bearer tokens from paths
    sanitized = re.sub(r'/tokens/[a-zA-Z0-9_-]+', '/tokens/***', sanitized)
    return sanitized


def validate_issue_title(title: str, max_length: int = 1000) -> bool:
    """Validate issue title to prevent injection attacks
    
    Args:
        title: Issue title to validate
        max_length: Maximum allowed title length
        
    Returns:
        True if title is safe, False otherwise
    """
    if not title or not title.strip():
        return False
    
    # Check length
    if len(title) > max_length:
        return False
    
    # Check for control characters (except common whitespace)
    if any(ord(c) < 32 and c not in ['\t', '\n', '\r'] for c in title):
        return False
    
    return True


def sanitize_token_in_text(text: str) -> str:
    """Remove GitHub tokens from any text content
    
    Args:
        text: Text that may contain GitHub tokens
        
    Returns:
        Text with tokens replaced by placeholders
        
    Security Notes:
        - Removes new format GitHub tokens (gh[ps]_...)
        - Removes classic 40-character tokens
        - Removes Bearer token headers
    """
    # GitHub personal access tokens (new format)
    text = re.sub(r'gh[ps]_[a-zA-Z0-9]{36}', 'TOKEN_REDACTED', text)
    
    # Classic GitHub tokens (40 hex characters)
    text = re.sub(r'\b[a-fA-F0-9]{40}\b', 'TOKEN_REDACTED', text)
    
    # Bearer tokens in authorization headers
    text = re.sub(r'Bearer\s+[a-zA-Z0-9_-]+', 'Bearer TOKEN_REDACTED', text, re.IGNORECASE)
    
    # Authorization header tokens
    text = re.sub(r'Authorization:\s*[a-zA-Z0-9_-]+', 'Authorization: TOKEN_REDACTED', text, re.IGNORECASE)
    
    return text


# Security validation registry for easy testing and maintenance
VALIDATORS = {
    'branch_name': validate_branch_name,
    'repo_access': validate_repo_access_secure,
    'file_path': validate_file_path_enhanced,
    'content_size': validate_content_size,
    'issue_title': validate_issue_title,
}

# Sanitizers for safe output
SANITIZERS = {
    'error_message': sanitize_error_message,
    'url_logging': sanitize_url_for_logging,
    'token_text': sanitize_token_in_text,  # ADD THIS LINE
}
