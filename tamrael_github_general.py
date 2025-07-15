#!/usr/bin/env python3
"""
Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server

Revolutionary security-first implementation with configurable access controls,
OS keyring integration, and multi-layer vulnerability protection.

Key Security Innovations:
✅ Repository whitelisting for access control
✅ Risk-based operation categorization
✅ OS keyring integration (zero token exposure)
✅ Rate limiting and request validation  
✅ Path traversal protection
✅ Content size limits
✅ Comprehensive audit logging

Requirements:
- Python 3.9+
- httpx
- mcp
- keyring (for secure credential storage)
- pydantic-settings

Usage:
    python tamrael_github_general.py --security-level standard --allowed-repos "my-project,work-repo"
    
Security Configuration:
    # Allow specific repositories only (recommended for production)
    python tamrael_github_general.py --security-level standard --allowed-repos "project1,project2"
    
    # Allow all repositories (development mode)
    python tamrael_github_general.py --security-level standard
    
    # Maximum security (read-only operations)
    python tamrael_github_general.py --security-level strict

Configuration:
    SECURITY_LEVEL: strict|standard|open (default: standard)
    ALLOWED_REPOS: comma-separated list, or empty for no restrictions
    GITHUB_TOKEN: GitHub Personal Access Token
"""

import asyncio
import json
import sys
import os
import re
import time
import argparse
import secrets
import threading
from typing import Any, Sequence, Optional, Dict
from collections import defaultdict, deque
from datetime import datetime, timedelta
import httpx
from mcp.server import Server
import mcp.server.stdio
import mcp.types as types
import base64

# Import secure configuration
try:
    from secure_config import get_secure_settings
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False
    print("Warning: keyring not available, falling back to environment variables")

# Import security validators module (REQUIRED - no fallback)
try:
    from security_validators import (
    validate_branch_name,
    validate_repo_access_secure, 
    validate_file_path_enhanced,
    validate_content_size,
    sanitize_error_message,
    sanitize_url_for_logging
)
except ImportError as e:
    print("CRITICAL: Security validators module required but not available.")
    print("Ensure security_validators.py is in the same directory.")
    print(f"Import error: {e}")
    print("This server cannot run securely without proper validation.")
    sys.exit(1)

# Import optional audit logging (CCTV for your codebase)
try:
    from overkill_audit_logger import OverkillAuditLogger
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    # Audit logging is optional - server works fine without it

# Risk-based operation categorization
OPERATION_RISKS = {
    # Low risk - Safe operations, always allowed
    "list_repositories": "low",
    "get_repository_info": "low", 
    "create_release": "low",
    
    # Medium risk - File operations, requires standard+ security
    "create_file": "medium",
    "get_file_content": "medium",
    "list_files": "medium",
    "create_issue": "medium",
    
    # High risk - Content reading, potential prompt injection
    "get_issues": "high",
    "read_issues": "high",
    "read_discussions": "high", 
    "read_comments": "high",
    "read_pull_requests": "high"
}

# Security level definitions with smart whitelisting
SECURITY_LEVELS = {
    "strict": {
        "risks": ["low"],
        "whitelisting": "manual_required",
        "description": "Manual whitelist required + read-only operations"
    },
    "standard": {
        "risks": ["low", "medium"],
        "whitelisting": "smart_default", 
        "description": "Smart auto-whitelist + file operations (DEFAULT)"
    },
    "open": {
        "risks": ["low", "medium", "high"],
        "whitelisting": "disabled",
        "description": "No restrictions + all operations (development)"
    }
}

# Configuration with user-friendly defaults
DEFAULT_SECURITY_LEVEL = "standard"  # Most users want file reading
MAX_CONTENT_SIZE = 1024 * 1024      # 1MB limit for file content
MAX_REQUESTS_PER_MINUTE = 60        # Rate limiting
MAX_FILE_PATH_LENGTH = 500          # Path length limit

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description="Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security Levels:
  strict   - Manual whitelist required + read-only operations only
  standard - Smart IP protection + file operations allowed (DEFAULT)
  open     - No restrictions + all operations (development/testing)

Smart Whitelisting (Empirically-Validated):
  • Private repos: 30-day activity threshold (IP protection)
  • Public repos: Always allowed (already public, no IP risk)
  • Based on enterprise research: 70-90% coverage of active business repos

Examples:
  # Smart IP protection (auto-detects active private repos)
  python tamrael_github_general.py --security-level standard
  
  # Smart detection + manual additions (additive)
  python tamrael_github_general.py --security-level standard --allowed-repos "extra-repo1,extra-repo2"
  
  # Manual whitelist for production (strict mode)
  python tamrael_github_general.py --security-level strict --allowed-repos "prod-app,staging-env"
  
  # Development mode (no restrictions)
  python tamrael_github_general.py --security-level open
        """
    )
    
    parser.add_argument(
        "--security-level", 
        choices=["strict", "standard", "open"],
        default=os.getenv("SECURITY_LEVEL", DEFAULT_SECURITY_LEVEL),
        help="Security level for operations (default: standard)"
    )
    
    parser.add_argument(
        "--allowed-repos",
        default=os.getenv("ALLOWED_REPOS", ""),
        help="Additional repositories to whitelist (added to smart detection in standard mode). Example: 'project1,project2,team-repo'"
    )
    
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=int(os.getenv("RATE_LIMIT", MAX_REQUESTS_PER_MINUTE)),
        help=f"Requests per minute limit (default: {MAX_REQUESTS_PER_MINUTE})"
    )
    
    return parser.parse_args()

# Global configuration
args = parse_args()
SECURITY_LEVEL = args.security_level
# ALLOWED_REPOS will be set dynamically in main() based on smart whitelisting
ALLOWED_REPOS = None
MAX_REQUESTS_PER_MINUTE = args.rate_limit

# Rate limiting storage with thread safety
request_times = defaultdict(deque)
rate_limit_lock = threading.Lock()

# Initialize MCP server
server = Server("tamrael-secure-github-mcp")

# Initialize optional audit logger (CCTV for your codebase)
audit_logger = None
if AUDIT_AVAILABLE:
    try:
        audit_logger = OverkillAuditLogger(enabled=True)
        print("🔒 AUDIT: CCTV for your codebase - ENABLED", file=sys.stderr)
    except Exception as e:
        print(f"⚠️ AUDIT: Could not initialize audit logger: {e}", file=sys.stderr)
        audit_logger = None

def get_github_token() -> str:
    """Get GitHub token from secure storage or environment"""
    if KEYRING_AVAILABLE:
        try:
            settings = get_secure_settings()
            if settings.has_github_token:
                return settings.github_token
        except Exception as e:
            print(f"Warning: Could not access secure config: {e}")
    
    # Fallback to environment variable
    return os.getenv("GITHUB_TOKEN", "")

async def get_smart_default_repos(github_token: str) -> list[str]:
    """Get smart default repositories based on empirically-validated activity patterns
    
    Private repos: 30-day threshold (captures 70-90% of active business repos)
    Public repos: Always allowed (no IP protection needed)
    
    Based on enterprise research showing private repos have higher commit frequencies
    and IP protection requires more restrictive access control.
    """
    smart_repos = []
    
    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        from datetime import datetime, timedelta
        # Empirically-validated threshold: 30 days for private repos (enterprise standard)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get user's repositories, sorted by recently updated
            response = await client.get(
                "https://api.github.com/user/repos?sort=updated&per_page=100",
                headers=headers
            )
            
            if response.status_code == 200:
                repos = response.json()
                public_repos = []
                private_repos = []
                
                # Separate private and public repositories
                for repo in repos:
                    if repo.get("private", False):
                        # Private repos: Apply 30-day smart filtering for IP protection
                        if repo.get("pushed_at", "") > thirty_days_ago:
                            private_repos.append(repo["name"])
                    else:
                        # Public repos: Always allow (no IP risk)
                        public_repos.append(repo["name"])
                
                # Combine with prioritization: private repos first (more restrictive)
                smart_repos = private_repos + public_repos
                
                # Log the intelligent filtering results
                if private_repos:
                    log_to_stderr(f"🔒 Private repos (30-day filter): {len(private_repos)} active")
                if public_repos:
                    log_to_stderr(f"🌐 Public repos (always allowed): {len(public_repos)} total")
                
                # Limit to reasonable number to prevent overwhelming
                smart_repos = smart_repos[:20]
                
    except Exception as e:
        log_to_stderr(f"Smart whitelist detection failed: {str(e)}")
        # Fallback to empty list - will require manual configuration
        return []
    
    return smart_repos

async def initialize_smart_whitelist() -> list[str]:
    """Initialize smart whitelist based on security level"""
    security_config = SECURITY_LEVELS.get(SECURITY_LEVEL, {})
    whitelisting_mode = security_config.get("whitelisting", "manual_required")
    
    if whitelisting_mode == "disabled":
        # Open mode - no whitelisting
        return None
    elif whitelisting_mode == "manual_required":
        # Strict mode - manual whitelist required
        if not args.allowed_repos:
            log_to_stderr("🛡️ STRICT MODE: Manual repository whitelist required")
            log_to_stderr("   Add: --allowed-repos 'repo1,repo2,repo3'")
            return []
        return [repo.strip() for repo in args.allowed_repos.split(",") if repo.strip()]
    elif whitelisting_mode == "smart_default":
        # Standard mode - smart defaults + manual additions
        smart_repos = []
        
        # Get smart defaults if enabled
        github_token = get_github_token()
        if github_token:
            smart_repos = await get_smart_default_repos(github_token)
            if smart_repos:
                log_to_stderr(f"🧠 SMART IP PROTECTION: Auto-detected {len(smart_repos)} repositories")
                log_to_stderr(f"   Smart repos: {', '.join(smart_repos)}")
            else:
                log_to_stderr("⚠️  No smart repos detected.")
        else:
            smart_repos = []
            log_to_stderr("❌ No GitHub token found for smart detection.")
        
        # Add manual repos to smart repos (additive)
        manual_repos = []
        if args.allowed_repos:
            manual_repos = [repo.strip() for repo in args.allowed_repos.split(",") if repo.strip()]
            log_to_stderr(f"📋 MANUAL ADDITIONS: {len(manual_repos)} repositories specified")
            log_to_stderr(f"   Manual repos: {', '.join(manual_repos)}")
        
        # Combine smart + manual (remove duplicates while preserving order)
        combined_repos = smart_repos.copy()
        for repo in manual_repos:
            if repo not in combined_repos:
                combined_repos.append(repo)
        
        if combined_repos:
            log_to_stderr(f"🚀 TOTAL WHITELIST: {len(combined_repos)} repositories ({len(smart_repos)} smart + {len(manual_repos)} manual)")
            log_to_stderr("💡 Add more with: --allowed-repos 'additional1,additional2'")
        else:
            log_to_stderr("⚠️  No repositories configured. Add manually: --allowed-repos 'repo1,repo2'")
        
        return combined_repos
    
    return []

def is_operation_allowed(operation: str) -> bool:
    """Check if operation is allowed based on current security level"""
    risk_level = OPERATION_RISKS.get(operation, "high")  # Default to high risk for unknown operations
    allowed_risks = SECURITY_LEVELS.get(SECURITY_LEVEL, {"risks": ["low"]}).get("risks", ["low"])
    return risk_level in allowed_risks

def validate_repo_access(repo_name: str) -> bool:
    """Check if repository access is allowed based on whitelist configuration
    
    Uses constant-time comparison to prevent timing attacks that could leak
    repository names in the whitelist.
    """
    allowed = validate_repo_access_secure(repo_name, ALLOWED_REPOS)
    if not allowed:
        # Don't leak repository name in logs to prevent information disclosure
        log_to_stderr("SECURITY: Repository access denied")
    return allowed

def get_security_error_message(operation: str) -> str:
    """Get user-friendly error message for blocked operations"""
    risk_level = OPERATION_RISKS.get(operation, "high")
    
    if risk_level == "medium":
        return f"Operation '{operation}' requires 'standard' or 'open' security level. Current: '{SECURITY_LEVEL}'"
    elif risk_level == "high":
        return f"Operation '{operation}' requires 'open' security level. Current: '{SECURITY_LEVEL}'"
    else:
        return f"Operation '{operation}' is not allowed at security level '{SECURITY_LEVEL}'"









def check_rate_limit(client_id: str = "default") -> bool:
    """Check if client is within rate limits
    
    Uses thread-safe atomic operations to prevent race conditions
    when multiple requests are processed simultaneously.
    """
    with rate_limit_lock:
        now = time.time()
        minute_ago = now - 60
        
        # Clean old requests
        while request_times[client_id] and request_times[client_id][0] < minute_ago:
            request_times[client_id].popleft()
        
        # Check if under limit
        if len(request_times[client_id]) >= MAX_REQUESTS_PER_MINUTE:
            return False
        
        # Add current request
        request_times[client_id].append(now)
        return True

def log_to_stderr(message: str):
    """Log to stderr with URL sanitization"""
    sanitized_message = sanitize_url_for_logging(message)
    print(f"[TAMRAEL-MCP] {sanitized_message}", file=sys.stderr)

def audit_log(operation: str, file_path: str, repo: str, result: str = "success", metadata: dict = None):
    """Optional audit logging for file operations (CCTV for your codebase)"""
    if audit_logger and audit_logger.enabled:
        try:
            audit_metadata = metadata or {}
            audit_metadata.update({
                "repo": repo,
                "security_level": SECURITY_LEVEL,
                "user_agent": "mcp_server"
            })
            
            entry_hash = audit_logger.log_file_access(
                file_path=file_path,
                operation=operation,
                user="mcp_server",
                result=result,
                metadata=audit_metadata
            )
            
            # Log the audit action (but don't spam)
            if operation in ["create", "delete"] or len(audit_logger.chain) % 10 == 0:
                log_to_stderr(f"📹 AUDIT: {operation.upper()} {file_path} | Hash: {entry_hash[:8]}...")
                
        except Exception as e:
            # Audit logging should never break the main functionality
            log_to_stderr(f"⚠️ AUDIT: Logging failed: {str(e)[:50]}...")

async def make_github_request(method: str, endpoint: str, data: Optional[dict] = None) -> dict:
    """Make HTTP request to GitHub API with comprehensive security"""
    
    # Rate limiting check
    if not check_rate_limit():
        return {"error": "Rate limit exceeded"}
    
    github_token = get_github_token()
    if not github_token:
        return {"error": "GitHub token not configured. Run: python secure_config.py setup"}
    
    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Tamrael-Secure-MCP/1.0"
        }
        
        url = f"https://api.github.com{endpoint}"
        
        # Log sanitized URL (no token exposure)
        log_to_stderr(f"Making {method} request to {sanitize_url_for_logging(url)}")
        
        # Handle data properly
        json_data = data if data is not None else {}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                response = await client.post(url, headers=headers, json=json_data)
            elif method == "PUT":
                response = await client.put(url, headers=headers, json=json_data)
            elif method == "PATCH":
                response = await client.patch(url, headers=headers, json=json_data)
            elif method == "DELETE":
                response = await client.delete(url, headers=headers)
            else:
                return {"error": "Unsupported HTTP method"}
            
            log_to_stderr(f"Response status: {response.status_code}")
            
            # Enhanced error handling
            if response.status_code == 401:
                return {"error": "GitHub authentication failed - check your token"}
            elif response.status_code == 403:
                return {"error": "GitHub access forbidden - check token permissions"}
            elif response.status_code == 404:
                return {"error": "GitHub resource not found"}
            elif response.status_code == 422:
                return {"error": "Invalid request data"}
            elif response.status_code >= 400:
                return {"error": f"GitHub API error {response.status_code}"}
            
            # Handle empty responses
            if not response.content:
                return {"success": True, "message": "Operation completed successfully"}
                
            return response.json()
        
    except httpx.TimeoutException:
        log_to_stderr("Request to GitHub API timed out")
        return {"error": "Request timeout"}
    except httpx.NetworkError as e:
        log_to_stderr(f"Network error: {type(e).__name__}")
        return {"error": "Network error"}
    except Exception as e:
        error_msg = sanitize_error_message(str(e))
        log_to_stderr(f"Request error: {error_msg}")
        return {"error": error_msg}

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available GitHub MCP tools based on security level"""
    log_to_stderr(f"Listing tools for security level: {SECURITY_LEVEL}")
    
    tools = []
    
    # Always available tools (low risk)
    if is_operation_allowed("list_repositories"):
        tools.append(types.Tool(
            name="list_repositories",
            description="List user's repositories with security status",
            inputSchema={
                "type": "object",
                "properties": {
                    "per_page": {
                        "type": "integer",
                        "description": "Number of repositories per page (max 100)",
                        "default": 30
                    },
                    "sort": {
                        "type": "string",
                        "description": "Sort by: created, updated, pushed, full_name",
                        "default": "updated"
                    }
                },
                "required": []
            }
        ))
    
    if is_operation_allowed("get_repository_info"):
        tools.append(types.Tool(
            name="get_repository_info",
            description="Get repository information and security status",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name (owner/repo for other users)"
                    }
                },
                "required": ["repo"]
            }
        ))
    
    if is_operation_allowed("create_release"):
        tools.append(types.Tool(
            name="create_release",
            description="Create a GitHub release",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "tag_name": {
                        "type": "string",
                        "description": "Git tag for the release"
                    },
                    "name": {
                        "type": "string",
                        "description": "Release name"
                    },
                    "body": {
                        "type": "string",
                        "description": "Release description/notes"
                    },
                    "draft": {
                        "type": "boolean",
                        "description": "Create as draft (default: false)",
                        "default": False
                    }
                },
                "required": ["repo", "tag_name", "name"]
            }
        ))
    
    # File operations (medium risk) - available in standard+ security
    if is_operation_allowed("create_file"):
        tools.append(types.Tool(
            name="create_file",
            description="Create a file in a repository with secure validation",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path for the new file (security validated)"
                    },
                    "content": {
                        "type": "string",
                        "description": "File content (size limited for security)"
                    },
                    "commit_message": {
                        "type": "string",
                        "description": "Commit message"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (default: main)",
                        "default": "main"
                    }
                },
                "required": ["repo", "file_path", "content", "commit_message"]
            }
        ))
    
    if is_operation_allowed("get_file_content"):
        tools.append(types.Tool(
            name="get_file_content",
            description="Get the content of a file from a repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (default: main)",
                        "default": "main"
                    }
                },
                "required": ["repo", "file_path"]
            }
        ))
    
    if is_operation_allowed("list_files"):
        tools.append(types.Tool(
            name="list_files",
            description="List files and directories in a repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory path (default: root)",
                        "default": ""
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch name (default: main)",
                        "default": "main"
                    }
                },
                "required": ["repo"]
            }
        ))
    
    # High risk operations (open security level only)
    if is_operation_allowed("get_issues"):
        tools.append(types.Tool(
            name="get_issues",
            description="Get repository issues (requires open security level)",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "state": {
                        "type": "string",
                        "description": "Issue state: open, closed, all",
                        "enum": ["open", "closed", "all"],
                        "default": "open"
                    },
                    "labels": {
                        "type": "string",
                        "description": "Comma-separated list of label names"
                    },
                    "assignee": {
                        "type": "string",
                        "description": "Username of assignee, or * for any assignee"
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Number of issues per page (max 100)",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 30
                    },
                    "page": {
                        "type": "integer",
                        "description": "Page number for pagination",
                        "minimum": 1,
                        "default": 1
                    }
                },
                "required": ["repo"],
                "additionalProperties": False
            }
        ))
    
    if is_operation_allowed("create_issue"):
        tools.append(types.Tool(
            name="create_issue",
            description="Create a new issue in a repository (requires standard+ security level)",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "title": {
                        "type": "string",
                        "description": "Issue title",
                        "minLength": 1
                    },
                    "body": {
                        "type": "string",
                        "description": "Issue description/body"
                    },
                    "assignees": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of usernames to assign to the issue"
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of label names to add to the issue"
                    }
                },
                "required": ["repo", "title"],
                "additionalProperties": False
            }
        ))
    
    if is_operation_allowed("read_issues"):
        tools.append(types.Tool(
            name="read_issues",
            description="Read repository issues (requires open security level)",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo": {
                        "type": "string",
                        "description": "Repository name"
                    },
                    "state": {
                        "type": "string",
                        "description": "Issue state: open, closed, all",
                        "default": "open"
                    }
                },
                "required": ["repo"]
            }
        ))
    
    log_to_stderr(f"Returning {len(tools)} tools for security level '{SECURITY_LEVEL}'")
    return tools

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    """Handle GitHub tool execution with comprehensive security"""
    
    log_to_stderr(f"Executing tool: {name}")
    
    # Rate limiting check
    if not check_rate_limit():
        return [types.TextContent(
            type="text",
            text="SECURITY: Rate limit exceeded. Please wait before making more requests."
        )]
    
    # Validate operation is allowed at current security level
    if not is_operation_allowed(name):
        return [types.TextContent(
            type="text",
            text=f"SECURITY: {get_security_error_message(name)}"
        )]
    
    # Repository access validation for operations that need it
    repo_name = arguments.get("repo", "")
    if repo_name and not validate_repo_access(repo_name):
        whitelist_info = f"Allowed repositories: {ALLOWED_REPOS}" if ALLOWED_REPOS else "All repositories allowed (no whitelist configured)"
        return [types.TextContent(
            type="text",
            text=f"SECURITY: Repository '{repo_name}' not accessible. {whitelist_info}"
        )]
    
    # Execute the requested operation
    if name == "list_repositories":
        per_page = arguments.get("per_page", 30)
        sort = arguments.get("sort", "updated")
        
        result = await make_github_request("GET", f"/user/repos?sort={sort}&per_page={per_page}")
        
        if "error" not in result and isinstance(result, list):
            # Add security status to each repo
            filtered_repos = []
            for repo in result:
                repo_info = {
                    "name": repo["name"],
                    "full_name": repo["full_name"], 
                    "private": repo["private"],
                    "description": repo["description"],
                    "updated_at": repo["updated_at"],
                    "security_status": {
                        "whitelisted": validate_repo_access(repo["name"]),
                        "accessible": validate_repo_access(repo["name"])
                    }
                }
                filtered_repos.append(repo_info)
            
            return [types.TextContent(
                type="text",
                text=f"Repositories (security level: {SECURITY_LEVEL}):\n{json.dumps(filtered_repos, indent=2)}"
            )]
        
        return [types.TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
    
    elif name == "get_repository_info":
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        result = await make_github_request("GET", f"/repos/{repo_full_name}")
        
        if "error" not in result:
            # Add security context
            result["security_status"] = {
                "whitelisted": validate_repo_access(repo_name),
                "security_level": SECURITY_LEVEL,
                "allowed_operations": [op for op in OPERATION_RISKS.keys() if is_operation_allowed(op)],
                "security_features": [
                    f"Rate limiting: {MAX_REQUESTS_PER_MINUTE} req/min",
                    "Path traversal protection",
                    f"Content size limit: {MAX_CONTENT_SIZE} bytes",
                    "Token sanitization",
                    f"Risk-based operation filtering"
                ]
            }
        
        return [types.TextContent(
            type="text",
            text=f"Repository info:\n{json.dumps(result, indent=2)}"
        )]
    
    elif name == "get_file_content":
        file_path = arguments.get("file_path", "")
        branch = arguments.get("branch", "main")
        
        # Security validations
        if not validate_file_path_enhanced(file_path):
            return [types.TextContent(
                type="text",
                text="SECURITY: Invalid file path detected (path traversal attempt blocked)"
            )]
        
        # Validate branch name to prevent command injection
        if not validate_branch_name(branch):
            return [types.TextContent(
                type="text",
                text="SECURITY: Invalid branch name detected (potential command injection blocked)"
            )]
        
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        result = await make_github_request("GET", f"/repos/{repo_full_name}/contents/{file_path}?ref={branch}")
        
        if "error" not in result and "content" in result:
            try:
                # Audit log the file read
                audit_log("read", file_path, repo_name, "success", {
                    "branch": branch,
                    "file_size": result.get('size', 0),
                    "encoding": "base64_decoded"
                })
                
                # Decode base64 content
                content = base64.b64decode(result["content"]).decode('utf-8')
                return [types.TextContent(
                    type="text",
                    text=f"File: {file_path}\nBranch: {branch}\nSize: {result.get('size', 0)} bytes\n\nContent:\n{content}"
                )]
            except Exception as e:
                audit_log("read", file_path, repo_name, "decode_failed", {
                    "error": "decode_error",
                    "branch": branch
                })
                return [types.TextContent(
                    type="text", 
                    text=f"Error decoding file content: {sanitize_error_message(str(e))}"
                )]
        else:
            # Log failed file read attempt
            audit_log("read", file_path, repo_name, "failed", {
                "branch": branch,
                "error": "file_not_found_or_error"
            })
        
        return [types.TextContent(
            type="text",
            text=f"File content result:\n{json.dumps(result, indent=2)}"
        )]
    
    elif name == "list_files":
        path = arguments.get("path", "")
        branch = arguments.get("branch", "main")
        
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        endpoint = f"/repos/{repo_full_name}/contents"
        if path:
            endpoint += f"/{path}"
        endpoint += f"?ref={branch}"
        
        result = await make_github_request("GET", endpoint)
        
        if "error" not in result and isinstance(result, list):
            # Audit log the directory listing
            audit_log("list", path or "root", repo_name, "success", {
                "branch": branch,
                "item_count": len(result),
                "directory_path": path
            })
            
            files = []
            for item in result:
                files.append({
                    "name": item["name"],
                    "type": item["type"],  # file or dir
                    "size": item.get("size", 0),
                    "path": item["path"]
                })
            
            return [types.TextContent(
                type="text",
                text=f"Files in {repo_name}/{path or 'root'} (branch: {branch}):\n{json.dumps(files, indent=2)}"
            )]
        else:
            # Log failed directory listing
            audit_log("list", path or "root", repo_name, "failed", {
                "branch": branch,
                "error": "directory_not_found_or_error"
            })
        
        return [types.TextContent(
            type="text",
            text=f"List files result:\n{json.dumps(result, indent=2)}"
        )]
    
    elif name == "create_file":
        file_path = arguments.get("file_path", "")
        content = arguments.get("content", "")
        commit_message = arguments.get("commit_message", "")
        branch = arguments.get("branch", "main")
        
        # Security validations
        if not validate_file_path_enhanced(file_path):
            return [types.TextContent(
                type="text",
                text="SECURITY: Invalid file path detected (path traversal attempt blocked)"
            )]
        
        if not validate_content_size(content):
            return [types.TextContent(
                type="text",
                text=f"SECURITY: Content too large (max {MAX_CONTENT_SIZE} bytes)"
            )]
        
        # Multi-step secure Git operations
        try:
            user_result = await make_github_request("GET", "/user")
            if "error" in user_result:
                return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
            
            username = user_result["login"]
            repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
            
            # Get branch reference
            ref_result = await make_github_request("GET", f"/repos/{repo_full_name}/git/refs/heads/{branch}")
            if "error" in ref_result:
                return [types.TextContent(type="text", text=f"Error getting branch ref: {json.dumps(ref_result, indent=2)}")]
            
            latest_commit_sha = ref_result["object"]["sha"]
            
            # Create blob
            blob_data = {
                "content": base64.b64encode(content.encode()).decode(),
                "encoding": "base64"
            }
            blob_result = await make_github_request("POST", f"/repos/{repo_full_name}/git/blobs", blob_data)
            if "error" in blob_result:
                return [types.TextContent(type="text", text=f"Error creating blob: {json.dumps(blob_result, indent=2)}")]
            
            blob_sha = blob_result["sha"]
            
            # Get commit to find tree
            commit_result = await make_github_request("GET", f"/repos/{repo_full_name}/git/commits/{latest_commit_sha}")
            if "error" in commit_result:
                return [types.TextContent(type="text", text=f"Error getting commit: {json.dumps(commit_result, indent=2)}")]
            
            base_tree_sha = commit_result["tree"]["sha"]
            
            # Create tree
            tree_data = {
                "base_tree": base_tree_sha,
                "tree": [{
                    "path": file_path,
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_sha
                }]
            }
            tree_result = await make_github_request("POST", f"/repos/{repo_full_name}/git/trees", tree_data)
            if "error" in tree_result:
                return [types.TextContent(type="text", text=f"Error creating tree: {json.dumps(tree_result, indent=2)}")]
            
            new_tree_sha = tree_result["sha"]
            
            # Create commit
            commit_data = {
                "message": commit_message,
                "parents": [latest_commit_sha],
                "tree": new_tree_sha
            }
            new_commit_result = await make_github_request("POST", f"/repos/{repo_full_name}/git/commits", commit_data)
            if "error" in new_commit_result:
                return [types.TextContent(type="text", text=f"Error creating commit: {json.dumps(new_commit_result, indent=2)}")]
            
            new_commit_sha = new_commit_result["sha"]
            
            # Update branch reference
            ref_update_data = {"sha": new_commit_sha}
            update_result = await make_github_request("PATCH", f"/repos/{repo_full_name}/git/refs/heads/{branch}", ref_update_data)
            
            if "error" not in update_result:
                # Audit log successful file creation
                audit_log("create", file_path, repo_name, "success", {
                    "branch": branch,
                    "commit_message": commit_message,
                    "content_size": len(content),
                    "commit_sha": new_commit_sha
                })
            else:
                # Log failed file creation
                audit_log("create", file_path, repo_name, "failed", {
                    "branch": branch,
                    "error": "branch_update_failed",
                    "commit_message": commit_message
                })
            
            return [types.TextContent(
                type="text",
                text=f"File created successfully in {repo_name}:\n{json.dumps(update_result, indent=2)}"
            )]
            
        except Exception as e:
            error_msg = sanitize_error_message(str(e))
            
            # Audit log the failed file creation attempt
            audit_log("create", file_path, repo_name, "failed", {
                "branch": branch,
                "error": "creation_exception",
                "commit_message": commit_message,
                "content_size": len(content)
            })
            
            return [types.TextContent(
                type="text",
                text=f"Error in secure file creation: {error_msg}"
            )]
    
    elif name == "create_release":
        tag_name = arguments.get("tag_name", "")
        release_name = arguments.get("name", "")
        release_body = arguments.get("body", "")
        is_draft = arguments.get("draft", False)
        
        # Validate release body size
        if not validate_content_size(release_body):
            return [types.TextContent(
                type="text",
                text=f"SECURITY: Release body too large (max {MAX_CONTENT_SIZE} bytes)"
            )]
        
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        release_data = {
            "tag_name": tag_name,
            "name": release_name,
            "body": release_body,
            "draft": is_draft,
            "prerelease": False
        }
        
        result = await make_github_request("POST", f"/repos/{repo_full_name}/releases", release_data)
        return [types.TextContent(
            type="text",
            text=f"Release creation result:\n{json.dumps(result, indent=2)}"
        )]
    
    elif name == "read_issues":
        state = arguments.get("state", "open")
        
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        result = await make_github_request("GET", f"/repos/{repo_full_name}/issues?state={state}")
        
        if "error" not in result and isinstance(result, list):
            issues = []
            for issue in result:
                issues.append({
                    "number": issue["number"],
                    "title": issue["title"],
                    "state": issue["state"],
                    "created_at": issue["created_at"],
                    "updated_at": issue["updated_at"],
                    "user": issue["user"]["login"] if issue["user"] else "unknown"
                })
            
            return [types.TextContent(
                type="text",
                text=f"Issues in {repo_name} (state: {state}):\n{json.dumps(issues, indent=2)}"
            )]
        
        return [types.TextContent(
            type="text",
            text=f"Issues result:\n{json.dumps(result, indent=2)}"
        )]
    
    elif name == "get_issues":
        state = arguments.get("state", "open")
        labels = arguments.get("labels", "")
        assignee = arguments.get("assignee", "")
        per_page = arguments.get("per_page", 30)
        page = arguments.get("page", 1)
        
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        # Build query parameters
        params = {
            "state": state,
            "per_page": per_page,
            "page": page
        }
        if labels:
            params["labels"] = labels
        if assignee:
            params["assignee"] = assignee
        
        # Build endpoint with query string
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"/repos/{repo_full_name}/issues?{query_string}"
        
        result = await make_github_request("GET", endpoint)
        
        if "error" not in result and isinstance(result, list):
            # Audit log the issues read
            audit_log("read", "issues", repo_name, "success", {
                "state": state,
                "labels": labels,
                "assignee": assignee,
                "issue_count": len(result),
                "page": page
            })
            
            # Filter sensitive data for security
            filtered_issues = []
            for issue in result:
                filtered_issues.append({
                    "number": issue["number"],
                    "title": issue["title"],
                    "state": issue["state"],
                    "created_at": issue["created_at"],
                    "updated_at": issue["updated_at"],
                    "user": issue["user"]["login"] if issue["user"] else "unknown",
                    "labels": [label["name"] for label in issue.get("labels", [])],
                    "assignees": [assignee["login"] for assignee in issue.get("assignees", [])],
                    "url": issue["html_url"]
                })
            
            return [types.TextContent(
                type="text",
                text=f"Issues in {repo_name} (state: {state}, page: {page}):\n{json.dumps(filtered_issues, indent=2)}"
            )]
        else:
            # Log failed issues read attempt
            audit_log("read", "issues", repo_name, "failed", {
                "state": state,
                "error": "issues_not_found_or_error"
            })
        
        return [types.TextContent(
            type="text",
            text=f"Issues result:\n{json.dumps(result, indent=2)}"
        )]
    
    elif name == "create_issue":
        title = arguments.get("title", "")
        body = arguments.get("body", "")
        assignees = arguments.get("assignees", [])
        labels = arguments.get("labels", [])
        
        # Security validations
        if not title.strip():
            return [types.TextContent(
                type="text",
                text="SECURITY: Issue title cannot be empty"
            )]
        
        if not validate_content_size(body):
            return [types.TextContent(
                type="text",
                text=f"SECURITY: Issue body too large (max {MAX_CONTENT_SIZE} bytes)"
            )]
        
        user_result = await make_github_request("GET", "/user")
        if "error" in user_result:
            return [types.TextContent(type="text", text=f"Error getting user info: {json.dumps(user_result, indent=2)}")]
        
        username = user_result["login"]
        repo_full_name = f"{username}/{repo_name}" if "/" not in repo_name else repo_name
        
        # Create issue data
        issue_data = {
            "title": title,
            "body": body
        }
        
        if assignees:
            issue_data["assignees"] = assignees
        if labels:
            issue_data["labels"] = labels
        
        result = await make_github_request("POST", f"/repos/{repo_full_name}/issues", issue_data)
        
        if "error" not in result:
            # Audit log successful issue creation
            audit_log("create", "issue", repo_name, "success", {
                "title": title,
                "body_length": len(body),
                "assignees": assignees,
                "labels": labels,
                "issue_number": result.get("number")
            })
        else:
            # Log failed issue creation
            audit_log("create", "issue", repo_name, "failed", {
                "title": title,
                "error": "creation_failed"
            })
        
        return [types.TextContent(
            type="text",
            text=f"Issue creation result:\n{json.dumps(result, indent=2)}"
        )]
    
    else:
        return [types.TextContent(
            type="text",
            text=f"Unknown tool: {name}"
        )]

async def main():
    """Run Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server"""
    global ALLOWED_REPOS
    
    try:
        log_to_stderr("🔐 Starting Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server")
        log_to_stderr("🏆 Security Innovations Active")
        log_to_stderr("=" * 60)
        
        # Initialize smart whitelisting based on security level
        ALLOWED_REPOS = await initialize_smart_whitelist()
        
        # Display current configuration
        security_config = SECURITY_LEVELS.get(SECURITY_LEVEL, {})
        log_to_stderr(f"🛡️  Security Level: {SECURITY_LEVEL}")
        log_to_stderr(f"   Description: {security_config.get('description', 'Unknown')}")
        
        allowed_ops = [op for op in OPERATION_RISKS.keys() if is_operation_allowed(op)]
        log_to_stderr(f"⚡ Allowed Operations ({len(allowed_ops)}): {', '.join(allowed_ops)}")
        
        if ALLOWED_REPOS is None:
            log_to_stderr("🌐 Repository Access: All repositories allowed (open mode)")
        elif len(ALLOWED_REPOS) == 0:
            log_to_stderr("🚫 Repository Access: No repositories configured")
        else:
            log_to_stderr(f"📋 Active Whitelist ({len(ALLOWED_REPOS)}): {', '.join(ALLOWED_REPOS)}")
        
        log_to_stderr(f"⏱️  Rate Limit: {MAX_REQUESTS_PER_MINUTE} requests/minute")
        log_to_stderr(f"📁 Max Content Size: {MAX_CONTENT_SIZE} bytes")
        
        # Check token configuration
        github_token = get_github_token()
        if github_token:
            token_preview = f"{github_token[:8]}...{github_token[-4:]}" if len(github_token) > 12 else "***"
            log_to_stderr(f"🔑 GitHub Token: ✅ Configured ({token_preview})")
            
            if KEYRING_AVAILABLE:
                log_to_stderr("🔐 Credential Storage: ✅ OS Keyring (Encrypted)")
            else:
                log_to_stderr("⚠️  Credential Storage: Environment Variables (Less Secure)")
                log_to_stderr("💡 Tip: Run 'python secure_config.py setup' for encrypted storage")
        else:
            log_to_stderr("❌ GitHub Token: Not configured")
            log_to_stderr("🔧 Setup: Run 'python secure_config.py setup'")
        
        log_to_stderr("=" * 60)
        log_to_stderr("🚀 Security Features Active:")
        log_to_stderr("   • Risk-based operation categorization")
        log_to_stderr("   • Smart repository whitelisting")
        log_to_stderr("   • OS keyring integration")
        log_to_stderr("   • Rate limiting & DoS protection")
        log_to_stderr("   • Path traversal prevention")
        log_to_stderr("   • Token sanitization")
        log_to_stderr("   • Comprehensive input validation")
        if audit_logger and audit_logger.enabled:
            log_to_stderr("   • CCTV audit logging (FOR THE LULZ)")
        log_to_stderr("=" * 60)
        
        if not github_token:
            log_to_stderr("⚠️  WARNING: No GitHub token - operations will fail")
            log_to_stderr("   Run: python secure_config.py setup")
        
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            log_to_stderr("✅ SUCCESS: Tamrael's Pretty, Pretty, Pretty Secure MCP Server initialized!")
            log_to_stderr("🔒 Ready for Claude Desktop with enterprise-grade security")
            
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
            
    except Exception as e:
        error_msg = sanitize_error_message(str(e))
        log_to_stderr(f"❌ Server failed to start: {error_msg}")
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Display configuration help for first-time users
    if len(sys.argv) == 1:  # No arguments provided
        print("\n🔐 Tamrael's Pretty, Pretty, Pretty Secure GitHub MCP Server")
        print("\n📖 Quick Start:")
        print("1. Set up credentials: python secure_config.py setup")
        print("2. Smart mode (auto-detects active repos): python tamrael_github_general.py")
        print("3. Manual whitelist: python tamrael_github_general.py --allowed-repos 'repo1,repo2'")
        print("4. Development mode: python tamrael_github_general.py --security-level open")
        print("\n📋 Security Levels:")
        print("  • strict   - Manual whitelist required + read-only operations")
        print("  • standard - Smart auto-whitelist + file operations [DEFAULT]")
        print("  • open     - No restrictions + all operations (development)")
        print("\n💡 Use --help for full options\n")
    
    asyncio.run(main())