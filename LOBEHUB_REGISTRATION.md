# LobeHub Registration — PPPS GitHub MCP Server

## Overview

| Field        | Value                                                                 |
| ------------ | --------------------------------------------------------------------- |
| **Name**     | Tamrael's PPPS (Pretty, Pretty, Pretty Secure) GitHub MCP Server      |
| **Identifier** | `tamrael-magi-ppps-github-mcp`                                      |
| **Version**  | 2.1.0                                                                 |
| **Author**   | Kevin Francisco (Tamrael)                                             |
| **Category** | development                                                           |
| **License**  | MIT                                                                   |
| **Homepage** | https://github.com/tamrael-magi/tamrael-prettyprettyprettysecure-github-mcp |
| **Connection Type** | stdio                                                          |
| **Status**   | End of Life — final release. No further development planned.          |

---

## Supported Transport

### STDIO (Desktop Only)

```json
{
  "mcpServers": {
    "ppps-github": {
      "command": "python",
      "args": [
        "path/to/tamrael_github_general.py",
        "--security-level", "standard"
      ]
    }
  }
}
```

> **Note:** Streamable HTTP is **not supported**. This server communicates via STDIO only, which means it runs on your local machine and is accessible in LobeHub desktop.

---

## Quick Import JSON

Paste this into LobeHub's "Quick Import JSON Configuration" dialog:

```json
{
  "identifier": "tamrael-magi-ppps-github-mcp",
  "name": "PPPS GitHub MCP Server",
  "description": "Secure GitHub MCP server with OS keyring integration, smart whitelisting, cryptographic audit logging, and risk-based access control.",
  "connectionType": "stdio",
  "command": "python",
  "args": [
    "tamrael_github_general.py",
    "--security-level", "standard"
  ],
  "env": {
    "PPPS_DEBUG": "false"
  },
  "settings": {
    "security_level": "standard"
  }
}
```

**Before use:**
1. Install dependencies: `pip install httpx mcp keyring`
2. Run `python secure_config.py setup` to store your GitHub token in the OS keyring
3. Update the `args` path to the actual location of `tamrael_github_general.py`

---

## Capabilities

### Tools (9 total)

This server exposes **tools only** — no MCP resources or prompts.

| Tool                  | Risk Level | Auth Required | Description                                        |
| --------------------- | ---------- | ------------- | -------------------------------------------------- |
| `list_repositories`   | Low        | GITHUB_TOKEN  | List user's repos with security status             |
| `get_repository_info` | Low        | GITHUB_TOKEN  | Get detailed repo info + security status           |
| `create_release`      | Low        | GITHUB_TOKEN  | Create a GitHub release with tag                   |
| `create_file`         | Medium     | GITHUB_TOKEN  | Create a file via Git API (blob→tree→commit→ref)   |
| `get_file_content`    | Medium     | GITHUB_TOKEN  | Read file contents (binary blocked, text only)     |
| `list_files`          | Medium     | GITHUB_TOKEN  | List files/dirs in a repo path                     |
| `create_issue`        | Medium     | GITHUB_TOKEN  | Create an issue with title, body, assignees, labels|
| `get_issues`          | High       | GITHUB_TOKEN  | List issues with filters (OPEN security level only)|
| `read_issues`         | High       | GITHUB_TOKEN  | Read issues (OPEN security level only)             |

### Resources

None. This server does not expose MCP resource endpoints.

### Prompts

None. This server does not expose MCP prompt templates.

---

## Required Configuration

### Authentication

**Required:** GitHub Personal Access Token with `repo` scope.

Stored via OS keyring (recommended) or `GITHUB_TOKEN` environment variable:
```bash
python secure_config.py setup   # Interactive, hides input, validates live
```

### Environment Variables

| Variable       | Default | Description                                    |
| -------------- | ------- | ---------------------------------------------- |
| `GITHUB_TOKEN` | —       | Fallback if keyring unavailable (headless use) |
| `PPPS_DEBUG`   | `false` | Enable debug logging                           |

---

## Security Levels

| Level      | Risks Allowed | Whitelist   | Use Case                          |
| ---------- | ------------- | ----------- | --------------------------------- |
| `strict`   | Low only      | Manual      | Maximum security, read-only       |
| `standard` | Low, Medium   | Smart auto  | Balanced (default)                |
| `open`     | Low, Med, High| Disabled    | Development, all ops permitted    |

Pass via `--security-level` flag or `SECURITY_LEVEL` env var.

---

## Validation Notes

- **Tested in:** LobeHub Desktop
- **Tested transport:** STDIO
- **Not supported:** Streamable HTTP, SSE
- **Known limitation:** All tools require `repo` scope on the GitHub token. Fine-grained PATs must include contents/issues/releases permissions.
- **EOL:** This is the final release (v2.1.0). The project is being replaced by a Rust-based GitLab MCP server.

---

## Files Required

Place all 4 files in the same directory:

```
tamrael_github_general.py    — Main MCP server (v2.0.0)
secure_config.py             — Credential management (v1.2.0)
security_validators.py       — Validation functions (v1.1.0)
overkill_audit_logger.py     — Optional audit logging (v2.1.0)
```

---

## Example: Working Configuration

```json
{
  "mcpServers": {
    "ppps-github": {
      "command": "python",
      "args": [
        "C:\\Users\\Kevin\\Desktop\\Senku_v3\\Senku_3\\MCP_Pretty\\tamrael_github_general.py",
        "--security-level", "standard",
        "--allowed-repos", "my-project,work-repo"
      ]
    }
  }
}
```