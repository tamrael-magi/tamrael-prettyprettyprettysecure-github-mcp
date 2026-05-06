# Quick Start — PPPS GitHub MCP

Get your AI tools talking to GitHub. Five minutes, not five hours.

---

## Before You Start

**You need:**
- Python 3.9+
- A GitHub account
- **Claude Desktop**, **OpenCode**, or any MCP-compatible client

## Step 1: Download

```bash
git clone https://github.com/tamrael-magi/tamrael-prettyprettyprettysecure-github-mcp.git
cd ppps-github-mcp
```

## Step 2: Install

```bash
pip install httpx mcp keyring
```

## Step 3: Set Up Your Token

Your token stays encrypted in your computer's keyring. No visible secrets.

```bash
python secure_config.py setup
```

The tool walks you through it. Paste your token when asked.

> **Don't have a token?** Go to GitHub → Settings → Developer settings → Personal access tokens. Pick `repo` scope.

## Step 4: Configure Your Client

**Claude Desktop** — edit `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ppps-github": {
      "command": "python",
      "args": ["path/to/tamrael_github_general.py"]
    }
  }
}
```

**OpenCode** — edit `opencode.json`:
```json
{
  "mcpServers": {
    "ppps-github": {
      "command": "python",
      "args": ["path/to/tamrael_github_general.py"]
    }
  }
}
```

**Replace** `path/to/` with the folder you downloaded.

## Step 5: Restart Your Client

That's it. You're connected.

---

## Test It Works

Ask Claude:
> "List my GitHub repositories"

You should see your repos with security status.

---

## What You Can Do

| Ask Claude To... | Example |
|---|---|
| List projects | "What repos do I have?" |
| Read a file | "Show me README.md in my-project" |
| Create a file | "Create a LICENSE file in my-project" |
| Open an issue | "File a bug for the login bug" |
| Make a release | "Create v1.0 release" |

---

## Troubleshooting

**"Token not found":**
```bash
python secure_config.py setup
```

**"Access denied":**
Your token might not have `repo` scope. Check GitHub settings.

**Claude can't find the server:**
- Check file path in your client's MCP config
- Restart the client
- Run: `python tamrael_github_general.py --help`

**"Received request before initialization was complete" (OpenCode):**
This was a race condition in v2.0.1. Update to v2.1.1+. The fix defers HTTP calls to lazy init so the MCP handshake completes instantly.

---

## What You Just Set Up

- **OS keyring** — your token stays encrypted, visible only to you
- **Repository whitelisting** — controls which repos the AI can see
- **Security levels** — strict, standard (default), or open
- **Audit logging** — optional, keeps a tamper-proof record of access

---

## Want More Control?

```bash
# Strict mode — read-only, manual allowlist
python tamrael_github_general.py --security-level strict --allowed-repos "my-project"

# Open mode — full access (development)
python tamrael_github_general.py --security-level open
```

See `README.md` for the full guide.

---

---

## File Manifest

These 4 files go in the same folder on your machine:

| File | Role |
|---|---|
| `tamrael_github_general.py` | Main MCP server — runs the show |
| `secure_config.py` | Handles your token (encrypted, never logged) |
| `security_validators.py` | Checks every input for attacks |
| `overkill_audit_logger.py` | Optional — tamper-proof audit trail |

---

_This project is End of Life after v2.1.0. Replaced by a Rust GitLab MCP server._