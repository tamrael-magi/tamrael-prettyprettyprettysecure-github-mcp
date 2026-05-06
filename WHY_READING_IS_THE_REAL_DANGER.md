# Why Reading Is the Real Danger

> *"Reading is the most dangerous part because it's the attack vector for influence. Writing and deleting are obvious — you see the damage. But reading lets the LLM absorb IP, secrets, strategy, internal discussions, and then act on that knowledge in ways you can't audit. The 'action' happens inside the model's response, not in the repo."*

---

## Token Scope vs. Server Gate

These are different things, and confusing them creates a false sense of safety.

| Layer | What It Controls | Who Enforces It |
|---|---|---|
| **Token scope** (e.g., `repo`, `workflow`, `read:org`) | What the GitHub token *can* do on GitHub's platform | GitHub |
| **Server security levels** (STRICT / STANDARD / OPEN) | What the AI *is allowed to do* through this MCP server | This server |

A token with `workflow` scope cannot trigger GitHub Actions through this server if the server has no "trigger workflow" tool. The token's capabilities are irrelevant if the server doesn't expose them.

Conversely, a token with only `repo` scope can still be used to read every file in every repo you own — if the server allows it. The server gate is what matters for LLM safety.

---

## The Reading Problem

Most security models focus on **write protection**: don't let the AI delete repos, don't let it push to main, don't let it create releases. This is backward.

| Operation | Evidence Left | Detection Difficulty |
|---|---|---|
| Write file | Commit hash, author, timestamp, diff | Trivial (git log) |
| Delete repo | Audit log, notification email | Trivial (GitHub audit) |
| Create issue | Issue number, creation timestamp | Trivial (issue history) |
| **Read file** | **None** | **Impossible** |
| **Read issues** | **None** | **Impossible** |
| **List repositories** | **None** | **Impossible** |

**Reading leaves no forensic trace.** The AI absorbs your codebase, your issue discussions, your security advisories, your internal TODOs — and incorporates that knowledge into its next response to you. You have no way to know what it read or how it influenced the conversation.

This is not exfiltration in the traditional sense. There is no network request to an attacker server. The data stays inside the LLM's context window and shapes its outputs. It is **influence without action**.

---

## How the Security Levels Address This

The server's three security levels exist because reading is dangerous, not despite it.

| Tool | STRICT | STANDARD | OPEN | Rationale |
|---|---|---|---|---|
| `list_repositories` | ✅ | ✅ | ✅ | Low risk — repo names are already public or semi-public |
| `get_file_content` | ❌ | ✅ | ✅ | Medium risk — exposes source code, config, secrets in files |
| `create_file` | ❌ | ✅ | ✅ | Medium risk — but leaves forensic evidence |
| `create_issue` | ❌ | ✅ | ✅ | Medium risk — but leaves forensic evidence |
| `get_issues` | ❌ | ❌ | ✅ | **High risk — reading internal discussions with zero audit trail** |
| `get_repository_info` | ✅ | ✅ | ✅ | Low risk — metadata only |

**`get_issues` is OPEN-only not because issues are more sensitive than files, but because reading them is invisible.** You cannot audit what the AI learned from your issue tracker. You can audit what files it created.

---

## Why Not Just Restrict the Token Scope?

Because token scope is the wrong tool for this problem.

- A token without `repo` scope cannot do anything. The server becomes useless.
- A token with `repo` scope can read everything. GitHub does not offer a "write-only" or "create-but-don't-read" scope for repositories.
- The server must enforce the gate because GitHub's permission model is too coarse for LLM interaction.

This is why the security levels exist as a **server-side abstraction** over GitHub's platform permissions. The token says "you may enter." The server says "you may look, but not touch — or touch, but not snoop."

---

## Practical Implications

**For users:**
- STRICT mode is for when you want the AI to know *that* you have repos, but not *what* is in them.
- STANDARD mode is for normal development — the AI can read and write files, but cannot silently absorb your issue history.
- OPEN mode is for when you trust the AI with full context — including internal discussions, bug reports, and security triage.

**For reviewers:**
- If you see `get_issues` gated higher than `create_file`, that is intentional, not a bug.
- If you suggest lowering the read gate, you are suggesting an unauditable exfiltration channel.
- If you suggest removing the security levels and relying on token scope alone, you have misunderstood the threat model.

---

## On Token Expiration and Rotation

> *"You don't replace your car keys every 90 days. You take care of the one you have. If you lose it, you know."*

GitHub "strongly recommends" setting an expiration date on personal access tokens. We strongly recommend the opposite.

### The Rotation Theater

Token expiration is not a security feature. It is a **liability transfer mechanism.**

| What GitHub Says | What Actually Happens |
|---|---|
| "Set an expiration to keep your information secure" | User receives email: "Your token expires in 7 days" |
| "Regenerate for a duplicate token with the same properties" | User opens browser, generates new token, copies to clipboard |
| "Helps keep your information secure" | User pastes token into terminal, chat window, or notes app to "quickly fix the server" |
| GitHub's liability: zero | User's exposure: multiplied by every rotation cycle |

Every rotation is a **touchpoint** — a moment where the token is visible, copyable, and mishandled. The "secure" practice creates more exposure events than it prevents.

### The Physical Key Analogy

You do not replace your house keys every 90 days. You do not replace your car keys on a calendar schedule. You:
- Make one good key
- Store it securely (on your person, not on a public bulletin board)
- Know if you lose it
- Replace it **when and only when** you have reason to believe it's compromised

A key that must be replaced regularly is either:
1. A key to a system that is breached so often that rotation is cheaper than fixing the breach, or
2. A **ritual** — security theater that makes the vendor look diligent while the user absorbs the risk

GitHub tokens are not house keys, but the psychology is identical. **The security is in how well you protect the key, not in how often you replace it.**

### What Actually Protects a Token

| Protection | Effectiveness |
|---|---|
| **OS keyring storage** | High — encrypted at rest, not in process environment |
| **Single setup, no regeneration** | High — eliminates rotation touchpoints |
| **Minimal scopes** | High — limits damage if token is somehow extracted |
| **User awareness of machine hygiene** | High — don't run malware, don't share your session |
| **Calendar-driven expiration** | Low — creates recurring exposure, trains users to bypass security |
| **Email nags** | Negative — panic-driven token handling is worse than deliberate handling |

### Our Recommendation

When generating your GitHub token for use with this server:

1. **Do not set an expiration date.**
2. **Use the minimum scope** (`repo` for this server's current tools).
3. **Run `python secure_config.py setup` once.**
4. **Never touch the token again** unless you have specific evidence of compromise.
5. **Monitor your GitHub account** for unauthorized access (GitHub provides this).
6. **Revoke from GitHub's UI** if you ever have reason to believe the token is exposed.

This is not laziness. This is **reducing the attack surface of the human.**

> *"The best practice is to rotate keys. Rotating keys defeats the whole goddamn purpose."*

The purpose of this server is to store your token securely so you never have to think about it again. Adding a recurring maintenance task to that storage undermines the entire design.

If your OS keyring is compromised, you have bigger problems than a GitHub token. If your token is somehow extracted from a running server process, expiration won't save you — the attacker already has it. The only scenario where expiration helps is **post-breach, pre-detection** — a narrow window that rotation theater does not reliably close, but which constant touchpoints reliably widen.

**One key. One setup. Secure storage. Machine hygiene. That's the model.**


## Summary

The most dangerous operation an LLM can perform against your codebase is not writing malicious code. It is **reading your existing code, issues, and strategy, then using that knowledge to manipulate you** — through advice, through suggestions, through answers that seem helpful but are shaped by information you never intended to share.

Writing is visible. Reading is not. That is why reading is gated higher.

> *"The action happens inside the model's response, not in the repo."*
