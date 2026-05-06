# Security Policy

> *"The password isn't dead — the industry's willingness to trust users with anything local is."*

---

## Threat Model: What We Actually Protect Against

This server was built on a simple observation: **most credential compromises are opportunistic, not targeted.** Malware scans for low-hanging fruit. CI systems dump environment variables into logs by default. LLMs with tool access read `os.environ` because it's there.

We do not claim to defeat a nation-state adversary with root access to your machine. We claim to **remove your token from the places where opportunistic harvesting happens.**

### What Keyring Storage Protects Against

| Threat | Environment Variable | OS Keyring |
|---|---|---|
| Shell history leakage (`.bash_history`, `.zsh_history`) | ❌ Exposed | ✅ Protected |
| CI/CD log dumps | ❌ Exposed | ✅ Protected |
| Child process inheritance | ❌ Automatic | ✅ None |
| Process enumeration (`/proc/*/environ`, `ps e`) | ❌ Trivial | ✅ Not present |
| LLM tool use scanning `os.environ` | ❌ Trivial | ✅ Not present |
| Opportunistic malware (env scanners) | ❌ Common target | ✅ Bypassed |
| Memory dump of running server | ⚠️ Possible | ⚠️ Possible |
| Malware with keyring library access | ❌ N/A | ⚠️ Targeted only |
| OS-level compromise (root/admin) | ❌ Game over | ❌ Game over |

**Keyring raises the bar from "trivial" to "targeted."** That is the win.

### What Keyring Does *Not* Protect Against

- **Memory forensics**: The token is decrypted into RAM while the server runs. A sophisticated attacker with memory access can extract it.
- **Malware specifically targeting this application**: If malware knows the service name (`ppps-github-mcp`) and your username, it can query the same keyring API we do. This requires targeting, not opportunism.
- **OS compromise**: If your machine is rooted, the keyring is accessible. At that point, your GitHub token is the least of your concerns.

> *"Wrong question. The right question is: 'Who can take it, and how hard is it?'"*

---

## Why No Environment Variables?

The industry has spent a decade making environment variables the default credential path. This was a mistake.

### The Convenience Trap

Modern CI/CD pipelines are credential-dense environments. Tokens for cloud providers, package registries, version control systems, and deployment targets are routinely present in pipeline execution contexts. This makes CI/CD infrastructure a high-value target.

Two converging trends make credential exposure acutely dangerous:

**1. Supply-chain worms operationalize CI/CD as a propagation vector.**

The Shai-Hulud / CanisterWorm family of npm supply-chain malware demonstrates the pattern:
- Infects packages via `preinstall` scripts
- Harvests credentials from environment variables, config files, and cloud metadata services
- Uses harvested tokens to infect all packages owned by the victim
- Exfiltrates stolen data to attacker-controlled repositories
- Implements a **dead man's switch**: if exfiltration channels are severed, triggers local data destruction

The malware also **repurposed TruffleHog** — a legitimate secret-scanning tool — as its filesystem harvesting payload, scanning the victim's home directory for credentials. This is a direct example of surveillance-layer tooling being weaponized against defenders.

**2. AI coding assistants expand the attack surface for prompt injection into pipeline execution.**

Hidden instructions in repository content (merge request descriptions, code comments, README files) can redirect AI assistant behavior. Since pipeline definitions are YAML files in the repository, and AI assistants can generate and commit YAML, an attacker who can inject instructions into any content the AI processes can potentially modify CI configurations to expose secrets.

### The Design Choice

By storing tokens exclusively in the OS keyring, we remove the token from the process environment entirely. The token is retrieved via OS-specific encrypted storage and held only in memory via `PrivateAttr`, excluded from all serialization.

This is **intentional friction.** If your keyring service is broken, fix your keyring service. We do not provide workarounds that degrade the security model.

> *"The whole 'just use SSO / OAuth / passkeys' shift has been a massive convenience grab that externalized risk onto users and centralized control into a handful of identity providers."*

---

## Why Persistent Tokens (No Short-Lived Rotation)

We do not implement token rotation or short-lived tokens.

**Short-lived tokens create ongoing touchpoints where security degrades:**
- Users forget the keyring workflow
- Users paste tokens into chat windows "just this once" to fix an expired token
- Users disable rotation because it's annoying
- Users write refresh scripts with worse security than the original setup

**Our philosophy: validate hard once, store securely, never touch again.**

- `secure_config.py setup` performs live API validation before storage
- Token is validated for correct OAuth scopes
- Token is stored in OS keyring
- Server retrieves it from keyring on each startup
- No refresh logic, no expiry timers, no maintenance theater

If compromise happens, GitHub provides revocation. The user revokes once, from GitHub's UI. The only reason to touch the token again is **incident response**, not **calendar-driven rotation.**

> *"If the keyring is compromised, the user was compromised. If the token is not revoked, that's on the vendor — and at least there is a separation between the user and the vendor."*

---

## Separation of Responsibility

| Layer | Owner | Responsibility |
|---|---|---|
| **User's machine / OS** | User | Keep the OS clean, don't run malware, maintain keyring service |
| **Token storage & retrieval** | This server | Store in keyring, never expose to env/serialization, fail closed |
| **Token validation at setup** | This server + GitHub API | Verify token works, verify scopes, reject broken tokens |
| **Token revocation** | GitHub (vendor) | Provide UI to revoke, audit access logs, respond to breaches |
| **Token scope enforcement** | This server | Request minimal scopes, validate permissions, fail on insufficient access |

If GitHub gets breached and tokens leak, GitHub revokes. That is their job.
If your machine is rooted, we cannot help you. That is your job.
The token itself is protected in the space between.

---

## No Fallbacks, No Workarounds

This server requires a working OS keyring. There is no env var fallback. There is no "paste it into the config" option. There is no `--insecure` flag.

If your keyring is broken:
- **macOS**: Open Keychain Access, ensure it's unlocked
- **Linux**: `sudo apt install gnome-keyring` or ensure `secret-service` backend is running
- **Windows**: Check Services → Credential Manager

If you cannot fix your keyring, this server will not run on your system. This is by design.

---

## Vulnerability Reporting

Found a security issue? Please report responsibly:

1. **Do NOT** create public issues for security vulnerabilities
2. **Email**: ops@tamrael.com with subject "PPPS Security Issue"
3. **Include**: Steps to reproduce, impact assessment, suggested fixes
4. **Response**: When we feel like it. Depends on severity.

See [SECURITY_POLICY.md](SECURITY_POLICY.md) for full disclosure policy.

---

## Honest Assessment

We do not claim this is unbreakable. We claim it is **pretty, pretty, pretty secure** — which is to say, more secure than the default, and honest about its limits.

> *"Because everyone else calls their stuff 'military-grade' and 'enterprise-ready' like they're selling tactical toilet paper."*

The token that never moves after setup is the token that never gets leaked in a paste, a screenshot, or a chat log. Fewer touchpoints. Less human error. Clean boundaries.

That is the design.
