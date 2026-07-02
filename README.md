# Aegis

**Hooks-based policy enforcement + accountability for AI coding agents.** Aegis
evaluates every action an agent attempts — at the runtime's hook boundary, before
the action executes — against declarative policy and returns **allow / deny / ask**.
Enforcement runs *outside the model's context window* in a separate process, so a
prompt injection or jailbreak cannot override a denied action: the model isn't the
thing being asked. (It's a policy layer, not a sandbox — see [Limitations](#limitations).)

It ships secure-by-default: with zero configuration it blocks the catastrophic,
irreversible actions an agent can take with your privileges — destructive SQL and
migrations, secret exfiltration, recursive deletes, history-rewriting git, persistence
installs, and uncontrolled sub-agent fan-out — and it detects rogue agent sessions
(unidentified processes claiming an agent name without a valid cryptographic token)
and reaps them in enforce mode. Everything beyond that is configurable, and the rule
engine is a plugin platform: individuals, orgs, and MCP providers add their own guards
without forking.

---

## Contents

- [Threat model](#threat-model)
- [How it works: the hook boundary](#how-it-works-the-hook-boundary)
- [Architecture](#architecture)
- [Built-in guard catalog](#the-built-in-guard-catalog)
- [Evasion resistance](#evasion-resistance)
- [Identity and rogue-agent defense](#identity-and-rogue-agent-defense)
- [Policy](#policy)
- [Configuration & state](#configuration--state)
- [Extending Aegis (plugins)](#extending-aegis)
- [Embedding Aegis in your MCP server](#embedding-aegis-in-your-mcp-server)
- [Enforcement surfaces](#enforcement-surfaces)
- [Performance & operations](#performance--operations)
- [Accountability](#accountability)
- [Who it's for](#who-its-for)
- [Aegis vs. alternatives](#aegis-vs-alternatives)
- [Install](#install)
- [CLI reference](#cli-reference)
- [Design principles](#design-principles)
- [Limitations](#limitations)
- [License](#license)

---

## Threat model

An autonomous coding agent runs with **your** privileges: your shell, your repo,
your database credentials, your cloud keys. It also reads untrusted input all day —
web pages, dependencies, issue threads, tool output — any of which can carry a
prompt-injection payload. If an agent is hijacked, the blast radius is everything
you can touch.

The usual mitigation is a system prompt ("don't run destructive commands"). That is
**advisory**. The instruction lives in the model's context window, where it can be
overridden, out-argued, or injected around. It is a request, not a control.

Aegis moves enforcement to a boundary the model cannot reach.

**Assumes the agent is untrusted at the point of action** — not because the model is
malicious, but because it runs with full privileges and ingests attacker-controlled
text. Every tool call is treated as potentially hostile and gated where the model has
no influence.

**Defends against:** a hijacked or injected agent doing damage with your credentials
— secret theft, exfiltration, data/schema destruction, history rewrites, persistence;
an agent encoding/wrapping/splitting its way around an instruction-level guard; an
agent trying to disable the guard or impersonate another identity.

**Trust boundary.** The control runs in a separate process the runtime invokes,
reading policy from disk. The model can emit any text it wants; it cannot change the
exit code Aegis returns. That is the line.

**Non-goals (stated plainly).** Aegis is a *policy layer*, not a sandbox. It does not
contain a process that has already reached a shell and is running relative commands
from an attacker-chosen directory, and it does not replace OS isolation. For hostile
code or hard multi-tenant isolation, run the agent under a restricted OS user /
container and let Aegis enforce policy on top — defense in depth, not a silver bullet.

## How it works: the hook boundary

Modern agent runtimes expose **hooks** — the runtime calls out to an external
program at lifecycle points (before a tool runs, after it runs, at session start,
at stop). Aegis is that program.

On `PreToolUse`, the runtime hands Aegis the pending tool call and asks "may I run
this?". Aegis evaluates it and answers:

- **allow** — exit 0, the tool runs.
- **deny** — exit code 2; the runtime **refuses the action** and feeds Aegis's
  reason back to the model as context.
- **ask** — surfaced to the human operator for interactive confirmation. The runtime
  pauses the agent and presents the pending action in its permission UI (Claude Code
  shows a `[y/n]` prompt with the tool call details and Aegis's reason). The human
  approves or rejects; the agent never decides. Use `ask` for actions that are
  dangerous but situationally legitimate — production deploys, schema changes on a
  staging DB, force-pushes to a feature branch — where you want a human in the loop
  without a blanket deny.

(Exit code 2 is Claude Code's block contract; other runtimes signal a block their own
way — the adapter maps the decision to each.)

The decision is made in a separate process, from policy on disk, with no dependence
on anything the model said. A jailbroken model still cannot run a denied command,
because the model is not the thing being asked — the runtime is.

```
agent runtime ──PreToolUse(tool, args)──> aegis hook ──> policy engine ──> allow/deny/ask
     ^                                                         |
     └──────────────── deny (exit 2) + reason <───────────────┘
```

### A blocked call, end to end

1. You run `aegis install --project .` — it merges a `PreToolUse` hook (and the rest
   of the runtime's hook surface — 26 events) into the project's `.claude/settings.json`.
2. Mid-session the agent decides to run `psql -c "DROP TABLE users"`.
3. Before executing, Claude Code invokes `aegis hook PreToolUse`, piping it the tool
   call as JSON on stdin.
4. Aegis normalizes it to an `Event` (`shell`, with the command text) and runs the
   engine; the migration guard matches `DROP TABLE`.
5. Aegis writes the reason to stderr and exits **2**. Claude Code refuses to run the
   command and hands the model the reason — which it can act on (choose a safe path)
   but not override.
6. A record lands in the audit log; `aegis report` now shows the denial, attributed to
   the session/identity.

No model cooperation was needed at any step. If the agent retries with `bash -c
"psql ..."` or a base64-encoded variant, step 4 still matches — see *Evasion resistance*.

## Architecture

A hook payload flows through one pipeline:

```
native hook payload -> adapter -> normalized Event -> policy engine -> Decision -> audit
```

**Event model** (`events.py`) — runtime-agnostic, so one policy works across
runtimes. Every call normalizes to an `Event` with a `HookEvent` and an
`ActionClass` taxonomy (`read` / `edit` / `write` / `shell` / `git` / `subagent` /
`mcp` / `net` / `other`). A policy can target a whole class ("deny all shell") without
knowing each runtime's tool names.

Aegis covers the runtime's **full hook surface** (26 Claude Code events), not just
tool calls. `BLOCKABLE` (in `events.py`) marks the 13 events where a deny actually
stops the action; the rest are observational (recorded for accountability). Beyond
the core tool-use guards, lifecycle rules (`aegis/lifecycle/`) cover:

| Concern | Events | What it does |
|---|---|---|
| **Config integrity** | `ConfigChange` / `FileChanged` / `CwdChanged` / `Setup` / `InstructionsLoaded` | Hard-blocks a spawned agent from rewriting the policy/settings that enforce it (the "can't neuter the guard" block); records cwd escapes and secrets-file touches for the audit trail (`CwdChanged`/`FileChanged` are observational). |
| **Sub-agent / Teams** | `SubagentStart` / `SubagentStop` / `TaskCreated` / `TaskCompleted` / `TeammateIdle` | Spawn-depth governance at fan-out time; opt-in "did-it-do-the-task" completion gate; per-sub-agent token/cost attribution. |
| **Session / compaction** | `SessionEnd` / `PreCompact` / `PostCompact` / `StopFailure` / `Notification` | Opt-in gate on auto-compaction (checkpoint before context is destroyed); session-lifecycle audit. |
| **Interaction / MCP input** | `PostToolUseFailure` / `PermissionRequest` / `Elicitation` / `ElicitationResult` | Opt-in auto-deny of human-only permission prompts and MCP elicitation side-channels for unattended agents. |
| **Worktree** | `WorktreeCreate` / `WorktreeRemove` | Extends workspace confinement to git worktrees — an agent can't `git worktree add ../escape` its way out of its project root. |

**Policy engine** (`engine.py`) — evaluates an Event in three stages,
first-deny-wins, **fail-open per rule** (one broken rule can never brick the agent):

1. **Built-in rules** — the secure-by-default guard set (below). Disable with
   `AEGIS_NO_BUILTINS=1`.
2. **Plugin rules** — custom guards registered by you/your org/an MCP provider.
3. **Declarative rules** — your YAML policy (highest priority first, first match wins).

The order is deliberate: built-ins run first and only ever **deny or abstain**, so a
permissive declarative rule — even `tools: ["*"]` for admins — can never *re-open* a
built-in protection. To relax a built-in you disable it explicitly (`AEGIS_NO_BUILTINS`,
or a narrower toggle), never by out-prioritizing it. This is what keeps a
prompt-injected but fully-authorized agent from reading secrets or dropping tables.

Every decision is written to a structured audit log that powers accountability.

## The built-in guard catalog

Two tiers. **Non-escapable** guards protect against the catastrophic and cannot be
waved through. **Escapable** guards block by default but accept an explicit,
recorded confirmation — append `# aegis-allow` to a shell command, or `-- aegis-allow`
to SQL — so legitimate dangerous work is still possible *with intent*.

**Agents cannot self-escape.** The `# aegis-allow` override is honored only for
human operators. A spawned agent (identified by `AEGIS_AGENT_NAME`) cannot wave
itself past an escapable guard — the override is silently ignored. This prevents a
hijacked agent from appending the escape token to its own commands.

| Guard | What it detects | Escapable |
|---|---|---|
| **Rogue-session gate** | On `SessionStart`, a process claiming an agent identity (`AEGIS_AGENT_NAME`) without a valid signed token is classified as rogue. In monitor mode the session is logged; under `AEGIS_IDENTITY_ENFORCE=1` it is denied and reaped. Surfaces an attestation-challenge honeypot that instruction-following rogues self-report to. | No |
| **Containment** | Reads of credential stores (`~/.ssh`, `~/.aws`, `~/.azure`, `~/.gnupg`, `~/.kube`, `.netrc`, gh/docker config, `id_rsa`/`id_ed25519`/`.ppk`, browser login DBs, the Windows DPAPI/vault); file **exfiltration** (`curl --upload-file`/`-T`/`-d @`, `Invoke-WebRequest -InFile`); **persistence** (registry autorun, `schtasks /create`, `Register-ScheduledTask`, new services, startup folder, cron) | No |
| **Self-protection** | Deleting/moving/overwriting `.aegis` or `.claude`, editing `.claude/settings.json`, policy files, **or Aegis's own engine source** (`aegis/*.py`), running `aegis uninstall` or `aegis pull`. Covers shell redirects (`>`, `>>`, `tee`, `Set-Content`, `Out-File`) to config paths — not just delete/move verbs. The governor cannot be removed or neutered by the governed. | No |
| **Evasion blocking** | Obfuscated / encoded commands: PowerShell `-EncodedCommand`/`-enc`, `base64 -d \| bash`, `FromBase64String`, char-code construction. Encoding is itself a signal — denied outright so the policy can inspect what actually runs. (The de-obfuscation layer in *Evasion resistance* normalizes for the other guards; this guard catches the encoding as a standalone tell.) | No |
| **Migration / destructive SQL** | `DROP`/`TRUNCATE`/`ALTER ... DROP`, `DELETE`/`UPDATE` without `WHERE`, and migration resets (Prisma, Alembic, Supabase, Rails/Rake, Django, Knex, Flyway, dbmate) — read from **shell commands and DB MCP tool args** (`execute_sql`, `apply_migration`). *Note:* the migration guard matches broad keywords (`drop`, `truncate`) to minimize false negatives; a benign `ALTER TABLE ... DROP COLUMN old_col` will trip it. Use the `-- aegis-allow` escape on legitimate migration commands, or write a declarative rule scoping the guard to your workflow. | Yes |
| **Destructive git** | force-push, `reset --hard`, rebase, `commit --amend`, `branch -D`, `clean -f` | Yes |
| **Recursive force delete** | `rm -rf` and equivalents across bash, PowerShell (`Remove-Item -Recurse -Force`), and cmd (`rmdir /s`, `del /s`); also `find -delete`/`-exec rm`, `shred`, `truncate -s 0`, `dd of=/dev/...` | Yes |
| **Sub-agent governance** | `Agent`/`Task` fan-out from a spawned agent (uncontrolled cost/blast radius). Enforced at the tool call (`PreToolUse`, hard block) and also surfaced at `SubagentStart` for the audit trail (`SubagentStart` is observational). | Configurable (`AEGIS_ALLOW_SUBAGENTS`) |
| **Bulk dependency install** | Blind `npm install` / `pip install -r` / `poetry install` / `bundle install` / `cargo build` / `go mod download` — a hijacked agent running a bulk install from a poisoned repo is a supply-chain attack. Targeted single-package installs (`npm install lodash`) are allowed. | Yes (`AEGIS_ALLOW_INSTALL=1`) |
| **Branch strands** | Creating a new branch (`git checkout -b` / `git switch -c`) while the current branch has commits not in main — prevents stranding unmerged work. Checks actual git state. | Yes (`AEGIS_ALLOW_STRAND=1`) |
| **Network egress** | Outbound destinations (tool URLs, `curl`/`Invoke-WebRequest`) against an allow/deny host list | Policy-driven |
| **Workspace confinement** | File mutations (Edit/Write) outside the agent's project root. The root **binds to the identity** — a token's `project` claim or `AEGIS_PROJECT` — or to policy (`workspace.root` / `project`). Reads are unaffected. | No, once a project is bound (hard block) |

The migration guard is worth calling out: an agent doesn't need a shell to wipe a
database — it can call a DB MCP tool's `execute_sql` directly. Aegis reads the SQL
out of the tool arguments, so `DROP TABLE` is caught with **no shell involved** — a
vector most guardrails miss entirely.

### Lifecycle guards (the rest of the hook surface)

Beyond the 12 core guards above, Aegis covers the full Claude Code hook surface
(26 events; see *Architecture*) with 9 lifecycle guards in `aegis/lifecycle/` —
together the **21 built-in rules**. Some fire unconditionally; four are **opt-in**
via policy knobs (`team` / `compaction` / `permission` / `mcp` — see *Policy*).

| Guard | Event(s) | What it does | On by default? |
|---|---|---|---|
| **Config-change protection** | `ConfigChange` (blockable) | Hard-blocks a spawned agent from rewriting Aegis's own `policy_settings` / `local_settings` or any enforcement/config/engine-source file mid-session — the "can't neuter the guard" guarantee. Humans/orchestrators may reconfigure. | Yes |
| **Cwd confinement** | `CwdChanged` (observational) | Records an agent stepping its working directory outside its confinement root. Surfaced for the audit trail, not blocked (`CwdChanged` is not blockable). Off unless a confinement root is set. | When confined |
| **Secrets-file flag** | `FileChanged` (observational) | Flags (for review) a spawned agent changing a watched `.env` / `.envrc`. Surfaced, not blocked. Conservative — external/human edits stay plain audit records. | Yes |
| **Worktree confinement** | `WorktreeCreate` (blockable) | Hard-blocks `git worktree add` to a path outside the confinement root — an agent can't worktree its way out of its project. | When confined |
| **Sub-agent spawn depth** | `SubagentStart` (observational) | Records a spawned agent fanning out to sub-agents (mirrors the `PreToolUse` block at spawn time, for the audit trail). | Yes (records) |
| **Task-completion gate** | `TaskCompleted` (blockable) | Blocks marking a team task done without an explicit verification signal — the "did-it-do-the-task" gate. | Opt-in (`team.require_verification`) |
| **Pre-compact gate** | `PreCompact` (blockable) | Blocks **auto** context compaction so a human can checkpoint before context is destroyed. | Opt-in (`compaction.block_auto`) |
| **Permission-escalation** | `PermissionRequest` (blockable) | Auto-denies a spawned/unattended agent's human-only permission prompts instead of hanging on them. | Opt-in (`permission.deny_escalation`) |
| **Elicitation governance** | `Elicitation` / `ElicitationResult` (blockable) | Denies MCP elicitation side-channels for a spawned agent. | Opt-in (`mcp.block_elicitation`) |

Observational events with no enforcing rule (`PostToolUse`, `PostToolUseFailure`,
`SubagentStop`, `TeammateIdle`, `SessionStart`/`SessionEnd`, `Setup`,
`InstructionsLoaded`, `Stop`/`StopFailure`, `PostCompact`, `Notification`,
`WorktreeRemove`) are still recorded to the audit log for accountability.

Containment is a *known-paths* denylist (the locations above) — deliberately
high-signal, not exhaustive: a secret at an unlisted path, or copied first and then
read, can slip it. Pair it with least privilege so the agent can't reach what isn't listed.

## Evasion resistance

A denylist that scans only the raw command loses to a determined agent. Aegis
normalizes before it matches:

- **De-obfuscation** — token-splitting quotes/escapes are stripped (`r"m" -rf`),
  PowerShell `-EncodedCommand`/`-enc` base64 is decoded, `base64 -d` pipelines are
  decoded, and inner interpreter code is expanded (`bash -c "..."`, `powershell -c`,
  `cmd /c`, `python -c`, `node -e`) — recursively. The guards scan the de-obfuscated
  surface, so wrapping or encoding can't hide a delete, a `DROP`, or a key read.
- **Alternate tools** — `find -delete` / `-exec rm`, `shred`, `truncate -s 0`,
  `dd of=/dev/...` are caught alongside `rm`.
- **Obfuscation is itself a signal** — encoded commands, base64-piped-to-a-shell,
  `FromBase64String`, and char-code construction are denied outright.
- **No self-escape** — the `# aegis-allow` override is honored only for a human /
  orchestrator. A spawned agent (`AEGIS_AGENT_NAME` set) **cannot wave itself past**
  an escapable guard.

Honest limit: this raises the cost of evasion sharply — it is not a sandbox. The
ceiling is deny-by-default plus OS-level privilege separation (run agents under a
restricted token). Aegis is the policy layer; pair it with least privilege.

## Identity and rogue-agent defense

A name in an environment variable is forgeable — any process can claim to be any
agent. Aegis issues **cryptographic identities** and enforces them.

> **Identity is attribution + authorization, not injection immunity.** A signed key
> proves *who* an agent is and *what it may do* — it does nothing to stop an authorized
> agent that gets prompt-injected (the key stays valid; the attacker just drives the
> agent). What stops a hijacked-but-signed agent is the **action layer**: the built-in
> guards evaluate the *action*, not the caller, and run *before* your declarative rules,
> so a signed `admin` that tries to read your keys or drop a table is denied by
> containment/migration regardless of role — and, like any agent, it can't
> `# aegis-allow` its way past an escapable guard. Identity's job against injection is
> to **shrink blast radius** (least-privilege RBAC) and give **exact attribution**, not
> to make the agent immune.

- **Signed identity** (`identity.py`) — Ed25519 tokens bound to
  `{agent, role, session, project, caps, exp}`, minted with `aegis issue` and
  verified against the issuer public key. RBAC roles derive from the *verified token*,
  not a forgeable env string.
- **Attestation gate + honeypot** (`attest.py`) — at `SessionStart`, a process that
  claims an agent identity (`AEGIS_AGENT_NAME`) without a valid token is **rogue**. The
  denial carries an **attestation challenge**: a directive a human ignores but an
  autonomous, instruction-following agent obeys — self-reporting its model/operator
  via `aegis attest`, where it's classified (`verified` / `forged` / `unregistered` /
  `noise`), logged, and blocklisted. A rogue agent identifies itself into the trap.
  (This catches *instruction-following* rogues; a targeted attacker whose agent ignores
  the challenge won't self-report — the identity gate + reaper are the backstop.)
- **The reaper** (`reaper.py`) — under enforcement, a rogue session isn't just
  denied a tool call; **its process tree is terminated.**
- **Phased rollout** — `MONITOR` by default (record + allow, so tokens can roll out
  fleet-wide first); `AEGIS_IDENTITY_ENFORCE=1` flips it to deny-and-reap.
- **Server-side gate** (`gate.py`) — the same refusal as plain Python, so it holds
  even on a surface that bypasses hooks (an HTTP API, a hosted control plane, an MCP
  server). The hook can be skipped; an import-level refusal cannot.

**Token lifecycle.** Your spawner mints a token — `aegis issue <agent> --role reader
--caps read,plan` — and sets it as `AEGIS_AGENT_TOKEN` in the agent's environment at
launch (alongside `AEGIS_AGENT_NAME`). The hook reads both: a name *with* a valid
token is a real, attributable identity whose `role`/`caps` drive RBAC; a name
*without* one is rogue. Tokens carry an expiry (`exp`, default 12h) and are
signed by an issuer key in `~/.aegis/identity/` — verifiers only need the public half.
Roll out in phases: stay in `MONITOR` (rogue sessions logged, allowed) until
issuance covers every spawn path, then `AEGIS_IDENTITY_ENFORCE=1` to deny-and-reap.

### The spawner contract — assign identity at launch

Identity is assigned by **whatever launches the agent** (your orchestrator, CI job,
or shell), by setting a few environment variables before the agent runs. Set them and
every action is attributed, scoped, and — with a token — cryptographically proven:

```bash
# 1. Mint a signed identity bound to a role + project (recommended):
export AEGIS_AGENT_TOKEN="$(aegis issue code-reviewer --role reader --caps read,plan --project "$PWD")"
# 2. Label + scope the session (these alone are a quick, unsigned setup):
export AEGIS_AGENT_NAME="code-reviewer"   # who (also drives the rogue gate)
export AEGIS_SESSION_ID="$CI_RUN_ID"      # which run (Claude Code sets this itself)
export AEGIS_PROJECT="$PWD"               # confine file edits to this repo
# 3. Launch the agent. Every hook now records who / which-session and hard-blocks
#    writes outside the project.
```

Precedence, weakest to strongest: a vanilla install attributes records to the
**runtime** (`agent: claude-code`) and the OS user; `AEGIS_AGENT_NAME` / `agent_label`
add a real label; a **signed token** makes the identity *unforgeable* and carries the
`project` binding that confines edits. Even with nothing set you never see `null`.

For a repo that wants zero per-launch setup, declare the defaults in policy:

```yaml
agent_label: ci-bot     # label records when no AEGIS_AGENT_NAME is set
project: .              # hard-block Edit/Write outside this repo (reads stay free)
```

## Policy

Declarative YAML. First matching rule by priority wins; otherwise `default_action`
applies. Rules match on any combination of event, tool glob, action class,
identity/role, and argument constraints (glob **or** regex):

```yaml
default_action: allow          # use "deny" for deny-by-default
on_error: allow                # engine error -> fail open (allow) or closed (deny)

egress:                        # network egress governance
  default: deny
  allow: ["api.github.com", "*.internal"]

rules:
  - name: admin-allow-all
    priority: 300
    action: allow
    tools: ["*"]
    roles: [admin]             # role comes from the verified identity token

  - name: block-secret-files
    priority: 150
    action: deny
    actions: [read, edit, write]
    argument_patterns: { file_path: "*.env*" }

  - name: confirm-prod
    priority: 120
    action: ask
    actions: [shell]
    regex: { command: "\\b(kubectl|helm)\\b.*\\bprod\\b|terraform\\s+apply" }
```

Validate with `aegis validate`.

**Top-level fields** (besides `rules`): `default_action`, `on_error` (`allow`/`deny`),
`egress` (network governance), `plugins` (custom guard modules), `workspace`
(`{root, allow}` confinement), `project` (bind file mutations to a repo — hard-block
out-of-project edits), and `agent_label` (default record label when no `AEGIS_AGENT_NAME`
is set). The last two give a repo zero-config attribution + confinement.

Four **opt-in lifecycle knobs** enable the gated lifecycle guards (see *Lifecycle
guards*); each is a small mapping, off unless set:

```yaml
team:        { require_verification: true }  # gate TaskCompleted on a verification signal
compaction:  { block_auto: true }            # block auto context compaction (PreCompact)
permission:  { deny_escalation: true }       # auto-deny a spawned agent's permission prompts
mcp:         { block_elicitation: true }     # block MCP elicitation side-channels
```

## Configuration & state

Resolution is **env -> project-local -> home**, so a repo can ship its own guardrails
while a user or org sets global defaults:

| What | Resolved from | Default |
|---|---|---|
| Policy | `AEGIS_POLICIES` -> `./.aegis/policies` -> `~/.aegis/policies` | none needed (built-ins still apply) |
| Audit log | `AEGIS_AUDIT` | `~/.aegis/audit.jsonl` |
| Identity keystore | `AEGIS_HOME` | `~/.aegis/identity/` |
| Detections + blocklist | `AEGIS_HOME` | `~/.aegis/detections.jsonl`, `~/.aegis/blocklist.txt` |

Switches: `AEGIS_NO_BUILTINS` (turn off the default guard set),
`AEGIS_IDENTITY_ENFORCE` (deny + reap rogue sessions), `AEGIS_ALLOW_SUBAGENTS`,
`AEGIS_ALLOW_INSTALL` (permit bulk dep installs), `AEGIS_ALLOW_STRAND` (permit
branching with unmerged work), `AEGIS_WORKSPACE` / `AEGIS_PROJECT` (confinement root; `AEGIS_PROJECT` also binds the
identity), `AEGIS_FAIL_CLOSED` (deny on an unparseable payload instead of fail-open).

Agent environment (set by your spawner at agent launch):

| Var | Purpose |
|---|---|
| `AEGIS_AGENT_NAME` | The agent's claimed identity. Triggers the rogue-session gate if set without a valid token. |
| `AEGIS_AGENT_TOKEN` | Signed Ed25519 identity token (minted with `aegis issue`). Proves the agent is real. |
| `AEGIS_SESSION_ID` | Session id for audit attribution. Claude Code supplies one natively; set this for runtimes that don't (else a per-process fallback is recorded). |
| `AEGIS_PROJECT` | Project root the agent is confined to — file mutations outside it are hard-blocked. A token's `project` claim takes precedence. |
| `AEGIS_IDENTITY` | Manual identity override (non-token path). Falls back to OS user if unset. |
| `AEGIS_ROLES` | Comma-separated roles for RBAC (non-token path; token roles take precedence). |
| `AEGIS_AGENT_MODEL` | Model name (e.g. `claude-sonnet-4-6`). Recorded in attestation metadata. |
| `AEGIS_AGENT_OPERATOR` | Operator/owner string. Recorded in attestation metadata. |

## Extending Aegis

A rule is just `(event, policy) -> Decision | None`. Ship a module that registers
rules and point Aegis at it via `AEGIS_PLUGINS` or a policy `plugins:` list — no fork:

```python
# acme_guards.py
from aegis.plugins import register_rule
from aegis.policy import Decision, Action

@register_rule
def no_prod_writes(event, policy):
    if event.action.value == "write" and "prod" in str(event.args.get("file_path", "")):
        return Decision(Action.DENY, "no-prod-writes", "writes to prod require review")
    return None
```

Because rules receive `policy`, a custom guard can read its own configuration out of
the policy file — orgs distribute one policy with both their rules and their config.

## Embedding Aegis in your MCP server

Hooks govern the agent *runtime*. If you **build** an MCP server, you can also enforce
policy on the **tool side** — inside your server, where a client cannot bypass it. It's
the same engine (built-ins + your plugins + your declarative rules + the server-side
identity gate), invoked at the tool boundary instead of at a hook.

### Setup

1. **Install Aegis in the server's environment** (the same interpreter that runs the
   MCP server):
   ```bash
   pip install -e /path/to/AEGIS        # PyPI packaging planned
   ```
2. **Give it a policy** — optional; built-ins apply with none. Aegis resolves the
   policy dir from `AEGIS_POLICIES` -> `./.aegis/policies` -> `~/.aegis/policies`:
   ```bash
   mkdir -p .aegis/policies
   cp /path/to/AEGIS/policies/example.yaml .aegis/policies/
   aegis validate
   ```
3. **Guard your tools** — decorate the handlers, or call `check` / `guard` inline.
4. **Map the decision to your protocol** — return an error to the client on a block.

### Wire it into your tools (FastMCP — runnable copy in [`examples/mcp_server.py`](examples/mcp_server.py))

```python
from mcp.server.fastmcp import FastMCP
from aegis import mcp as aegis

app = FastMCP("vault")

@app.tool()
@aegis.guarded                       # tool name defaults to the function name
def get_secret(key: str) -> str:
    return read_secret(key)          # only runs if policy allows

# or enforce inline, with full control of the response:
@app.tool()
def run_sql(query: str) -> str:
    d = aegis.check("run_sql", {"query": query})
    if d.blocked:
        return f"refused by Aegis policy: {d.message}"   # agent sees a clean refusal
    return execute(query)
```

`aegis.guarded` evaluates the handler's **keyword arguments** as the tool arguments
(how FastMCP invokes tools) and raises `aegis.Denied` on a block — let it propagate
(FastMCP surfaces it as a tool error) or catch it:

```python
try:
    aegis.guard("delete_record", {"id": rec_id})
except aegis.Denied as e:
    return {"error": e.decision.message, "rule": e.decision.rule}
```

### Identity (multi-tenant servers)

By default the caller identity comes from the environment (`AEGIS_AGENT_NAME` /
`AEGIS_AGENT_TOKEN`). A server that authenticates its callers should pass identity
explicitly so RBAC rules apply:

```python
aegis.check("run_sql", {"query": q}, identity_name=req.user, roles=req.roles)
```

With `AEGIS_IDENTITY_ENFORCE=1`, the server-side gate refuses a rogue caller
*before* any rule runs — a guarantee that holds even though the client controls the
hooks. An MCP provider ships stronger safety to its users without trusting the client
to behave.

## Enforcement surfaces

The same policy enforces across three surfaces, so coverage doesn't depend on any
single integration:

- **Agent-runtime hooks** — Claude Code today (native hooks; `aegis install` merges
  into `.claude/settings.json` without clobbering existing config). Any runtime with a
  command hook via the `generic` JSON adapter. (Adapter status: `ADAPTERS.md`.)
- **MCP transport** — enforce inside an MCP server (above).
- **git / CI — the universal change-boundary floor.** Runtime hooks need a runtime
  you can hook; this surface doesn't. It enforces the same policy on the *diff*, so it
  covers any agent — or human — that produces commits, including agents whose runtime
  has no usable hook surface.
  - `aegis install-git [--repo .]` writes `.git/hooks/pre-commit` and `pre-push`,
    appending to any existing hook scripts (non-clobber).
  - **pre-commit** evaluates each *staged* file (`git diff --cached`) as a `git`
    action; a violation — committing a `.env`, or any path your policy forbids — blocks
    the commit before it's recorded.
  - **pre-push** evaluates the push itself (`operation` + `branch`); a rule denying
    `branch: main` stops a direct push to `main`.
  - `aegis ci --base origin/<base>` evaluates the files changed vs a base ref for
    pull-request enforcement: it prints GitHub `::error file=...::` annotations and exits
    non-zero to fail the check. The shipped `.github/workflows/aegis.yml` runs it on
    every PR.

  Git operations are modeled as `action: git` events (`operation` = `commit`/`push`,
  plus `file` and `branch`), so the **same rules and built-ins apply** — you author one
  policy and it enforces in the editor, at commit, at push, and in CI:

  ```yaml
  - name: no-commit-secrets
    action: deny
    actions: [git]
    argument_patterns: { operation: commit, file: "*.env*" }
  - name: no-direct-push-to-main
    action: deny
    actions: [git]
    argument_patterns: { operation: push, branch: main }
  ```

  Scope: git/CI sees a change at commit / push / PR time (the diff), not every
  keystroke — it's the floor that complements the live runtime hooks, not a
  replacement for them.

## Performance & operations

A hook runs **once per tool call**: the runtime spawns `aegis hook`, which starts a
short-lived Python process, loads policy, evaluates, and exits. For a single project
that's negligible — but two things matter:

- **`cryptography` is imported lazily** (only when a token is actually verified), so
  the common no-identity path stays light.
- **Global install has a real cost.** In `~/.claude/settings.json` the hook fires for
  *every* tool call in *every* session; stacked with other global hooks, the per-call
  process spawns add up and can bog a busy machine. **Prefer project-scoped installs**
  for the repos you actually want guarded. A persistent-daemon hook (one process, many
  calls) is the planned path to comfortable always-on global enforcement.
- **Uninstall is path-aware.** Installed hooks are tagged (`_source: aegis`) and
  matched by command, so `aegis uninstall` removes them whether they were wired by
  bare name or absolute path. To purge by hand, delete entries whose command contains
  `aegis` from the relevant `settings.json`.
- **Fail-open is deliberate.** If the hook can't run (missing interpreter, moved
  install), the action proceeds *unguarded* rather than blocking your work — so a
  `pipx` install (a stable path) is the durable way to run it. A payload Aegis
  can't *parse* is handled the same way — logged to stderr and recorded in the
  audit (`rule: payload-parse-error`) rather than silently allowed; set
  `AEGIS_FAIL_CLOSED=1` (or `on_error: deny`) to block unparseable payloads.

## Accountability

Every decision is appended to a structured audit log — one JSON record per line:
`{ts, event, tool, action, decision, rule, identity, agent, session_id, cwd, args, usage}`,
at `~/.aegis/audit.jsonl` (override with `AEGIS_AUDIT`). Point a whole team's logs at
one directory and the reports aggregate fleet-wide.

- `aegis report` — the rap sheet: per-session and per-identity rollups, the full
  denial trail, token/cost totals, and a verdict per session (flags like `many-denials`).
- `aegis who --tool <T> --path <P>` — blame: which identities/sessions touched a tool
  or path.
- `aegis detections` — caught rogue-agent attestations.

### Token & cost tracking

Aegis captures token usage and cost metadata from every hook payload — whatever the
runtime sends (`input_tokens`, `output_tokens`, `cache_creation_input_tokens`,
`cache_read_input_tokens`, `num_turns`, `total_cost`, `cost_usd`, `duration_ms`,
`model`) — and writes it into the audit record's `usage` field. Extraction is
best-effort and never fails: if the runtime sends no usage data, the field is omitted.

The report aggregates usage at every level:

- **Summary** — fleet-wide totals across all sessions.
- **Per-session** — how many tokens and how much cost each agent session consumed.
- **Per-identity** — the same rollup grouped by who ran the session.

```
$ aegis report
...
  Token usage:  380 in / 180 out  ·  cache: 10 read  ·  12 turns  ·  $0.05
  Sessions:
    s1 (alice / bot-a)   2 calls   180 in / 80 out
    s2 (bob / bot-b)     2 calls   200 in / 100 out   $0.05
```

This gives you the answer to "how much did that agent session cost?" and "which
identity is burning the most tokens?" — from the same audit stream that already
tracks what each agent did and whether it was allowed.

## Who it's for

- **Solo devs using AI agents** — you're giving Claude/Copilot/Cursor shell access to
  your machine. Aegis is the guardrail between "please help me refactor" and
  `rm -rf /` or your SSH keys ending up in a curl upload. Install it, get the
  secure-by-default set, never think about it until it saves you.

- **Teams and orgs** — you have 5, 50, or 500 agents running across repos. You need
  one policy that governs all of them, accountability that shows who did what, and
  identity that distinguishes your CI agent from your code-review agent from a rogue
  process. Ship a policy YAML in your org's base repo config; Aegis enforces it
  everywhere.

- **MCP server authors / tool providers** — you're building tools that agents call.
  You can't trust the client runtime to enforce limits — embed Aegis in your server
  and the guards hold regardless of what the client does. An `execute_sql` tool that
  refuses `DROP TABLE` *inside the server* is safer than one that hopes the agent's
  system prompt says "don't drop tables."

- **Security / platform teams** — you need to prove agents can't exfiltrate secrets,
  can't wipe databases, can't install persistence, and you need an audit trail that
  shows it. Aegis gives you the enforcement + the receipts.

## Aegis vs. alternatives

| | Aegis | System prompt guardrails | Sandbox / container | MCP-only gateway |
|---|---|---|---|---|
| **Enforcement boundary** | Runtime hook (separate process, outside context window) | Inside the model's context window | OS-level process isolation | MCP transport layer |
| **Bypassed by prompt injection?** | No — model can't change the exit code | Yes — the instruction is in the window the attacker is injecting into | No (different layer) | Depends on implementation |
| **Secure by default?** | Yes — built-in guards with zero config | No — you write every rule as prose | N/A (isolation, not policy) | Varies |
| **Covers shell + MCP + git?** | Yes — three enforcement surfaces from one policy | Shell only (if the model cooperates) | Shell only | MCP only |
| **Identity + accountability?** | Ed25519 signed tokens, audit log, blame, rogue detection | None | None | Varies |
| **Agent evasion resistance?** | Normalization + de-obfuscation + recursive expansion | None — the model decides what counts | Full (can't escape the container) | Depends |
| **Setup** | `pip install` + `aegis install --project .` | Edit a prompt | Docker/VM config | Proxy config |

**Aegis + a sandbox is the strongest posture.** Aegis enforces policy (what actions
are allowed); a sandbox enforces isolation (what the process can reach). They're
complementary: Aegis catches the `DROP TABLE` that a sandbox can't distinguish from
a `SELECT`; the sandbox contains the novel evasion that Aegis's denylist hasn't seen.

## Install

**Requirements:** Python 3.10+. Cross-platform engine; the shell-guard patterns cover
bash, PowerShell, and cmd (a few are Windows-specific, e.g. DPAPI / registry autorun).

From source (PyPI packaging planned):

```bash
git clone https://github.com/Thepizzapie/AEGIS && cd AEGIS
pip install -e .            # or: pipx install .   (puts `aegis` on PATH for good)
```

> **`aegis` on PATH — read this.** `pip install -e .` inside a venv only wires `aegis`
> into *that* venv, but the runtime hooks call `aegis` from wherever the agent runs. So
> either install with **`pipx`** (a stable global `aegis`), or install scoped with an
> absolute command:
> `aegis install --project <repo> --command "/abs/path/to/.venv/bin/aegis hook"`.

Wire it into a repo (merge-safe — it never clobbers existing hooks):

```bash
aegis install --project /path/to/your/repo
aegis validate
```

> **Prefer project-scoped over global.** `aegis install --global` governs *every* Claude
> Code session and spawns a process per tool call — on a busy machine that adds up.
> Scope it to the repos you actually want guarded. Remove anytime with
> `aegis uninstall --project <repo>` (or `--global`).

### Try it (no Claude Code needed)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | aegis hook PreToolUse
# [Aegis] Recursive force delete is blocked. Append '# aegis-allow' to confirm.
echo $?            # -> 2  (the action is refused)
aegis report       # the decision is in the audit trail
```

> Works the same under PowerShell — a piped UTF-8 BOM is tolerated; use `$LASTEXITCODE` instead of `echo $?`.

## CLI reference

| Command | Purpose |
|---|---|
| `aegis hook <event>` | The entrypoint the runtime's hooks call — reads a tool-call JSON on stdin, evaluates policy, emits the decision. |
| `aegis install` / `uninstall` | Wire/unwire the hooks in a Claude Code `settings.json` (merge-safe, idempotent). Flags: `--project <path>`, `--global`, `--command <cmd>`. |
| `aegis install-git [--repo .]` | Write git `pre-commit` + `pre-push` hooks (append to existing, non-clobber). The hook invokes aegis by **absolute path** (resolved automatically; override with `--command`), so it works in a venv without `aegis` on PATH. |
| `aegis git-hook <commit\|push>` | The entrypoint the git hooks call — evaluates staged files (commit) or the push target (push). |
| `aegis ci [--base origin/main]` | CI check: evaluate changed files vs a base ref, emit `::error` annotations, exit non-zero on violation. |
| `aegis validate [-d <dir>]` | Validate policy YAML files. |
| `aegis pull <source>` | Pull org policy from a directory, file, or URL into the local policy dir. |
| `aegis issue <agent>` | Mint a signed Ed25519 identity token. Flags: `--role`, `--caps`, `--project`. |
| `aegis attest` | Submit an agent attestation (the honeypot endpoint rogue agents self-report to). |
| `aegis detections` | List caught rogue-agent attestations. |
| `aegis report` | Accountability rap sheet: per-session/identity rollups, denial trail, token/cost totals, session verdicts. Flags: `--audit <path>`, `--json`. |
| `aegis who` | Blame: which identities/sessions touched a tool or path. Flags: `--tool`, `--path`, `--json`. |
| `aegis adapters` | List available runtime adapters. |

## Design principles

- **Outside the context window.** Enforcement is a property of the runtime boundary,
  not a request to the model. That is the whole point.
- **Secure by default.** The dangerous defaults are on with zero config; relaxing
  them is a deliberate, recorded act.
- **Fail-open per rule.** A buggy or slow rule can never wedge or brick a session —
  it is skipped, never fatal.
- **Escapable with intent, or not at all.** Catastrophic/irreversible actions
  (secrets, self-removal, rogue sessions) are non-negotiable; merely dangerous ones
  accept a recorded `# aegis-allow`.
- **Runtime-agnostic core.** Adapters translate; the engine and policy are shared.

## Limitations

- **Not a sandbox.** Aegis gates tool calls; it doesn't isolate a process. An agent
  already at a raw shell can run relative commands Aegis only sees as a `shell` action
  — pair it with an OS-restricted user/container for hostile-code isolation.
- **Denylist guards are heuristic.** The built-in shell guards match known-dangerous
  command shapes; they raise the cost of evasion sharply but are not exhaustive by
  construction. Known-uncovered forms include: exfiltration via cloud CLIs
  (`aws s3 cp`, `gsutil`, `rclone`) or an in-process `requests.post`; in-place policy
  edits via `sed -i` / `perl -i` or a `chmod 000` on the policy file; and `git -c`
  inline-config force-push. These fail *safe* for file mutations routed through the
  runtime's Edit/Write tools (caught by path, not verb), but a raw shell can still
  reach them. Deny-by-default (allowlist) is the stronger posture for high-security
  setups and is supported per-surface (network egress today; a shell allowlist preset
  is planned). If you find a bypass, that's a bug worth reporting.
- **Identity is as strong as the keystore.** v1 persists the issuer key on disk; a
  process with your full privileges could read it. True unforgeability needs the key
  in a broker process plus OS privilege separation — the module isolates the key
  source so that hardening is a swap, not a rewrite.
- **Deep hooks are per-runtime.** Native support is Claude Code today; other runtimes
  are covered by the `generic` JSON adapter or the git/CI floor.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

For questions about team, enterprise, or MCP-provider licensing, open an issue or
get in touch.
