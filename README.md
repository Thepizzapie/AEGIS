# Aegis

Policy enforcement for AI coding agents, at the runtime's hook boundary.

Your agent runs with your shell, your keys, your database. Aegis checks every action it tries and answers allow, deny, or ask — from a separate process the model can't reach, so a prompt injection can't talk its way past a block. It ships with the dangerous defaults already on (no config), and logs every decision so you can see what each agent did.

It is a policy layer, not a sandbox. See [Limits](#limits).

```bash
pip install aegis-hooks
aegis install --project /path/to/your/repo
```

## Try it (no Claude Code needed)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | aegis hook PreToolUse
# [Aegis] Recursive force delete is blocked. Append '# aegis-allow' to confirm.
echo $?            # 2 = refused   (PowerShell: $LASTEXITCODE)
aegis report       # the decision is in the audit trail
```

## How it works

Runtimes like Claude Code call out to an external program before a tool runs. Aegis is that program. On `PreToolUse` the runtime pipes it the pending tool call as JSON and waits for the exit code:

- `0` — the tool runs.
- `2` — blocked; the reason is fed back to the model.
- `ask` — surfaced to you for a yes/no. The agent never decides.

The decision comes from policy on disk, not from anything the model wrote. A jailbroken model still can't run a denied command, because the thing being asked "may I?" is the runtime, not the model.

`aegis install` merges hooks into `.claude/settings.json` (the full 26-event surface) without clobbering existing hooks or keys. Uninstall removes only what Aegis added.

## What it blocks by default

Non-escapable guards can't be waved through. Escapable ones block but accept a recorded `# aegis-allow` (shell) or `-- aegis-allow` (SQL) from a **human** — a spawned agent can't escape its own guards.

| Guard | Catches | Escapable |
|---|---|---|
| Containment | Reads of credential stores (`~/.ssh`, `~/.aws`, `.netrc`, browser logins, DPAPI), file exfiltration (`curl -T`/`-d @`, `-InFile`), persistence (cron, registry autorun, scheduled tasks, services) | No |
| Self-protection | Deleting/editing `.aegis`, `.claude/settings.json`, or Aegis's own source; `aegis uninstall`/`pull` | No |
| Evasion | Encoded/obfuscated commands (`-EncodedCommand`, `base64 -d \| bash`, char-code) | No |
| MCP config | Writes to MCP server-config files (`.mcp.json`, `mcpServers`, etc.) that auto-run on every future session | Human only |
| Destructive SQL | `DROP`/`TRUNCATE`/`ALTER ... DROP`, `DELETE`/`UPDATE` without `WHERE`, migration resets — from shell **and** DB tool args | Yes |
| Destructive git | force-push, `reset --hard`, rebase, `branch -D`, `clean -f` | Yes |
| Recursive delete | `rm -rf` and equivalents (PowerShell, cmd, `find -delete`, `shred`, `dd`) | Yes |
| Forced install review | Blocks `pip/npm/... install` until its manifest is fully read, then asks | Human only |
| Fetch-to-shell | `curl … \| sh`, `iex(iwr …)`, DNS-TXT payload retrieval | Human only |
| Failure loop | The Nth identical retry of a call that keeps failing (default 3) | Human only |
| Workspace confinement | Edits/writes outside the agent's project root | No, once bound |
| Network egress | Outbound hosts against an allow/deny list | Policy-driven |

Built-in guards run before your declarative rules and can only deny or abstain, so a permissive rule (even `tools: ["*"]` for an admin) can't re-open a built-in. To relax one, disable it explicitly.

Beyond tool calls, Aegis covers the full lifecycle surface (sub-agent fan-out, task/stop completion gates, worktree confinement, context-compaction gates). Most are opt-in via policy knobs.

## Policy

Declarative YAML. First matching rule by priority wins, else `default_action`. Match on event, tool glob, action class, role, or argument (glob or regex).

```yaml
default_action: allow          # "deny" for deny-by-default
egress:
  default: deny
  allow: ["api.github.com", "*.internal"]
rules:
  - name: block-secret-files
    action: deny
    actions: [read, edit, write]
    argument_patterns: { file_path: "*.env*" }
  - name: confirm-prod
    action: ask
    actions: [shell]
    regex: { command: "terraform\\s+apply|\\bkubectl\\b.*\\bprod\\b" }
```

Validate with `aegis validate`. Policy resolves env → `./.aegis/policies` → `~/.aegis/policies`, so a repo can ship its own guardrails.

## Identity and accountability

A name in an env var is forgeable, so Aegis issues Ed25519 tokens (`aegis issue <agent> --role reader --project .`) and treats a claimed name without a valid token as rogue. Under `AEGIS_IDENTITY_ENFORCE=1` a rogue session is denied and its process tree reaped. Roles come from the verified token, so a prompt-injected but signed `admin` is still blocked by the action-layer guards.

Every decision lands in `~/.aegis/audit.jsonl`. `aegis report` gives the rap sheet (denials, token/cost totals, per-session verdicts); `aegis who --tool X --path Y` is blame.

## Grounding

Enforcement governs what an agent *does*; grounding governs what it *claims*. `aegis.grounding` (the folded-in Receipts engine) checks every claim in an answer against a ledger of evidence: a claim must cite real evidence or be demoted to an assumption, effort words ("I reviewed the entire codebase") need coverage proof, and cited evidence must actually back the claim.

Because Aegis already logs every tool call and its output, `ledger_from_audit()` builds that ledger from the audit trail — so a final answer is checked against what the agent actually did.

```python
from aegis.grounding import Gate, Answer, Claim, ClaimKind, ledger_from_audit
ledger = ledger_from_audit("~/.aegis/audit.jsonl")
print(Gate(ledger).finalize(answer))   # renders, or raises with a fix list
```

```bash
aegis grounding audit trace.json          # exit 1 if any claim is ungrounded
```

Deterministic and dependency-free by default; the LLM judge is optional (`pip install "aegis-hooks[anthropic]"`). Previously the standalone `receipts-gate` package.

## Other surfaces

Same policy, three places: runtime hooks (Claude Code native, others via the `generic` adapter), inside your own MCP server (`from aegis import mcp`, decorate tools with `@aegis.guarded`), and git/CI (`aegis install-git`, `aegis ci --base origin/main`) as a floor that works even where a runtime has no hooks.

## Install notes

`pip install -e .` inside a venv only wires `aegis` into that venv, but the hooks call `aegis` from wherever the agent runs. Use `pipx install aegis-hooks` for a stable global `aegis`, or scope the command:

```bash
aegis install --project <repo> --command "/abs/path/to/.venv/bin/aegis hook"
```

Prefer project-scoped installs. `--global` fires for every tool call in every session and the per-call process spawns add up on a busy machine.

## CLI

| Command | Purpose |
|---|---|
| `aegis hook <event>` | The hook entrypoint the runtime calls (reads JSON on stdin, emits the decision). |
| `aegis install` / `uninstall` | Wire/unwire hooks + skills in a `settings.json`. Flags: `--project`, `--global`, `--command`, `--no-skills`. |
| `aegis install-git` / `git-hook` / `ci` | Enforce the same policy at commit, push, and PR. |
| `aegis validate` | Check policy YAML. |
| `aegis issue <agent>` | Mint a signed identity token. |
| `aegis report` / `who` / `detections` | Accountability: rap sheet, blame, rogue detections. |
| `aegis grounding audit <trace>` | Gate an answer's claims against evidence. Flags: `--from-audit`, `--json`, `--llm`. |
| `aegis pull` / `adapters` | Pull org policy; list runtime adapters. |

## The hard posture: pair it with a sandbox

Aegis alone is a policy + audit layer, not containment. The honest strong setup runs the agent in a throwaway container (the sandbox limits what it can *reach*) with Aegis inside it (policy for what it's *allowed to do*, plus the audit). Each covers the other's blind spot: the container makes Aegis's denylist gaps survivable, and Aegis catches the intent-level things the OS reads as legal (dropping a scratch DB is a valid operation to the kernel).

Ready-to-run container + VS Code devcontainer + one-command launcher are in [`sandbox/`](sandbox/):

```bash
cd sandbox && ./run.sh /path/to/repo    # or run.ps1 on Windows
```

## Limits

- **Not a sandbox by itself.** An agent already at a raw shell can run relative commands Aegis only sees as opaque `shell` text. Use the [`sandbox/`](sandbox/) container, or an OS-restricted user, for hostile-code isolation.
- **Guards are a denylist.** They catch known-dangerous shapes, not every possible one. Known gaps: cloud-CLI exfil (`aws s3 cp`, `gsutil`, `rclone`), in-place edits (`sed -i`), `git -c` inline-config force-push. Deny-by-default egress is the backstop. Found a bypass? That's a bug worth reporting.
- **Fail-open by default.** If the hook can't run, the action proceeds unguarded rather than blocking your work. Set `AEGIS_FAIL_CLOSED=1` to invert.
- **Identity is as strong as the keystore.** The issuer key lives on disk; a process with your privileges can read it.
- **Deep hooks are Claude Code today.** Other runtimes use the `generic` adapter or the git/CI floor.

## License

Apache-2.0. See [LICENSE](LICENSE).
