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
| Containment | Reads of credential stores (`~/.ssh`, `~/.aws`, `.netrc`, browser logins, DPAPI), file exfiltration (`curl -T`/`-d @`, `-InFile`, cloud-CLI uploads: `aws s3 cp`/`gsutil`/`az storage upload`/`rclone`), env-var secret exfiltration (`env`/`printenv`/`Get-ChildItem Env:` dumped into curl/nc/socat/ssh/etc.), persistence (cron, registry autorun, scheduled tasks, services) | No |
| Cloud metadata SSRF | Fetching the cloud instance-metadata service (`169.254.169.254` and its GCP/Azure/Alibaba/encoded-IP variants) — via shell, `WebFetch`, or an MCP tool — which hands out live IAM/service-account credentials to anything on-box, no auth required | No |
| Self-protection | Deleting/editing `.aegis`, `.claude/settings.json`, or Aegis's own source; `aegis uninstall`/`pull` | No |
| Evasion | Encoded/obfuscated commands (`-EncodedCommand`, `base64 -d \| bash`, char-code) | No |
| MCP config | Writes to MCP server-config files (`.mcp.json`, `mcpServers`, etc.) that auto-run on every future session | Human only |
| CI/CD workflow | Writes to CI pipeline definitions (`.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`, CircleCI/Azure/Travis/Drone/Bitbucket/Buildkite/Cloud Build/AppVeyor) — a step planted there runs on a future, different, higher-privilege machine (the CI runner), not this session | Human only |
| Git hooks | Writes to `.git/hooks/*` (pre-commit, pre-push, post-checkout, ...) or a `core.hooksPath` redirect — a hook runs with the invoking user's full privileges on the next matching git operation and, unlike a tracked file, is invisible to `git diff`/`git status`/code review | Human only |
| Agent definitions | Writes to `CLAUDE.md`/`AGENTS.md` (folded into every future session's context) or `.claude/agents/*.md`/`.claude/commands/*.md`/`.claude/output-styles/*.md` (custom sub-agent/slash-command/output-style definitions, project or user scope) — a planted instruction or definition is auto-loaded/auto-invoked next session with no further agent action | Human only |
| Shell-startup / SSH persistence | Writes to a shell startup/profile file (`~/.bashrc`/`~/.zshrc`/`~/.profile`/`~/.bash_aliases`/`~/.xprofile`/fish's `config.fish`/`/etc/profile.d/*.sh`/a PowerShell `$PROFILE`) — runs with the human's full privileges the next time they open a shell, no git/CI/session-restart trigger needed — or an SSH persistence target (`~/.ssh/authorized_keys`, `~/.ssh/rc`, `~/.ssh/config`, `/etc/ssh/sshd_config`, `/etc/ssh/ssh_config`, and their `Include`d `*.d/*.conf` drop-ins) | Human only |
| direnv auto-exec-on-cd | Writes to a project `.envrc` (any nesting depth — direnv sources every ancestor `.envrc`), the global `direnvrc` (`~/.config/direnv/direnvrc`, legacy `~/.direnvrc` — sourced for *every* `.envrc` on the machine, no per-file trust check), or `direnv.toml`'s `[whitelist]` (pre-trusts matching `.envrc` paths unconditionally, regardless of content or `direnv allow`/`deny`) — runs as arbitrary shell the next time anyone `cd`s into the project, no git/CI/session-restart trigger needed. Also gates `direnv allow`/`permit`/`edit`, the CLI subcommand that grants direnv's own trust to an untrusted/changed `.envrc` — unlike VS Code's click-only "Allow Automatic Tasks" prompt, an agent can invoke this itself and self-approve a payload it just planted | Human only |
| Package manifests | Planting an auto-run lifecycle-script hook in `package.json` (`preinstall`/`install`/`postinstall`/`preuninstall`/`postuninstall`/`prepare`/`prepublish`/`prepublishOnly`) or `composer.json`'s equivalent (`pre-install-cmd`/`post-install-cmd`/`pre-update-cmd`/`post-update-cmd`/`pre-autoload-dump`/`post-autoload-dump`/...) — runs unattended on the next `npm install`/`composer install`, by this agent, a teammate, or CI — or redirecting a package registry/index (`.npmrc`, `.yarnrc`/`.yarnrc.yml`, `pip.conf`/`pip.ini`, `.cargo/config.toml`, `pyproject.toml`'s `[[tool.poetry.source]]`), via file write or CLI (`npm`/`pnpm`/`yarn`/`pip config set`, `npm pkg set`, `poetry source add`, `composer config repositories.*`, `cargo config set ... replace-with`) | Human only |
| Git-config credential/exec hijack | Redirecting `credential.helper` (any value — git hands the configured helper the target host, and on a `store` verb the actual username/password/PAT, before every future authenticated fetch/push/pull) or planting a `!`-prefixed shell-command value on any git-config key (`alias.<name>`, `core.pager`, `core.editor`, `diff.external`, `mergetool.<name>.cmd`, ...) — a `!`-prefixed alias runs with the invoking user's/CI's full privileges on the very next `git <name>`, the same "write now, auto-exec later" shape as a git hook. Covers `git config`, inline `-c`/`--config`/`--config-env`, `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` env-injection, and direct writes to the config file | Human only |
| Git-attributes filter/diff/merge hijack | Wiring a `.gitattributes`/`.git/info/attributes` path pattern to a `filter=<name>`/`diff=<name>`/`merge=<name>` driver, and setting the git-config keys that RUN that driver directly with no `!`-prefix needed at all (unlike the credential/exec-hijack guard above): `filter.<name>.clean`/`smudge`/`process`, `diff.<name>.textconv`/`command`, `merge.<name>.driver` — plus two more no-bang direct-exec keys, `core.fsmonitor` and `core.sshCommand`. Once both halves are set, the single most ordinary git actions there are (`git add`, `git checkout`, `git diff`, `git status`, a merge) silently execute the configured command, with no special command name for a human to notice | Human only |
| Systemd/launchd persistence | Writes to a systemd unit (`/etc/systemd/system/*.service`, `/etc/systemd/user/*.service`, `~/.config/systemd/user/*.service`, `/usr/lib/systemd/{system,user}/*`, `*.timer`/`*.socket`/`*.path`/`*.mount` siblings, or a `<unit>.service.d/override.conf` drop-in) or a launchd property list (`~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons/*.plist`) — runs with root or the human's full privileges on the next boot/login, no git/CI/session-restart trigger needed, the Linux/macOS analog of the Windows scheduled-task/service persistence Containment already denies. Also gates the activation commands that flip an already-present unit live with no file write at all: `systemctl enable`/`reenable`/`link`/`edit`, `systemd-run --on-calendar`/`--on-boot`/..., `launchctl load`/`bootstrap`/`enable` | Human only |
| Dev-container lifecycle hijack | Writes to `.devcontainer/devcontainer.json` (`.devcontainer/<name>/devcontainer.json`, or the root-level `.devcontainer.json` shorthand) that plant an `initializeCommand`/`onCreateCommand`/`updateContentCommand`/`postCreateCommand`/`postStartCommand`/`postAttachCommand` — runs automatically, unattended, the next time this dev environment builds or starts (VS Code "Reopen in Container", a GitHub Codespaces create/prebuild, `devcontainer up`/`build`), no git/CI/boot trigger needed; `initializeCommand` runs on the HOST before the container even exists, outside the container boundary the sandbox posture below relies on. Covers Edit/Write/MCP writes and shell writes (redirect, in-place edit, `jq`+`sponge`) | Human only |
| VS Code auto-run task hijack | Writes to `.vscode/tasks.json` that plant a task with `"runOptions": {"runOn": "folderOpen"}` — runs automatically, unattended, the next time this workspace folder is opened in VS Code, no git/CI/boot trigger needed — or to `.vscode/settings.json` that set `"task.allowAutomaticTasks": "on"`, silencing VS Code's own one-time "Allow Automatic Tasks in Folder..." confirmation prompt, the one human checkpoint otherwise standing between a planted task and it running. Gated on the specific dangerous value, not the key alone (`runOn: "default"` and `allowAutomaticTasks: "off"` stay allowed). Covers Edit/Write/MCP writes and shell writes (redirect, in-place edit, `jq` — both direct-assignment and merge forms — and a prior `cd`/`pushd`/`Set-Location` into `.vscode` followed by a bare filename) | Human only |
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
- **Guards are a denylist.** They catch known-dangerous shapes, not every possible one. Known gaps: bucket-to-bucket cloud transfers and aliased clients (`mc`, `doctl`) that the cloud-CLI exfil guard doesn't parse, `git -c` inline-config force-push, shell-computed path indirection reaching self-protection's protected files — `find`'s `-path`/`-name`/`-regex` predicates are covered, but reconstructing a path from a variable split across assignments, a `for`/`xargs` loop, or `basename`/`dirname` is not — and a single named environment variable handed to a network call (e.g. an API token in an `Authorization` header) is deliberately not flagged by the env-exfil guard, which only catches a *bulk* dump piped/substituted into a network sink; there's no reliable way to tell "the vendor's own API" from "an attacker's host" by regex alone; and the CI/CD workflow guard, like self-protection, is a path-string match — a shell command that computes the workflow path indirectly (a variable built across assignments, `find -path`/`xargs`, `basename`/`dirname`) evades it, and a self-hosted/less-common CI system whose config filename isn't in its list (Woodpecker, TeamCity, a custom `include:` path) isn't covered. The git-hooks guard shares that same path-string-match nature — a hook name outside the standard githooks(5) list, a fully relocated git dir (`--separate-git-dir`) with no `modules/` segment, an MCP tool naming its target argument outside the recognized key list, and `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` redirecting to a payload staged in an earlier, separate tool call are residual gaps for the same "each tool call is evaluated independently" reason. The CI/CD workflow, git-hooks, agent-definitions, and shell-persist guards all share one more: a direct fetch-to-file write (`curl -o <target>`, `wget -O <target>`) is caught by none of their write-verb checks (redirect/delete/move/in-place-edit/forced-link/archive-sync) — an ordinary `curl`/`wget` invocation targeting a protected path sails through undetected on all four. The shell-persist guard's SSH coverage overlaps the non-escapable containment guard for the ordinary `~/.ssh/authorized_keys`/`~/.ssh/config` forms (containment wins first there); it adds real coverage only for `/etc/ssh/sshd_config`/`/etc/ssh/ssh_config` and a relative reference with no leading path separator, and its `find`-fallback deliberately excludes the bare words "config"/"profile" (too generic to disambiguate from an unrelated file). The package-manifest guard is content-gated, not path-only like its siblings (package.json/pyproject.toml/composer.json are edited too often for benign reasons to tolerate a path-only ask) — known gaps there: a lifecycle-script/registry value assembled via the target language's own string-building (`'post'+'install'`, an f-string, `.join()`) rather than appearing as one contiguous literal defeats the content check, the same "computed indirectly" class every other guard here accepts; a key planted with an innocuous placeholder value in one Edit, then swapped for the real payload in a second Edit whose diff never repeats the key name, evades detection on the second call (no cross-call session state, the same limitation `git_hooks`' split-across-calls gap already accepts); `find`-path indirection around the manifest/config filename isn't covered at all (no `*_find_hit`-style fallback, unlike five of its siblings); and a direct fetch-to-file write (`curl -o package.json`) is caught by none of its write-verb checks, the same inherited gap the CI/CD workflow/git-hooks/agent-definitions/shell-persist guards already disclose. The git-config-exec guard's shell branch doesn't gate on a write-verb at all (unlike its path-only siblings) since the CLI/inline-config forms are already the dominant way this surface is reached; known gaps there: a value assembled indirectly (shell variable concatenation, a wrapper script that itself invokes `git config`) rather than one contiguous literal defeats it, the same "computed indirectly" class every other guard here accepts; `find`-path indirection around the git-config file path isn't covered; the paired `GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n` env-injection form is matched independently per side rather than confirmed to actually pair up, the same `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` split-across-calls limitation `git_hooks` already accepts; and a value quoted with a leading space before `!` (real git does not treat this as shell-exec) is still conservatively gated, a disclosed false positive traced to the shared quote-stripping normalization layer every guard in this file relies on to see through obfuscation. The systemd/launchd guard matches a unit/plist path on its distinctive `systemd/system`, `systemd/user`, `LaunchAgents`, or `LaunchDaemons` path segment rather than a fixed full prefix, so it doesn't need every packaging layout enumerated — but its `find`-fallback deliberately excludes the bare extensions `.plist`/`.timer`/`.service` (too generic — an ordinary iOS/macOS project's `Info.plist`, or an unrelated tool's own `.service` file, carries no systemd/launchd signal on its own), a direct fetch-to-file write (`curl -o ~/Library/LaunchAgents/x.plist`) is caught by none of its write-verb checks, the same inherited gap the CI/CD workflow/git-hooks/agent-definitions/shell-persist/package-manifest guards already disclose, and an `$XDG_CONFIG_HOME` relocation of where systemd looks for user units isn't covered, the same "computed indirectly" class shell-persist's own `$ZDOTDIR` gap already accepts. The git-attributes filter/diff/merge guard's shell-form `.gitattributes`-wiring check is deliberately whole-command, not clause-scoped — after four rounds of adversarial review found that every attempt at scoping it to a single `;`/`&&`-joined clause (to avoid a false ask on an unrelated `filter=`/`diff=`/`merge=`-shaped substring elsewhere in the same command) opened a worse false-negative bypass instead (a heredoc, a quoted argument, an unusual heredoc delimiter), it checks both conditions over the whole scanned command and accepts the narrower false ask as the trade-off; a subsection name reachable only via outer shell quoting containing a literal ASCII space (`git config 'filter.evil driver.smudge' ...`) still evades its git-config key check, verified non-exploitable end-to-end since `.gitattributes` values are themselves ASCII-space/tab-delimited. The dev-container lifecycle guard matches only one optional named subdirectory under `.devcontainer/` (`.devcontainer/<name>/devcontainer.json`) — a deeper nesting is not covered; a lifecycle-command value assembled indirectly (shell variable concatenation, a templating step) rather than appearing as a literal JSON key defeats it; a direct fetch-to-file write (`curl -o .devcontainer/devcontainer.json ...`) is caught by none of its write-verb checks, the same inherited gap the CI/CD workflow/git-hooks/agent-definitions/shell-persist/package-manifest/systemd-launchd guards already disclose; and, like package-manifest, it has no `find`-path-indirection fallback; its `cd`/`pushd`-into-directory fallback (`DEVCONTAINER_CD_RE`) also terminates the directory name with a bare word-boundary rather than a real path-segment terminator, so an unrelated lookalike directory whose name merely starts with `.devcontainer` followed by a non-word character (`.devcontainer-old`, `.devcontainer.bak`) false-positives — found verifying the same, since-fixed bug in the newer VS Code auto-run task guard's own `VSCODE_CD_RE` (below); a false ask, not a false allow, and not yet fixed here. A related but distinct auto-run surface — a VS Code `.vscode/tasks.json` entry with `"runOptions": {"runOn": "folderOpen"}`, or its `.vscode/settings.json` `"task.allowAutomaticTasks": "on"` prompt-silencing companion — is now covered by the VS Code auto-run task guard (below); a JetBrains run configuration's "Before launch" step is a related but distinct IDE-auto-run primitive that guard does not cover. The VS Code auto-run task guard itself: a multi-root `*.code-workspace` file can embed the same `"tasks"`/`task.allowAutomaticTasks` settings directly, with no `.vscode/` path segment at all — not covered; a `runOn`/`allowAutomaticTasks` value assembled indirectly (a templating step, a build script) rather than appearing as a literal is not caught; and, like the dev-container guard, a direct fetch-to-file write (`curl -o .vscode/tasks.json ...`) is caught by none of its write-verb checks, the same inherited gap five of its siblings already disclose. The direnv guard has no bare-directory fallback at all (unlike shell-persist/service-persist/git-hooks/agent-def) — deliberately: an `.envrc`'s own parent directory is the project root itself, too generic a signal to gate an archive/sync tool restoring a whole checkout on; a direct fetch-to-file write (`curl -o .envrc ...`) is caught by none of its write-verb checks, the same inherited gap seven of its siblings already disclose; and an `$XDG_CONFIG_HOME` relocation of the global `direnvrc`/`direnv.toml` is only caught when the `direnv/direnvrc`/`direnv/direnv.toml` path segment itself still appears literally — a relocation that also renames that segment is the same "computed indirectly" class of gap shell-persist's own `$ZDOTDIR` gap already accepts. Independent adversarial QA on the direnv guard also surfaced three gaps confirmed to be pre-existing and shared across every literal-substring shell guard in this file, not unique to direnv — noted here rather than fixed per-guard, since a real fix belongs in the shared de-obfuscation/activation-regex layer every `*_protect` guard builds on: (1) a bare backslash before an ordinary character is removed by bash at parse time (`di\renv` IS `direnv`, `.e\nvrc` IS `.envrc`) but the shared de-obfuscation surface only strips quote characters and ANSI-C (`$'...'`) escapes, never a bare mid-token backslash — the identical gap already lets `echo x >> ~/.ba\shrc` evade the shell-persist guard today; (2) a one-line shell function wrapper (`d() { direnv "$@"; }; d allow`) breaks an activation-command regex's word-adjacency assumption while bash still executes the real command, the same gap the systemd/launchd guard's own activate-command check already has; (3) that guard family's shared 200-char non-greedy verb-adjacency bound is a wider fixed window, not a structural fix — a single ~220-char padding argument still pushes the verb outside it. Deny-by-default egress is the backstop. Found a bypass? That's a bug worth reporting.
- **Fail-open by default.** If the hook can't run, the action proceeds unguarded rather than blocking your work. Set `AEGIS_FAIL_CLOSED=1` to invert.
- **Identity is as strong as the keystore.** The issuer key lives on disk; a process with your privileges can read it.
- **Deep hooks are Claude Code today.** Other runtimes use the `generic` adapter or the git/CI floor.

## License

Apache-2.0. See [LICENSE](LICENSE).
