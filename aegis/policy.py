"""Policy model, decision type, and rule matching (AEGI-1).

AEGI-1 defines the rule/decision shapes and the matching the engine needs.
AEGI-3 adds the YAML authoring / loader / ``aegis validate`` layer on top.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .events import Event


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


def _as_values(items) -> list:
    return [it.value if isinstance(it, Enum) else str(it) for it in items]


def _any_glob(globs, value: str) -> bool:
    return any(fnmatch.fnmatch(value, g) for g in globs)


@dataclass
class Rule:
    """A single policy rule. An empty selector list means "matches any". A rule
    matches an event only when *all* of its non-empty selectors match."""

    name: str
    action: Action = Action.DENY
    events: list = field(default_factory=list)             # HookEvent values; [] = any
    tools: list = field(default_factory=list)              # globs on tool name; [] = any
    actions: list = field(default_factory=list)            # ActionClass values; [] = any
    roles: list = field(default_factory=list)              # caller roles; [] = any
    argument_patterns: dict = field(default_factory=dict)  # arg name -> glob (or list of globs)
    regex: dict = field(default_factory=dict)              # arg name -> regex (re.search)
    message: Optional[str] = None
    priority: int = 0
    description: Optional[str] = None

    def matches(self, ev: Event) -> bool:
        if self.events and ev.event.value not in _as_values(self.events):
            return False
        if self.actions and ev.action.value not in _as_values(self.actions):
            return False
        if self.tools and not _any_glob(self.tools, ev.tool or ""):
            return False
        if self.roles and not (set(self.roles) & set(ev.roles or [])):
            return False
        for key, pat in (self.argument_patterns or {}).items():
            val = ev.args.get(key)
            if val is None:
                return False
            # a pattern may be a single glob OR a list of globs (match if ANY) —
            # so one rule can cover a dangerous action across shells/phrasings
            # (rm -rf, Remove-Item -Recurse -Force, rmdir /s, ...).
            pats = pat if isinstance(pat, (list, tuple)) else [pat]
            if not any(fnmatch.fnmatch(str(val), str(p)) for p in pats):
                return False
        for key, rx in (self.regex or {}).items():
            val = ev.args.get(key)
            if val is None or not re.search(str(rx), str(val), re.IGNORECASE):
                return False
        return True


@dataclass
class Decision:
    action: Action
    rule: Optional[str] = None
    message: Optional[str] = None

    @property
    def blocked(self) -> bool:
        return self.action == Action.DENY


@dataclass
class Policy:
    rules: list = field(default_factory=list)
    default_action: Action = Action.ALLOW
    # Fail-safe: if evaluation itself errors, a broken hook must not brick the
    # agent. Default ALLOW (fail-open); set DENY for fail-closed enforcement.
    on_error: Action = Action.ALLOW
    # Network egress governance: {default: allow|deny, allow: [host globs], deny: [...]}
    egress: dict = field(default_factory=dict)
    # Custom guard plugin module paths (loaded via aegis.plugins)
    plugins: list = field(default_factory=list)
    # Workspace confinement: {root: <path>, allow: [<path>, ...]} (opt-in)
    workspace: dict = field(default_factory=dict)
    # Project root the agent identity is bound to. When set, file mutations
    # outside it are hard-blocked (out-of-project edits). .aegis default; a
    # token `project` claim or AEGIS_PROJECT take precedence at the hook.
    project: Optional[str] = None
    # Default agent label when no AEGIS_AGENT_NAME is set -> zero-config
    # attribution for a repo's agents.
    agent_label: Optional[str] = None
    # --- opt-in lifecycle-hook knobs (read by aegis.lifecycle rules) ---
    # Team / sub-agent governance: {require_verification: bool} — gate TaskCompleted
    # on an explicit verification signal (did-it-do-the-task).
    team: dict = field(default_factory=dict)
    # Context-compaction control: {block_auto: bool} — deny auto PreCompact so a
    # human can checkpoint before context is destroyed.
    compaction: dict = field(default_factory=dict)
    # Permission-escalation control: {deny_escalation: bool} — auto-deny a spawned
    # agent's human-only PermissionRequest prompts instead of hanging on them.
    permission: dict = field(default_factory=dict)
    # MCP-input governance: {block_elicitation: bool} — deny MCP elicitation side
    # channels for a spawned/unattended agent.
    mcp: dict = field(default_factory=dict)
    # Forced install review: {mode: off|monitor|ask, deep: bool,
    # require_pinned: bool, allow: [regex on command]}. Empty -> defaults
    # (mode=ask) apply. See rules.rule_install_review.
    install_review: dict = field(default_factory=dict)
    # MCP server-config protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=deny) apply.
    # See rules.rule_mcp_config_protect.
    mcp_config: dict = field(default_factory=dict)
    # CI/CD pipeline-definition protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=ask) apply.
    # See rules.rule_ci_workflow_protect.
    ci_workflow: dict = field(default_factory=dict)
    # Git-hooks protection: {mode: deny|ask|monitor|off, allow: [regex on
    # path/command]}. Empty -> defaults (mode=ask) apply. See
    # rules.rule_git_hooks_protect.
    git_hooks: dict = field(default_factory=dict)
    # Agent-instructions / agent-definition protection: {mode: deny|ask|
    # monitor|off, allow: [regex on path/command]}. Empty -> defaults
    # (mode=ask) apply. Covers CLAUDE.md/AGENTS.md and .claude/agents/*.md,
    # .claude/commands/*.md. See rules.rule_agent_def_protect.
    agent_def: dict = field(default_factory=dict)
    # Claude Code Skill-definition protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=ask) apply.
    # Covers .claude/skills/<name>/SKILL.md, project- or user-scoped — a
    # skill's description is read into every future session's context
    # unattended, and the model can select and run its body with no
    # explicit per-invocation approval, a surface rule_agent_def_protect
    # was never extended to reach. See rules.rule_skills_protect.
    skills_protect: dict = field(default_factory=dict)
    # Shell-startup / SSH persistence protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=ask) apply.
    # Covers ~/.bashrc/~/.zshrc/~/.profile/fish's config.fish/
    # /etc/profile.d/*.sh/a PowerShell $PROFILE and ~/.ssh/authorized_keys/
    # ~/.ssh/config/sshd_config/ssh_config. See rules.rule_shell_persist_protect.
    shell_persist: dict = field(default_factory=dict)
    # direnv .envrc / global direnvrc auto-exec-on-cd protection: {mode:
    # deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers a project .envrc (any nesting depth)
    # and the global direnvrc (~/.config/direnv/direnvrc, ~/.direnvrc), plus
    # the direnv allow/permit/edit activation commands that trust an
    # untrusted/changed .envrc with no file write of their own. See
    # rules.rule_direnv_protect.
    direnv: dict = field(default_factory=dict)
    # Package-manifest lifecycle-script / registry-hijack protection:
    # {mode: deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers package.json/composer.json lifecycle
    # scripts (preinstall/postinstall/prepare/...) and registry-redirect
    # config (.npmrc/.yarnrc*/pip.conf/.cargo/config.toml/pyproject.toml's
    # [[tool.poetry.source]]). See rules.rule_package_manifest_protect.
    package_manifest: dict = field(default_factory=dict)
    # Git-config credential/exec-hijack protection: {mode: deny|ask|monitor|
    # off, allow: [regex on path/command]}. Empty -> defaults (mode=ask)
    # apply. Covers `credential.helper` redirection and any git-config key
    # given a `!`-prefixed shell-command value (alias.*, core.pager, ...).
    # See rules.rule_git_config_exec_protect.
    git_config_exec: dict = field(default_factory=dict)
    # .gitattributes filter/diff/merge driver hijack + non-bang direct-exec
    # git-config key protection: {mode: deny|ask|monitor|off, allow: [regex
    # on path/command]}. Empty -> defaults (mode=ask) apply. Covers
    # .gitattributes/.git/info/attributes wiring a path to filter=/diff=/
    # merge=, and filter.<name>.clean/smudge/process, diff.<name>.textconv/
    # command, merge.<name>.driver, core.fsmonitor, core.sshCommand — keys
    # git_config_exec's bang-only value check can't reach (no `!` required).
    # See rules.rule_git_attributes_exec_protect.
    git_attributes_exec: dict = field(default_factory=dict)
    # .gitmodules submodule-hijack protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=ask) apply.
    # Covers a submodule `url` using the `ext::`/`file://` scheme
    # (git-remote-ext RCE), a submodule `path` with a `..` traversal segment
    # (hooks-directory collision / write outside the intended directory),
    # and setting `protocol.ext.allow`/`protocol.file.allow` to an allowing
    # value (the override git's own 2.38.1+ default requires before either
    # scheme runs at all). See rules.rule_gitmodules_protect.
    gitmodules: dict = field(default_factory=dict)
    # Systemd unit / launchd persistence protection: {mode: deny|ask|monitor|
    # off, allow: [regex on path/command]}. Empty -> defaults (mode=ask)
    # apply. Covers /etc/systemd/{system,user}/*.service (+ .timer/.socket/
    # .path/.mount and *.service.d/*.conf drop-ins) and
    # ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons
    # *.plist, plus the systemctl enable/link/edit and launchctl
    # load/bootstrap/enable activation commands. See
    # rules.rule_service_persist_protect.
    service_persist: dict = field(default_factory=dict)
    # Dynamic-linker preload / search-path hijack protection: {mode:
    # deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers /etc/ld.so.preload (glibc dlopen()s
    # every listed .so into EVERY dynamically-linked program run on the
    # machine from that point on, no reboot/new-shell/CI trigger needed) and
    # /etc/ld.so.conf + /etc/ld.so.conf.d/*.conf (shared-library search-path
    # hijack). See rules.rule_ld_preload_protect.
    ld_preload: dict = field(default_factory=dict)
    # Dev-container lifecycle-command protection: {mode: deny|ask|monitor|
    # off, allow: [regex on path/command]}. Empty -> defaults (mode=ask)
    # apply. Covers .devcontainer/devcontainer.json (+ .devcontainer/<name>/
    # devcontainer.json, .devcontainer.json) carrying an initializeCommand/
    # onCreateCommand/updateContentCommand/postCreateCommand/
    # postStartCommand/postAttachCommand — auto-run on the next devcontainer
    # build/start, initializeCommand on the HOST with no container isolation.
    # See rules.rule_devcontainer_exec_protect.
    devcontainer_exec: dict = field(default_factory=dict)
    # VS Code auto-run task protection: {mode: deny|ask|monitor|off, allow:
    # [regex on path/command]}. Empty -> defaults (mode=ask) apply. Covers
    # .vscode/tasks.json carrying "runOptions": {"runOn": "folderOpen"} and
    # .vscode/settings.json carrying "task.allowAutomaticTasks": "on" (which
    # silences VS Code's one-time confirmation prompt for the former). See
    # rules.rule_vscode_tasks_protect.
    vscode_tasks_exec: dict = field(default_factory=dict)
    # PATH binary-shadow (hijack) protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=ask) apply.
    # Covers planting/symlinking/`chmod +x`-ing an executable over a trusted
    # command name (git, ssh, sudo, curl, python, pip, npm, docker, aws,
    # aegis, ...) inside a directory that already sits ahead of the system
    # directories on $PATH (~/.local/bin, ~/.cargo/bin, pyenv/rbenv/asdf
    # shims, ~/go/bin, /usr/local/bin, /opt/homebrew/bin, ...). See
    # rules.rule_path_hijack_protect.
    path_hijack: dict = field(default_factory=dict)
    # Claude Code hook-config protection: {mode: deny|ask|monitor|off, allow:
    # [regex on path/command]}. Empty -> defaults (mode=ask) apply. Covers a
    # `hooks` entry planted in `.claude/settings.local.json` — the
    # project-local, gitignored-by-default sibling of `.claude/settings.json`
    # (already fully blocked by self-protect) that Claude Code reads and
    # merges hooks from with equal authority, and that no other guard
    # reaches. See rules.rule_claude_hooks_protect.
    claude_hooks: dict = field(default_factory=dict)
    # Claude Code statusline-hijack protection: {mode: deny|ask|monitor|off,
    # allow: [regex on path/command]}. Empty -> defaults (mode=ask) apply.
    # Covers a `statusLine.command` entry planted in
    # `.claude/settings.local.json` -- the same file `claude_hooks` guards
    # for its `hooks` key -- which Claude Code spawns directly and
    # re-invokes on an ongoing UI-refresh cadence, with no future tool-call/
    # git/CI/session-restart trigger needed at all, unlike every other
    # auto-exec surface this file guards. See rules.rule_statusline_protect.
    statusline: dict = field(default_factory=dict)
    # pytest conftest.py auto-exec-on-collection protection: {mode:
    # deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers a conftest.py carrying a
    # module-level process/code-exec call, an auto-invoked pytest hook
    # (pytest_configure, pytest_sessionstart, ...) wrapping one, or an
    # autouse=True fixture wrapping one -- pytest auto-imports every
    # conftest.py on the very next `pytest` invocation, no opt-in needed.
    # See rules.rule_conftest_protect.
    conftest: dict = field(default_factory=dict)
    # Python interpreter-startup auto-exec protection: {mode:
    # deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers a module-level process/code-exec
    # call in sitecustomize.py/usercustomize.py (CPython's `site` module
    # imports either unconditionally on every interpreter startup), or a
    # `.pth` file in site-packages/dist-packages/__pypackages__ carrying an
    # `import `-prefixed line CPython execs as code that itself invokes a
    # process/code-exec call -- runs on the very next `python`/`pytest`
    # invocation, no opt-in needed. See rules.rule_pysite_protect.
    pysite: dict = field(default_factory=dict)
    # IPython/Jupyter interpreter-startup auto-exec protection: {mode:
    # deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers a module-level process/code-exec
    # call in a `.ipython/profile_*/startup/` `.py`/`.ipy` file, or -- `.ipy`
    # only -- a bare `!<command>` shell-escape line: IPython runs every file
    # in the active profile's startup/ directory unconditionally on every
    # `ipython`/Jupyter-kernel launch, no opt-in needed. See
    # rules.rule_ipython_startup_protect.
    ipython_startup: dict = field(default_factory=dict)
    # Cloud-credential-provider exec hijack protection: {mode:
    # deny|ask|monitor|off, allow: [regex on path/command]}. Empty ->
    # defaults (mode=ask) apply. Covers an AWS CLI/SDK `credential_process`
    # directive (~/.aws/config, ~/.aws/credentials, or the `aws configure
    # set` CLI form) and a Kubernetes kubeconfig `exec:` credential-plugin
    # block (~/.kube/config, or the `kubectl config set-credentials
    # --exec-command` CLI form) -- both name an external command the
    # SDK/CLI executes and hands a live, freshly-minted credential to on
    # every future credential resolution through that profile/context. See
    # rules.rule_cloud_cred_exec_protect.
    cloud_cred_exec: dict = field(default_factory=dict)
    # Fetch-to-file backstop: {mode: deny|ask|monitor|off, allow: [regex on
    # command]}. Empty -> defaults (mode=ask) apply. Governs ONLY the
    # human-escapable tier -- a curl/wget/PowerShell/certutil fetch writing
    # its response directly to a path one of the OTHER *_protect guards
    # above already protects (git hooks, CI workflows, shell-persist,
    # package manifests, systemd/launchd, ld.so.preload, devcontainer,
    # VS Code tasks, Claude Code hooks, conftest.py, pysite, IPython
    # startup, ...). The never-escapable tier (Aegis's own
    # config/policy/source/skills, the same surface rule_self_protect
    # itself hard-blocks) has no config knob here at all -- it is checked
    # unconditionally, the same way rule_self_protect takes no policy
    # config. See rules.rule_fetch_to_file_protect.
    fetch_to_file: dict = field(default_factory=dict)
    # Context injection: {mode: on|off} — emit a policy-posture digest as
    # additionalContext on SessionStart and PostCompact so the rules the agent
    # runs under survive context compaction. Empty -> on. See aegis.context.
    inject: dict = field(default_factory=dict)
    # Failure-loop guard: {mode: deny|ask|monitor|off, max_repeats: int} — deny a
    # PreToolUse whose exact (tool, args) signature already failed max_repeats
    # times this session. Empty -> defaults (mode=deny, max_repeats=3) apply.
    # See rules.rule_failure_loop.
    failures: dict = field(default_factory=dict)
    # Completion verification: {require_tests: bool, patterns: [regex]} — opt-in
    # Stop gate: after file mutations, the session may not stop until a test run
    # is recorded after the last change. See lifecycle.session.
    completion: dict = field(default_factory=dict)
