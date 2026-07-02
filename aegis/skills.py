"""Shipped agent skills (AEGI-20): the guidance half of enforcement.

Hooks are the teeth; these skills are the manual. Each is a Claude Code skill
(``.claude/skills/<name>/SKILL.md``) installed alongside the hooks by ``aegis
install`` so a blocked agent can self-correct instead of retry-looping, and a
human can ask the agent for its own rap sheet:

- **aegis-explain-block** — why the last action was denied + the compliant path.
  Deny messages point here (see the claude_code adapter), turning a hard deny
  into course-correction.
- **aegis-status** — the active posture: policy validity, knobs, guard surface.
- **aegis-report** — the accountability rap sheet from the audit trail.
- **aegis-policy** — how to change policy SAFELY (edit YAML + validate; never
  the enforcement files, which self-protect blocks anyway).

Every file carries a managed-by marker; install overwrites only its own files
(marker present or file absent) and uninstall removes only marked ones — the
same merge-never-clobber contract as the hook installer. The skills themselves
are guidance, not enforcement: self-protect blocks agents from rewriting them
(patterns.AEGIS_SKILL_PATH_RE), so the guidance can't be quietly subverted.
"""
from __future__ import annotations

from pathlib import Path

MARKER = "<!-- managed-by: aegis -->"

# Rule name -> one-line remedy, embedded in aegis-explain-block so the agent can
# map any deny to its compliant path without reading Aegis source.
_REMEDIES = """\
| rule | why it fired | the compliant path |
|---|---|---|
| containment-credentials | touched an SSH/cloud/browser/OS credential store | work without stored credentials; ask the human to provide scoped secrets |
| containment-persistence | installed autorun/service/scheduled-task persistence | don't persist; run the task in-session |
| containment-exfiltration | uploaded local files to the network | keep data local; the human can share files deliberately |
| self-protect | wrote/deleted Aegis config, policy, engine source, or an aegis-* skill | leave Aegis alone; ask the human to change policy via `aegis-policy` |
| mcp-config-protect | wrote an MCP server config (durable auto-run backdoor) | ask the human; they can set AEGIS_ALLOW_MCP_CONFIG=1 after review |
| workspace-confine | wrote outside the project root the identity is bound to | stay in the project; ask for workspace.allow if a path is legitimate |
| destructive-migration | destructive SQL / migration reset | use a reversible migration; a human may append '-- aegis-allow' |
| subagent-spawn | a spawned agent tried to spawn sub-agents | do the work in this session, or run with AEGIS_ALLOW_SUBAGENTS=1 |
| egress | network egress to a host outside policy | use an allowlisted host or ask for the allowlist to be widened |
| evasion | encoded/obfuscated command | run the command in the clear |
| failure-loop | identical retry of a call that already failed repeatedly | read the error; change the arguments or the approach — don't re-run it |
| remote-exec | fetch piped straight into a shell | download, read in full, then run the local copy |
| destructive-git | history-rewriting/force git | use git revert / branch -d; a human may append '# aegis-allow' |
| destructive-delete | recursive force delete | delete precisely; a human may append '# aegis-allow' |
| install-review | install of an unread/unpinned manifest | Read the manifest in FULL (no limit/offset), then retry |
| branch-strand | new branch while current one has unmerged commits | merge/push/PR the current branch first |
| config-change-protect | agent changed Aegis policy/settings mid-session | policy changes are human-only |
| permission-escalation | unattended agent hit a human-only permission prompt | use pre-approved actions only |
| elicitation-governance | MCP server requested user input in an unattended run | avoid elicitation-dependent servers when unattended |
| task-completion-gate | task marked done without recorded verification | verify (tests/review), record it, then complete |
| stop-verification-gate | stopping after edits with no post-edit test run | run the test suite, then stop |
| precompact-gate | auto-compaction while policy preserves context | checkpoint, then run a manual /compact |\
"""

SKILLS = {
    "aegis-explain-block": f"""---
name: aegis-explain-block
description: Explain why Aegis blocked the last action and give the compliant path forward. Use immediately after any "[Aegis] ..." denial message instead of retrying the blocked action.
---
{MARKER}

# What just happened

An Aegis policy hook denied the action BEFORE it ran. The denial is enforcement,
not advice: retrying the same action will produce the same deny, and every
attempt is recorded in the audit trail.

# Steps

1. Read the `[Aegis]` denial text — it names the rule and usually the remedy.
2. If you need detail, pull the most recent denials for this session:
   `aegis report --json` (look at `denials`, matched by your `session_id`).
3. Map the rule to its compliant path in the table below, do THAT instead.
4. Do not attempt to bypass: obfuscation, encoded commands, editing Aegis
   files, and `# aegis-allow` (honored only for humans) are all themselves
   guarded and recorded.

# Rule -> remedy

{_REMEDIES}
""",
    "aegis-status": f"""---
name: aegis-status
description: Show the active Aegis enforcement posture — policy validity, default action, active opt-in knobs, and where policy/audit live. Use when asked "what is aegis doing" or before changing how you work.
---
{MARKER}

# Steps

1. `aegis validate` — is the active policy well-formed, and which dir is it?
2. Read the policy YAML files it names (they are small) and summarize:
   `default_action`, `on_error`, workspace root, egress posture, and which
   opt-in knobs are on (`install_review`, `mcp_config`, `inject`, `failures`,
   `completion`, `team`, `compaction`, `permission`, `mcp`).
3. `aegis adapters` — which runtimes are wired.
4. Report the posture in a short table. Do NOT edit any of these files — use
   the `aegis-policy` skill for changes.
""",
    "aegis-report": f"""---
name: aegis-report
description: Produce the Aegis accountability rap sheet — who/which session did what, what was denied, token usage, and flagged sessions. Use when asked what an agent did, what it cost, or why a session is flagged.
---
{MARKER}

# Steps

1. `aegis report --json` (add `--audit <path>` for a non-default audit log).
2. Summarize: total events, denials (rule + tool + session), per-session usage
   (tokens/cost), and any flagged sessions.
3. Flags mean: `many-denials`/`mostly-denied` — the agent kept hitting policy;
   `high-failure-rate` — the session thrashed on failing tool calls;
   `orphaned-subagent` — sub-agents started but never reconciled.
4. For "who touched X": `aegis who --path <path>` or `aegis who --tool <tool>`.
""",
    "aegis-policy": f"""---
name: aegis-policy
description: Safely change Aegis policy — add/edit declarative rules or opt-in knobs in the policy YAML and validate. Use when asked to allow, deny, or gate something via Aegis.
---
{MARKER}

# Ground rules

- Policy lives in YAML (`aegis validate` prints the dir). Edit ONLY those YAML
  files. Never touch `.claude/settings.json` hook entries, `aegis/*.py`, or
  `.claude/skills/aegis-*` — self-protect denies it, and a spawned agent
  cannot override.
- If you are a spawned agent, policy changes are blocked by design
  (config-change-protect). Report the change you'd make and ask the human.

# Steps

1. `aegis validate` to locate the policy dir and confirm the current state.
2. Read the existing YAML; make the smallest change that expresses the intent:
   - declarative rule: `rules: [{{name, action: allow|deny|ask, tools/actions/
     events/argument_patterns/regex, message, priority}}]`
   - knobs: `default_action`, `egress`, `workspace`, `install_review`,
     `mcp_config`, `inject`, `failures`, `completion`, `team`, `compaction`,
     `permission`, `mcp`.
3. `aegis validate` again — it must pass before the change is real.
4. State what changed and which agents/sessions it affects.
""",
}


def skills_dir(claude_dir) -> Path:
    return Path(claude_dir) / "skills"


def install_skills(claude_dir) -> int:
    """Write the shipped skills under ``<claude_dir>/skills/``. Only writes a
    file that is absent or carries the managed marker (never clobbers a user's
    same-named skill). Returns how many files were written."""
    written = 0
    for name, content in SKILLS.items():
        target = skills_dir(claude_dir) / name / "SKILL.md"
        if target.exists():
            try:
                existing = target.read_text(encoding="utf-8")
            except Exception:
                continue
            if MARKER not in existing:
                continue  # user-owned file of the same name — leave it alone
            if existing == content:
                continue  # already current
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written += 1
    return written


def uninstall_skills(claude_dir) -> int:
    """Remove only the marker-tagged skill files this module installed (and
    their dirs when emptied). Returns how many files were removed."""
    removed = 0
    for name in SKILLS:
        target = skills_dir(claude_dir) / name / "SKILL.md"
        try:
            if not target.exists() or MARKER not in target.read_text(encoding="utf-8"):
                continue
            target.unlink()
            removed += 1
            try:
                target.parent.rmdir()  # only succeeds when empty — intended
            except OSError:
                pass
        except Exception:
            continue
    return removed
