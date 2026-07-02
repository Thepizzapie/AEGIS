"""The event model + tool/action taxonomy (AEGI-1).

Every runtime adapter normalizes its native hook payloads into these types, so
the policy engine stays runtime-agnostic. Nothing Claude-Code-specific lives
here — adapters (``aegis.adapters.*``) own the translation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class HookEvent(str, Enum):
    """Lifecycle points an agent runtime can hand to Aegis.

    Every Claude Code hook event maps to a member here so the enum is the single
    source of truth: the CLI gates on it, ``aegis install`` writes one settings.json
    entry per member, and the audit records every one. ``BLOCKABLE`` (below) marks
    the subset where an exit-2 deny actually stops the action; the rest are
    observational (accountability / audit only).
    """

    # --- enforcement points (a deny here BLOCKS) ---
    PRE_TOOL_USE = "PreToolUse"          # before a tool runs
    USER_PROMPT_SUBMIT = "UserPromptSubmit"  # before a prompt is processed
    PERMISSION_REQUEST = "PermissionRequest"  # permission dialog would appear
    ELICITATION = "Elicitation"          # MCP server asks the user for input
    ELICITATION_RESULT = "ElicitationResult"  # user answered an MCP elicitation
    SUBAGENT_STOP = "SubagentStop"       # a sub-agent finished (gate it)
    TASK_CREATED = "TaskCreated"         # a team task was created
    TASK_COMPLETED = "TaskCompleted"     # a team task was marked done (gate it)
    TEAMMATE_IDLE = "TeammateIdle"       # a teammate went idle
    CONFIG_CHANGE = "ConfigChange"       # settings/policy/skills changed mid-session
    PRE_COMPACT = "PreCompact"           # before context compaction
    WORKTREE_CREATE = "WorktreeCreate"   # a git worktree is being created
    STOP = "Stop"                        # the turn is ending (gate completion)

    # --- observational points (audit / accountability only) ---
    POST_TOOL_USE = "PostToolUse"        # after a tool succeeds
    POST_TOOL_USE_FAILURE = "PostToolUseFailure"  # after a tool fails
    SESSION_START = "SessionStart"       # inject rules / context
    SESSION_END = "SessionEnd"           # session terminates
    SETUP = "Setup"                      # --init/--maintenance bootstrap
    INSTRUCTIONS_LOADED = "InstructionsLoaded"  # CLAUDE.md / rules loaded
    SUBAGENT_START = "SubagentStart"     # a sub-agent was spawned
    NOTIFICATION = "Notification"        # runtime notification (idle / permission / auth)
    STOP_FAILURE = "StopFailure"         # turn ended on an API error
    POST_COMPACT = "PostCompact"         # after context compaction
    WORKTREE_REMOVE = "WorktreeRemove"   # a git worktree was removed
    CWD_CHANGED = "CwdChanged"           # working directory changed
    FILE_CHANGED = "FileChanged"         # a watched file (.env/.envrc) changed


# Events where an exit-2 deny meaningfully BLOCKS the action and the message is fed
# back to the model. Everything else is observational: a deny is surfaced, not enforced.
BLOCKABLE = frozenset({
    HookEvent.PRE_TOOL_USE,
    HookEvent.USER_PROMPT_SUBMIT,
    HookEvent.PERMISSION_REQUEST,
    HookEvent.ELICITATION,
    HookEvent.ELICITATION_RESULT,
    HookEvent.SUBAGENT_STOP,
    HookEvent.TASK_CREATED,
    HookEvent.TASK_COMPLETED,
    HookEvent.TEAMMATE_IDLE,
    HookEvent.CONFIG_CHANGE,
    HookEvent.PRE_COMPACT,
    HookEvent.WORKTREE_CREATE,
    HookEvent.STOP,
})


class ActionClass(str, Enum):
    """Normalized class of what a tool *does*, across runtimes. Policy can target
    a whole class (e.g. deny all ``shell``) without knowing per-runtime tool
    names."""

    READ = "read"
    EDIT = "edit"
    WRITE = "write"
    SHELL = "shell"
    GIT = "git"
    SUBAGENT = "subagent"
    MCP = "mcp"
    NET = "net"
    OTHER = "other"


# Common tool name (lowercased) -> ActionClass. Adapters may override per runtime.
_TOOL_CLASS = {
    "read": ActionClass.READ,
    "glob": ActionClass.READ,
    "grep": ActionClass.READ,
    "ls": ActionClass.READ,
    "edit": ActionClass.EDIT,
    "multiedit": ActionClass.EDIT,
    "notebookedit": ActionClass.EDIT,
    "write": ActionClass.WRITE,
    "bash": ActionClass.SHELL,
    "powershell": ActionClass.SHELL,
    "shell": ActionClass.SHELL,
    "task": ActionClass.SUBAGENT,
    "agent": ActionClass.SUBAGENT,
    "webfetch": ActionClass.NET,
    "websearch": ActionClass.NET,
}


def classify(tool: Optional[str]) -> ActionClass:
    """Best-effort tool-name -> ActionClass. ``mcp__server__tool`` -> MCP. A
    shell command that happens to run git is still ``shell`` here (we only see
    the tool name); adapters can refine ``shell`` -> ``git`` from the command."""
    if not tool:
        return ActionClass.OTHER
    t = tool.strip().lower()
    if t.startswith("mcp__"):
        return ActionClass.MCP
    return _TOOL_CLASS.get(t, ActionClass.OTHER)


@dataclass
class Event:
    """A normalized hook event. ``raw`` keeps the original payload for adapters
    and audit."""

    event: HookEvent
    tool: Optional[str] = None
    action: ActionClass = ActionClass.OTHER
    args: dict = field(default_factory=dict)
    identity: Optional[str] = None
    roles: list = field(default_factory=list)
    session_id: Optional[str] = None
    agent: Optional[str] = None
    cwd: Optional[str] = None
    # Lifecycle-event fields (sub-agent / team / worktree hooks). Populated by the
    # adapter from the native payload when present; None for tool-use events.
    agent_id: Optional[str] = None     # SubagentStart/Stop, TeammateIdle
    agent_type: Optional[str] = None   # the sub-agent / teammate type
    worktree: Optional[str] = None     # WorktreeCreate/Remove path
    matcher: Optional[str] = None      # the event's matcher value (config type,
                                       # notification type, compaction type, reason)
    raw: dict = field(default_factory=dict)

    @classmethod
    def make(cls, event, tool: Optional[str] = None, **kw) -> "Event":
        """Construct an Event, auto-classifying ``action`` from ``tool`` unless
        an explicit ``action`` is passed."""
        action = kw.pop("action", None) or classify(tool)
        return cls(event=HookEvent(event), tool=tool, action=action, **kw)
