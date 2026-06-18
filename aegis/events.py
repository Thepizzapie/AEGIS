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
    """Lifecycle points an agent runtime can hand to Aegis."""

    PRE_TOOL_USE = "PreToolUse"        # before a tool runs — the only point that can BLOCK
    POST_TOOL_USE = "PostToolUse"      # after a tool runs — observe / audit
    SESSION_START = "SessionStart"     # inject rules / context
    STOP = "Stop"                      # gate completion
    USER_PROMPT_SUBMIT = "UserPromptSubmit"


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
    raw: dict = field(default_factory=dict)

    @classmethod
    def make(cls, event, tool: Optional[str] = None, **kw) -> "Event":
        """Construct an Event, auto-classifying ``action`` from ``tool`` unless
        an explicit ``action`` is passed."""
        action = kw.pop("action", None) or classify(tool)
        return cls(event=HookEvent(event), tool=tool, action=action, **kw)
