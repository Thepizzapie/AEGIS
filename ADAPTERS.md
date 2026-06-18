# Aegis runtime adapters

Aegis enforcement is hook-based, so each agent runtime needs an adapter that maps
its hook payloads to Aegis's event model and renders the decision back. An adapter
is a module exposing:

```python
parse_event(payload: dict) -> Event
render_decision(event: Event, decision: Decision) -> (exit_code, stdout, stderr)
```

registered in [`aegis/adapters/__init__.py`](aegis/adapters/__init__.py) and
selectable via `aegis hook --runtime <name>`.

## Status

| Runtime | Hook surface | Adapter | Status |
|---|---|---|---|
| **Claude Code** | native `PreToolUse` / `PostToolUse` / `SessionStart` / `Stop` / `UserPromptSubmit` | `claude-code` | ✅ shipped (AEGI-2) |
| **Any command-hook runtime** | normalized JSON over stdin/stdout | `generic` | ✅ shipped (AEGI-7) |
| **git / CI** | `pre-commit` / `pre-push` / CI action | git surface | ✅ shipped (AEGI-5) |
| Cursor | rules + command hooks (assessing) | `generic` | ⏳ assess |
| Codex CLI | command hooks (assessing) | `generic` | ⏳ assess |
| GitHub Copilot | limited client hooks | git/CI floor | ⏳ assess |
| Windsurf | command hooks (assessing) | `generic` | ⏳ assess |
| Devin | no local hook surface | git/CI floor | ⏳ assess |

**Coverage strategy:** a runtime with a native hook surface gets a bespoke adapter
(Claude Code). A runtime that can "run a command" on tool use points that command
at `aegis hook --runtime generic` (the normalized JSON contract below). A runtime
with **no** usable hook surface is still covered by the **git/CI surface**
(AEGI-5), which enforces the same policy at the change boundary regardless of which
agent produced the change.

## The generic JSON contract

Input (stdin):

```json
{"event": "PreToolUse", "tool": "Bash", "args": {"command": "..."},
 "identity": "alice", "roles": ["dev"], "session_id": "s1", "cwd": "/repo"}
```

Output (stdout):

```json
{"decision": "deny", "rule": "no-shell", "message": "blocked"}
```

Exit code: **2 = deny (block the action)**, 0 = allow / ask.
