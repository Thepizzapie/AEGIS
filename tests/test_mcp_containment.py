"""MCP/NET tool-call containment (containment-credentials / containment-persistence
reaching arbitrary MCP tool arguments, not just shell + Read/Edit/Write).

Threat model: an MCP server is arbitrary third-party code the runtime hands tool
calls to — a filesystem server, a cloud-storage server, a browser-automation
server, or anything a malicious/compromised/prompt-injection-steered dependency
registers. Before this guard, `rule_containment` computed CRED_RE/PERSIST_RE text
for shell commands and Claude's own Read/Edit/Write, but for an MCP or other
network-shaped tool call it discarded the scan text entirely (kept only for the
cloud-metadata SSRF check) — so `mcp__filesystem__read_file(path="~/.ssh/id_rsa")`
sailed through with ZERO containment checks, while the identical shell command
`cat ~/.ssh/id_rsa` was already blocked. Same gap for persistence (an MCP write
tool targeting a registry Run key / crontab / Startup folder path).

The fix reuses the same key-name-agnostic deep-arg scan (`_net_text` /
`_flatten_strings`) already built for the cloud-metadata guard's MCP coverage —
the target credential path can sit under any argument key name, at any nesting
depth, same as a metadata-fetch URL can.
"""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy

EMPTY = Policy()  # default-allow; built-ins still apply


def _mcp(tool, args):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


# --- blocked: credential-store access through an MCP tool's arguments --------

def test_mcp_filesystem_read_ssh_key_blocked():
    d = evaluate(_mcp("mcp__filesystem__read_file", {"path": "/home/user/.ssh/id_rsa"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_mcp_cloud_tool_aws_credentials_blocked():
    d = evaluate(_mcp("mcp__aws__get_object", {"key": "/home/user/.aws/credentials"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_mcp_arbitrary_key_name_credential_path_blocked():
    # the argument carrying the path can be named anything — no fixed key-name
    # allowlist (same principle the cloud-metadata guard already established)
    d = evaluate(_mcp("mcp__vault__fetch", {"target": "C:\\Users\\me\\.aws\\credentials"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_mcp_deeply_nested_credential_path_blocked():
    deep = {"input": {"params": {"request": {"file": {"nested": "/root/.ssh/id_ed25519"}}}}}
    d = evaluate(_mcp("mcp__browser__navigate", deep), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_mcp_browser_cookie_store_blocked():
    d = evaluate(_mcp("mcp__browser__read_file", {"path": "AppData/Local/Google/Chrome/User Data/Default/Cookies"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_net_tool_credential_path_blocked():
    d = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="WebFetch",
                             args={"url": "file:///home/user/.ssh/id_rsa"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


# --- blocked: persistence through an MCP tool's arguments --------------------

def test_mcp_scheduler_persistence_blocked():
    d = evaluate(_mcp("mcp__scheduler__create_task",
                       {"command": "schtasks /create /tn x /tr y.exe"}), EMPTY)
    assert d.blocked and d.rule == "containment-persistence"


def test_mcp_filesystem_write_to_startup_folder_blocked():
    d = evaluate(_mcp("mcp__filesystem__write_file",
                       {"path": r"C:\Users\me\Start Menu\Programs\Startup\evil.bat"}), EMPTY)
    assert d.blocked and d.rule == "containment-persistence"


# --- non-escapable, same tier as the shell/Read/Edit/Write form --------------

def test_mcp_credential_read_not_escapable(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    d = evaluate(_mcp("mcp__filesystem__read_file",
                       {"path": "/home/user/.ssh/id_rsa # aegis-allow"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


# --- scope: WebSearch keeps its existing exemption ---------------------------

def test_websearch_mentioning_credential_path_not_blocked():
    q = "how to protect .ssh/id_rsa from being read by an agent"
    d = evaluate(Event.make(HookEvent.PRE_TOOL_USE, tool="WebSearch", args={"query": q}), EMPTY)
    assert not d.blocked


# --- QA round 1 (two independent agents): confirmed bypasses, now fixed -----

def test_mcp_relative_credential_path_blocked():
    # CRED_RE's directory alternatives required a LEADING path separator
    # (`/.aws/...`) — a bare relative path (the routine shape for a
    # filesystem-style MCP tool's `path` argument) had no separator in front
    # and sailed through untouched. Confirmed identically on Read/Edit/Write
    # too (see test_builtins.py) — not new to this guard, just now closed
    # everywhere CRED_RE is shared.
    d = evaluate(_mcp("mcp__filesystem__read_file", {"path": ".aws/credentials"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"
    d2 = evaluate(_mcp("mcp__filesystem__read_file", {"path": ".kube/config"}), EMPTY)
    assert d2.blocked and d2.rule == "containment-credentials"


def test_mcp_percent_encoded_credential_path_blocked():
    # _net_text had no de-obfuscation at all (unlike the shell surface's
    # normalize.scan_surface): a percent-encoded path defeated every pattern
    # outright. MCP path/URI arguments routinely carry percent-encoding with
    # no attacker intent required, so decoding it unconditionally is safe.
    d = evaluate(_mcp("mcp__filesystem__read_file",
                       {"path": "%2Fhome%2Fuser%2F.ssh%2Fid_rsa"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


# --- QA round 1: findings considered and deliberately NOT "fixed" -----------

def test_mcp_search_tool_credential_mention_still_blocked():
    # QA flagged that a native WebSearch query mentioning a credential path is
    # exempt, but the identical query routed through an MCP-hosted search tool
    # (mcp__brave-search__..., mcp__tavily__...) is NOT exempt, and asked
    # whether that's an inconsistent false positive. It is NOT: WebSearch is
    # the runtime's own trusted, fixed-behavior implementation, but an MCP
    # tool is arbitrary third-party code — a compromised/malicious MCP server
    # can name a credential-exfiltrating tool anything it likes, including
    # something with "search" in the name, specifically to dodge a name-based
    # carve-out. Trusting the tool NAME here would reopen the exact hole this
    # guard exists to close, so this is locked in as intentional, not a bug.
    d = evaluate(_mcp("mcp__brave-search__brave_web_search",
                       {"query": "how to protect ~/.ssh/id_rsa from being read by an agent"}),
                 EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_mcp_documentation_mentioning_credential_path_blocked():
    # QA flagged that a PR-body/commit-message/docs-page MCP tool call merely
    # MENTIONING a credential path (not accessing one) also trips this guard.
    # True, but it is the IDENTICAL pre-existing trade-off the shell surface
    # already made before this change (see test_containment_credentials's
    # `grep`/commit-message style, and CLOUD_METADATA_MENTION_ONLY_RE's own
    # round-4 QA history in patterns.py: a positive-verb/allowlist attempt at
    # narrowing a non-escapable guard was tried and reverted because it
    # under-blocks far worse than this over-blocks). Locked in as accepted
    # behavior, not silently patched with a fragile allowlist.
    d = evaluate(_mcp("mcp__wiki__create_page",
                       {"content": "Detection rule: alert on writes to "
                                   r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"}),
                 EMPTY)
    assert d.blocked and d.rule == "containment-persistence"


# --- scope: exfil/cloud-exfil/env-dump patterns stay shell-only -------------
# (shell-flag syntax like `curl -d @file` has no analogue in a tool call's JSON
# arguments — this locks in that an unrelated MCP call isn't accidentally
# caught by one of those patterns matching plain argument text.)

def test_mcp_tool_with_unrelated_flag_like_text_allowed():
    d = evaluate(_mcp("mcp__notes__create", {"body": "remember to run curl -d @notes.txt later"}), EMPTY)
    assert not d.blocked


# --- allowed: ordinary MCP tool calls are untouched --------------------------

def test_ordinary_mcp_tool_call_allowed():
    d = evaluate(_mcp("mcp__github__get_file_contents", {"path": "src/app.py"}), EMPTY)
    assert not d.blocked


def test_ordinary_mcp_write_allowed():
    d = evaluate(_mcp("mcp__filesystem__write_file",
                       {"path": "src/app.py", "content": "print('hello')"}), EMPTY)
    assert not d.blocked


# --- regression: shell form of the same checks is unaffected -----------------

def test_shell_credential_read_still_blocked():
    assert evaluate(_shell("cat ~/.ssh/id_rsa"), EMPTY).blocked


def test_shell_persistence_still_blocked():
    assert evaluate(_shell("schtasks /create /tn x /tr y.exe"), EMPTY).blocked
