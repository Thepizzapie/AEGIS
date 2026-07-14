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
from pathlib import Path

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


def test_mcp_pathlike_credential_argument_blocked():
    # QA round 7: aegis.mcp.guarded/check is a real embedding path where
    # ev.args are an MCP server's own live Python **kwargs, not JSON — a
    # filesystem-style tool handler written as `def read_file(path: Path)`
    # (an entirely ordinary signature) hands a real pathlib.Path/bytes
    # object, not a str. _flatten_strings previously fell through every
    # isinstance check to the empty-list default for those types, so the
    # value vanished from scanning entirely — a fully-escapable containment
    # guard for any tool taking a non-str argument type.
    d = evaluate(_mcp("mcp__filesystem__read_file", {"path": Path("/home/user/.ssh/id_rsa")}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"
    d2 = evaluate(_mcp("mcp__filesystem__read_file", {"path": Path(".aws/credentials")}), EMPTY)
    assert d2.blocked and d2.rule == "containment-credentials"
    d3 = evaluate(_mcp("mcp__filesystem__read_file", {"path": b"/home/user/.ssh/id_rsa"}), EMPTY)
    assert d3.blocked and d3.rule == "containment-credentials"


def test_mcp_pathlike_ordinary_argument_not_blocked():
    d = evaluate(_mcp("mcp__filesystem__read_file", {"path": Path("src/app.py")}), EMPTY)
    assert not d.blocked


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


def test_mcp_relative_persistence_path_blocked():
    # QA round 6: PERSIST_RE has the identical bare-relative-path gap
    # CRED_RE had — its registry-Run-key and Start-Menu-Startup alternatives
    # both require a literal leading separator, so an MCP filesystem/
    # registry tool's relative path/key argument bypassed it untouched.
    # Fixed with PERSIST_RELATIVE_RE (patterns.py), same per-value-anchored
    # design as CRED_RELATIVE_RE.
    d = evaluate(_mcp("mcp__filesystem__write_file",
                       {"path": "Start Menu/Programs/Startup/evil.bat", "content": "x"}), EMPTY)
    assert d.blocked and d.rule == "containment-persistence"
    d2 = evaluate(_mcp("mcp__registry__set_value",
                        {"key": "CurrentVersion\\Run", "value": "evil.exe"}), EMPTY)
    assert d2.blocked and d2.rule == "containment-persistence"


def test_mcp_relative_startup_mention_not_blocked():
    # regression: an ordinary mention of "Start Menu" / "Programs" text (not
    # an actual Startup-folder path) must not trip the new relative check.
    d = evaluate(_mcp("mcp__wiki__create_page",
                       {"content": "Open Start Menu and go to Programs."}), EMPTY)
    assert not d.blocked


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
# (round 3, a THIRD independent agent, later found the first fix for the
# relative-path gap regressed into a false-positive — see the section below.
# The final design: CRED_RELATIVE_RE, matched per-argument-value with full
# anchoring, not a CRED_RE substring relaxation.)

def test_mcp_relative_credential_path_blocked():
    # CRED_RE's directory alternatives require a LEADING path separator
    # (`/.aws/...`) — a bare relative path (the routine shape for a
    # filesystem-style MCP tool's `path` argument) has no separator in front
    # and would sail through untouched. Fixed via CRED_RELATIVE_RE (patterns.py),
    # matched against each individual flattened argument value, not a joined
    # blob — see the false-positive regression this avoided, below.
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


def test_mcp_double_percent_encoded_credential_path_blocked():
    # QA round 3: a single unquote() pass left double-encoded input
    # (%252F...) one layer short of the literal text any pattern matches.
    # _net_text now decodes to a fixpoint (bounded).
    d = evaluate(_mcp("mcp__filesystem__read_file",
                       {"path": "%252Fhome%252Fuser%252F.ssh%252Fid_rsa"}), EMPTY)
    assert d.blocked and d.rule == "containment-credentials"


def test_mcp_relative_credential_path_with_incidental_whitespace_or_quotes_blocked():
    # QA round 4: CRED_RELATIVE_RE's full-value anchor (^...$) was matched
    # against the RAW flattened value — a stray leading space/tab (a value
    # built by string concatenation, or just copied with incidental
    # whitespace) or a value the tool call happened to hand over still quoted
    # defeated the `^` anchor silently. _strip_value() trims both before the
    # anchored match.
    for path in (" .aws/credentials", "\t.aws/credentials",
                 '".aws/credentials"', "'.aws/credentials'"):
        d = evaluate(_mcp("mcp__filesystem__read_file", {"path": path}), EMPTY)
        assert d.blocked and d.rule == "containment-credentials", path


def test_mcp_relative_credential_path_with_wider_wrapping_blocked():
    # QA round 6: _STRIP_CHARS was still missing NBSP, backticks, guillemets,
    # and a literal two-character `\"` (double-JSON-escaped quote) sequence —
    # each defeated CRED_RELATIVE_RE's anchor identically to the already-fixed
    # curly-quote case.
    for path in ("\xa0.aws/credentials\xa0", "`.kube/config`",
                 "\xab.azure/credentials\xbb", "\\\".ssh/authorized_keys"):
        d = evaluate(_mcp("mcp__filesystem__read_file", {"path": path}), EMPTY)
        assert d.blocked and d.rule == "containment-credentials", path


def test_mcp_relative_credential_path_with_unmatched_leading_quote_blocked():
    # QA round 5: _strip_value's first implementation only stripped a
    # MATCHED quote pair (s[0] == s[-1]) — a single unmatched leading quote
    # with no closing quote left the leading character in place, defeating
    # the anchor identically. str.strip(chars) strips each end
    # independently and fixes this for .aws/.azure/.gnupg/.kube/.netrc and
    # non-keyword .ssh paths that don't happen to contain id_rsa/id_ed25519.
    for path in ('".aws/credentials', "'.kube/config", '".ssh/authorized_keys',
                 "'.azure/credentials", '".gnupg/id', "'.netrc"):
        d = evaluate(_mcp("mcp__filesystem__read_file", {"path": path}), EMPTY)
        assert d.blocked and d.rule == "containment-credentials", path


# --- QA round 3 (independent agent): a fix that became a worse regression ---
# The FIRST attempt at closing the relative-path gap broadened CRED_RE itself
# to also treat whitespace/start-of-string/a quote as a valid leading edge —
# and that turned "Cookies"/"Web Data" (ordinary English words/phrases) and a
# .gitignore's `.aws/`/`.ssh/` entries (routine, GOOD security practice) into
# false positives on a NEVER-ESCAPABLE guard. That relaxation was reverted;
# these lock the reverted behavior in as a regression test.

def test_gitignore_content_mentioning_credential_dirs_not_blocked():
    content = ".aws/\n.ssh/\nnode_modules/\n"
    assert not evaluate(_mcp("mcp__filesystem__write_file",
                              {"path": ".gitignore", "content": content}), EMPTY).blocked


def test_ordinary_word_cookies_not_blocked():
    d = evaluate(_mcp("mcp__wiki__create_page",
                       {"content": "This site uses Cookies to remember your preferences."}),
                 EMPTY)
    assert not d.blocked


def test_ordinary_phrase_web_data_not_blocked():
    d = evaluate(_mcp("mcp__wiki__create_page",
                       {"content": "The report includes Web Data for the last quarter."}),
                 EMPTY)
    assert not d.blocked


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
