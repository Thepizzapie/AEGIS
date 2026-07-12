"""Cloud instance-metadata SSRF guard (containment-cloud-metadata).

Threat model: an agent running inside a cloud VM/container (AWS/Azure/GCP/...)
fetches the link-local instance-metadata service — reachable from on-box with
no auth — and walks off with live IAM/service-account credentials or user-data
secrets. The trigger doesn't have to be a deliberate attack by the model: a
prompt-injected web page, a malicious repo's setup instructions, or a
compromised dependency's install step can all steer an otherwise-normal agent
into curling http://169.254.169.254/. This is the SSRF-to-IMDS path behind real
breaches (e.g. Capital One, 2019). Non-escapable, like the rest of containment:
'# aegis-allow' must NOT waive it, and it applies with NO policy configuration
(unlike rule_network_egress, which is opt-in).
"""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy

EMPTY = Policy()  # default-allow; built-ins still apply


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _webfetch(url):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="WebFetch", args={"url": url})


def _mcp_fetch(url):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fetch__fetch", args={"url": url})


def _mcp_arbitrary_key(key, url):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__browser__navigate", args={key: url})


def _websearch(query):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="WebSearch", args={"query": query})


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                       args={"file_path": path, "content": content})


# --- blocked: the canonical endpoint, across surfaces ------------------------

def test_curl_to_metadata_ip_blocked():
    d = evaluate(_shell("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_wget_to_metadata_ip_blocked():
    assert evaluate(_shell("wget -qO- http://169.254.169.254/latest/meta-data/"), EMPTY).blocked


def test_invoke_webrequest_to_metadata_ip_blocked():
    cmd = 'Invoke-WebRequest -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{Metadata="true"}'
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_gcp_metadata_hostname_blocked():
    cmd = 'curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/'
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_alibaba_metadata_ip_blocked():
    assert evaluate(_shell("curl http://100.100.100.200/latest/meta-data/"), EMPTY).blocked


def test_aws_ipv6_metadata_blocked():
    assert evaluate(_shell("curl -g -6 'http://[fd00:ec2::254]/latest/meta-data/'"), EMPTY).blocked


def test_webfetch_tool_metadata_blocked():
    d = evaluate(_webfetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/role"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_mcp_fetch_tool_metadata_blocked():
    d = evaluate(_mcp_fetch("http://169.254.169.254/latest/meta-data/"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


# --- blocked: encoded/shorthand forms of the same IP -------------------------

def test_decimal_encoded_ip_blocked():
    assert evaluate(_shell("curl http://2852039166/latest/meta-data/"), EMPTY).blocked


def test_hex_encoded_ip_blocked():
    assert evaluate(_shell("curl http://0xa9fea9fe/latest/meta-data/"), EMPTY).blocked


def test_dotted_shorthand_ip_blocked():
    assert evaluate(_shell("curl http://169.254.43518/latest/meta-data/"), EMPTY).blocked


def test_two_part_dotted_shorthand_ip_blocked():
    assert evaluate(_shell("curl http://169.16689662/latest/meta-data/"), EMPTY).blocked


def test_dotted_hex_form_blocked():
    assert evaluate(_shell("curl http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/"), EMPTY).blocked


def test_octal_form_blocked():
    assert evaluate(_shell("curl http://0251.0376.0251.0376/latest/meta-data/"), EMPTY).blocked


def test_ipv6_mapped_hex_group_blocked():
    assert evaluate(_shell("curl -6 'http://[::ffff:a9fe:a9fe]/latest/meta-data/'"), EMPTY).blocked


# --- MCP: the target URL can sit under ANY argument key (round-1 QA finding) --

def test_mcp_tool_arbitrary_key_name_blocked():
    d = evaluate(_mcp_arbitrary_key("target", "http://169.254.169.254/latest/meta-data/"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_mcp_tool_href_key_blocked():
    assert evaluate(_mcp_arbitrary_key("href", "http://169.254.169.254/"), EMPTY).blocked


def test_mcp_tool_nested_arg_blocked():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__browser__fetch",
                     args={"input": {"request": {"url": "http://169.254.169.254/"}}})
    assert evaluate(ev, EMPTY).blocked


# --- scope: WebSearch queries and file content ARE NOT fetches (round-2 QA) --

def test_websearch_query_mentioning_ip_not_blocked():
    # researching the topic is not an attempt to reach the endpoint
    q = "how does the 169.254.169.254 cloud metadata SSRF attack work"
    assert not evaluate(_websearch(q), EMPTY).blocked


def test_writing_file_that_mentions_ip_not_blocked():
    # documenting/blocking the address in a firewall rule, blog post, or this
    # guard's own test file must not itself be denied — it isn't a fetch
    content = "deny egress to 169.254.169.254  # block cloud metadata SSRF"
    assert not evaluate(_write("infra/firewall.rules", content), EMPTY).blocked


def test_editing_this_own_test_file_not_blocked():
    # rewriting this very file (dense with the literal IP) must not deadlock
    with open(__file__, "r", encoding="utf-8") as f:
        own_content = f.read()
    assert not evaluate(_write("tests/test_cloud_metadata.py", own_content), EMPTY).blocked


# --- scope: a shell command must REACH the endpoint, not just mention it -----
# (round-3 QA: a bare substring search over the whole shell command denied a
# security-audit grep, a git commit message, and a firewall-rule echo line —
# none of which make an outbound request.)

def test_shell_grep_for_ip_not_blocked():
    assert not evaluate(_shell("grep -r 169.254.169.254 ."), EMPTY).blocked


def test_shell_commit_message_mentioning_ip_not_blocked():
    cmd = 'git commit -m "block 169.254.169.254 in the firewall"'
    assert not evaluate(_shell(cmd), EMPTY).blocked


def test_shell_echo_to_firewall_rule_not_blocked():
    assert not evaluate(_shell('echo "deny 169.254.169.254" >> firewall.rules'), EMPTY).blocked


# --- MCP arg scanning survives deep nesting ----------------------------------

def test_mcp_deeply_nested_arg_blocked():
    deep = {"input": {"params": {"request": {"target": {"nested":
            "http://169.254.169.254/latest/meta-data/"}}}}}
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__browser__navigate", args=deep)
    assert evaluate(ev, EMPTY).blocked


# --- evasion: de-obfuscated surfaces still catch it --------------------------

def test_inner_interpreter_metadata_fetch_blocked():
    cmd = "bash -c \"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\""
    assert evaluate(_shell(cmd), EMPTY).blocked


# --- coverage beyond curl/wget: a fetch-verb ALLOWLIST was tried and reverted
# (round-4 QA) because it's trivially routed around by any tool not on the
# list. These lock in that the guard catches the fetch regardless of
# *mechanism* — bash's raw /dev/tcp device, other language runtimes, and
# lesser-known downloaders — not just the couple of tools an allowlist would
# have enumerated.

def test_bash_dev_tcp_blocked():
    cmd = 'exec 3<>/dev/tcp/169.254.169.254/80; echo -e "GET / HTTP/1.0\\r\\n\\r\\n" >&3; cat <&3'
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_perl_one_liner_blocked():
    cmd = "perl -MLWP::Simple -e 'getprint(\"http://169.254.169.254/latest/meta-data/\")'"
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_ruby_one_liner_blocked():
    cmd = 'ruby -rnet/http -e \'Net::HTTP.get(URI("http://169.254.169.254/"))\''
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_php_one_liner_blocked():
    cmd = 'php -r \'file_get_contents("http://169.254.169.254/");\''
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_socat_blocked():
    assert evaluate(_shell("socat - TCP:169.254.169.254:80"), EMPTY).blocked


def test_openssl_s_client_blocked():
    assert evaluate(_shell("openssl s_client -connect 169.254.169.254:80"), EMPTY).blocked


def test_aria2c_blocked():
    assert evaluate(_shell("aria2c http://169.254.169.254/latest/meta-data/"), EMPTY).blocked


def test_axel_blocked():
    assert evaluate(_shell("axel http://169.254.169.254/latest/meta-data/"), EMPTY).blocked


# --- the mention-only exemption cannot be abused to smuggle a real fetch -----

def test_grep_prefix_cannot_smuggle_a_real_fetch():
    # a leading benign verb followed by a REAL fetch after a separator must
    # still be blocked — the exemption requires the ENTIRE command match the
    # benign shape, not just its first word
    cmd = "grep 169.254.169.254 /etc/hosts; curl http://169.254.169.254/latest/meta-data/ -o /tmp/x"
    assert evaluate(_shell(cmd), EMPTY).blocked


# --- the exemption can't be smuggled past via substitution either (round-5) --
# `;`/`&`/`|` aren't the only way to run a second command: process
# substitution (`<(...)`/`>(...)`) and command substitution (`$(...)`/
# backticks) run one too, without any of those separator characters.

def test_grep_with_process_substitution_fetch_blocked():
    cmd = "grep foo <(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/)"
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_echo_with_command_substitution_fetch_blocked():
    cmd = "echo start $(curl http://169.254.169.254/latest/meta-data/)"
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_echo_with_backtick_substitution_fetch_blocked():
    cmd = "echo `curl http://169.254.169.254/latest/meta-data/`"
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_git_commit_with_command_substitution_fetch_blocked():
    cmd = 'git commit -m "$(curl http://169.254.169.254/latest/meta-data/)"'
    assert evaluate(_shell(cmd), EMPTY).blocked


# --- /dev/tcp is itself a network reach, even through a bare redirect (round-6)

def test_echo_redirect_to_dev_tcp_blocked():
    cmd = 'echo "GET /latest/meta-data/ HTTP/1.0" > /dev/tcp/169.254.169.254/80'
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_grep_input_redirect_from_dev_tcp_blocked():
    assert evaluate(_shell("grep foo < /dev/tcp/169.254.169.254/80"), EMPTY).blocked


# --- ANSI-C-quoted /dev/tcp still resolves to the same device (round-7 QA) ---
# bash's `$'...'`/`$"..."` quoting expands to plain text before the redirect
# target is resolved — `/dev/$'tcp'/HOST/PORT` opens the exact same socket as
# `/dev/tcp/HOST/PORT` (verified against real bash: both produce a live
# "Connection refused" from the kernel, not a file-not-found). This exercises
# the fix in aegis/normalize.py (_ANSIC_QUOTE_RE) that decodes it for every
# pattern in the codebase, not just this guard.

def test_ansic_quoted_dev_tcp_echo_blocked():
    cmd = "echo \"GET / HTTP/1.0\" > /dev/$'tcp'/169.254.169.254/80"
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_ansic_quoted_dev_tcp_grep_blocked():
    assert evaluate(_shell("grep foo < /dev/$'tcp'/169.254.169.254/80"), EMPTY).blocked


def test_locale_quoted_dev_tcp_blocked():
    assert evaluate(_shell('grep foo < /dev/$"tcp"/169.254.169.254/80'), EMPTY).blocked


def test_python_inline_metadata_fetch_blocked():
    cmd = "python3 -c \"import urllib.request; urllib.request.urlopen('http://169.254.169.254/latest/meta-data/')\""
    assert evaluate(_shell(cmd), EMPTY).blocked


# --- non-escapable: same tier as containment-credentials ---------------------

def test_not_escapable():
    cmd = "curl http://169.254.169.254/latest/meta-data/  # aegis-allow"
    assert evaluate(_shell(cmd), EMPTY).blocked


def test_not_escapable_as_spawned_agent(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    cmd = "curl http://169.254.169.254/latest/meta-data/  # aegis-allow"
    assert evaluate(_shell(cmd), EMPTY).blocked


# --- allowed: ordinary network activity is untouched -------------------------

def test_ordinary_curl_allowed():
    assert not evaluate(_shell("curl https://api.github.com/repos/foo/bar"), EMPTY).blocked


def test_ordinary_webfetch_allowed():
    assert not evaluate(_webfetch("https://docs.python.org/3/library/urllib.html"), EMPTY).blocked


def test_unrelated_local_ip_allowed():
    # a routine internal address must not false-positive off a partial-octet match
    assert not evaluate(_shell("curl http://169.254.1.1/health"), EMPTY).blocked
