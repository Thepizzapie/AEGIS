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


# --- evasion: de-obfuscated surfaces still catch it --------------------------

def test_inner_interpreter_metadata_fetch_blocked():
    cmd = "bash -c \"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\""
    assert evaluate(_shell(cmd), EMPTY).blocked


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
