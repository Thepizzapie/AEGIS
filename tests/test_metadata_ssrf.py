"""Cloud instance-metadata / IMDS SSRF containment (never escapable).

An agent with plain network access (no filesystem reach) can hit the
link-local cloud metadata service and pull the instance/task IAM role's live
credentials — a distinct surface from CRED_RE (which only sees filesystem
paths) and from egress (which is opt-in / policy-driven, so it says nothing
with a default, zero-config policy)."""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.loader import load_policy
from aegis.policy import Policy

EMPTY = Policy()  # default-allow; built-ins still apply


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _fetch(url):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="WebFetch", args={"url": url})


def _mcp_fetch(url):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__http__fetch", args={"url": url})


def _other_tool(name, **args):
    # A tool name the taxonomy can't classify (not WebFetch/WebSearch, no mcp__
    # prefix) -> ActionClass.OTHER. Regression test for the bypass an earlier
    # revision of this guard had: OTHER-classed tools were skipped entirely.
    return Event.make(HookEvent.PRE_TOOL_USE, tool=name, args=args)


def _write(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                       args={"file_path": path, "content": content})


def test_blocks_aws_imds_via_shell():
    d = evaluate(_shell("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_blocks_aws_ecs_task_creds_endpoint():
    assert evaluate(_shell("curl http://169.254.170.2/v2/credentials/abc"), EMPTY).blocked


def test_blocks_gcp_metadata_hostname_and_header():
    assert evaluate(_shell(
        "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/"
    ), EMPTY).blocked


def test_blocks_azure_and_generic_imds_ip():
    assert evaluate(_shell(
        "curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token'"
    ), EMPTY).blocked


def test_blocks_alibaba_imds():
    assert evaluate(_shell("wget http://100.100.100.200/latest/meta-data/"), EMPTY).blocked


def test_blocks_ip_encoding_bypasses():
    # decimal and hex encodings of 169.254.169.254 — a documented SSRF filter bypass
    assert evaluate(_shell("curl http://2852039166/latest/meta-data/"), EMPTY).blocked
    assert evaluate(_shell("curl http://0xa9fea9fe/latest/meta-data/"), EMPTY).blocked


def test_blocks_python_and_nc_requests():
    # NOTE: no internal ';' — the same-statement anchor (like EXFIL_RE/
    # PIPE_TO_SHELL_RE elsewhere in this file) stops at ;|&/newline, so a
    # semicolon-separated multi-statement -c payload is a known, accepted gap
    # consistent with the rest of the codebase's shell-scan heuristics.
    assert evaluate(_shell(
        "python3 -c \"requests.get('http://169.254.169.254/latest/meta-data/')\""
    ), EMPTY).blocked
    assert evaluate(_shell("nc 169.254.169.254 80"), EMPTY).blocked


def test_blocks_via_webfetch_tool_not_just_shell():
    d = evaluate(_fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/role"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_blocks_via_mcp_tool_url_arg():
    d = evaluate(_mcp_fetch("http://169.254.169.254/latest/meta-data/"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_blocks_unclassified_tool_with_url_shaped_arg():
    # a fetch-shaped tool the taxonomy classifies as OTHER (not WebFetch/WebSearch,
    # no mcp__ prefix) must still be caught via its url-shaped argument
    assert evaluate(_other_tool("HttpGet", url="http://169.254.169.254/latest/meta-data/"), EMPTY).blocked
    assert evaluate(_other_tool("BrowserNavigate", href="http://169.254.169.254/"), EMPTY).blocked
    # one level of nesting (params/request/input/arguments/options wrapping the url)
    assert evaluate(_other_tool("FetchTool", request={"url": "http://169.254.169.254/"}), EMPTY).blocked


def test_not_escapable():
    # containment tier — the human override token must NOT bypass it
    d = evaluate(_shell("curl http://169.254.169.254/latest/meta-data/  # aegis-allow"), EMPTY)
    assert d.blocked and d.rule == "containment-cloud-metadata"


def test_benign_requests_and_content_not_blocked():
    assert not evaluate(_fetch("https://api.github.com/repos/foo/bar"), EMPTY).blocked
    assert not evaluate(_shell("curl https://example.com/health"), EMPTY).blocked
    # writing documentation that merely mentions the IMDS IP as text is not a
    # network access — should not trip a containment-tier, non-escapable guard
    assert not evaluate(_write("docs/cloud.md", "The IMDS IP is 169.254.169.254."), EMPTY).blocked


def test_mere_mention_in_shell_not_blocked():
    # discussing / grepping / redacting / firewalling the address is not a
    # network request — none of these should trip a non-escapable guard
    assert not evaluate(_shell('git commit -m "reject requests carrying the '
                               'X-aws-ec2-metadata-token header"'), EMPTY).blocked
    assert not evaluate(_shell("iptables -A OUTPUT -d 169.254.169.254 -j DROP"), EMPTY).blocked
    assert not evaluate(_shell('grep -rn "169.254.169.254" ./docs'), EMPTY).blocked
    assert not evaluate(_shell("sed -i 's/169.254.169.254/REDACTED/' notes.txt"), EMPTY).blocked
    assert not evaluate(_shell('echo "processed 2852039166 bytes total"'), EMPTY).blocked
    assert not evaluate(_shell('echo "blocking metadata-flavor: google spoofing in our WAF"'), EMPTY).blocked


def test_mode_off_allows():
    pol = Policy(metadata_ssrf={"mode": "off"})
    assert not evaluate(_shell("curl http://169.254.169.254/latest/meta-data/"), pol).blocked


def test_mode_monitor_allows_and_records(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT", str(audit))
    pol = Policy(metadata_ssrf={"mode": "monitor"})
    d = evaluate(_shell("curl http://169.254.169.254/latest/meta-data/"), pol)
    assert not d.blocked
    assert audit.exists() and "containment-cloud-metadata-monitor" in audit.read_text()


def test_yaml_loader_wires_metadata_ssrf_and_mcp_config(tmp_path):
    (tmp_path / "p.yaml").write_text(
        "metadata_ssrf:\n  mode: monitor\nmcp_config:\n  mode: monitor\n", encoding="utf-8"
    )
    pol = load_policy(tmp_path)
    assert pol.metadata_ssrf == {"mode": "monitor"}
    assert pol.mcp_config == {"mode": "monitor"}
