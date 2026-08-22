"""Container-runtime escape-to-host protection guard — blocks the handful of
`docker`/`podman`/`nerdctl`/`ctr run|create|exec` flags that hand a container
the means to reach or CONTROL the HOST it runs on, not just its own
filesystem (`--privileged`, a bind-mount of the runtime's own control socket,
`--cap-add=SYS_ADMIN`/`ALL`, a bind-mount of the host's root filesystem), plus
the container-runtime-independent `nsenter --target 1 --mount` host-namespace-
entry primitive.

THREAT MODEL (see `rule_container_escape_protect`'s own docstring in
rules.py for the full reasoning): every guard in this file assumes the tool
call Aegis evaluates is the boundary the agent is confined to. Any of these
primitives breaks that assumption structurally, not just practically —
everything that runs after one of these executes happens inside a fresh
namespace/container with no further tool call for Aegis to gate at all. This
is the same "one-shot, catastrophic, needs a human to have actually looked
at it" shape every other `*_protect` guard in this file covers, and unlike
`CRED_RE`/`PERSIST_RE`/`EXFIL_RE` (containment's own non-escapable tier) it
is implemented as an escapable `ask`-by-default guard, matching the
majority of sibling guards, because `--privileged`/a docker-socket mount
also has real, routine legitimate uses (DinD CI runners, systemd-in-
container integration tests, GPU/device passthrough) that a blanket
non-escapable deny would break.

Default mode is `ask` (not `deny`) for that same reason. A dedicated
`mode: deny` policy is used below to test the stricter posture explicitly.
"""
import time

from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()                                              # default mode: ask
DENY = Policy(container_escape={"mode": "deny"})               # stricter, hard-block posture

RULE = "container-escape-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _gated(d) -> bool:
    return d.action != Action.ALLOW


# ---- the five gated primitives, default (ask) posture -------------------------

def test_privileged_run_gated():
    d = evaluate(_shell("docker run --privileged -it alpine sh"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_privileged_create_gated():
    d = evaluate(_shell("docker create --privileged alpine sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_privileged_exec_gated():
    """`docker exec --privileged <running-container> sh` re-grants full
    capabilities to an exec session inside an already-running container,
    the same escape shape as a privileged `run`/`create`."""
    d = evaluate(_shell("docker exec --privileged mycontainer sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_podman_privileged_gated():
    d = evaluate(_shell("podman run --privileged fedora sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_nerdctl_privileged_gated():
    d = evaluate(_shell("nerdctl run --privileged alpine sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_socket_mount_gated():
    d = evaluate(_shell(
        "docker run -v /var/run/docker.sock:/var/run/docker.sock -it docker sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_docker_socket_mount_long_form_volume_gated():
    d = evaluate(_shell(
        "docker run --volume=/var/run/docker.sock:/var/run/docker.sock alpine sh"), EMPTY)
    assert _gated(d)


def test_docker_socket_mount_via_mount_flag_gated():
    d = evaluate(_shell(
        "docker run --mount type=bind,source=/var/run/docker.sock,"
        "target=/var/run/docker.sock alpine sh"), EMPTY)
    assert _gated(d)


def test_podman_socket_mount_gated():
    d = evaluate(_shell(
        "podman run -v /var/run/podman/podman.sock:/var/run/docker.sock alpine sh"), EMPTY)
    assert _gated(d)


def test_cap_add_sys_admin_gated():
    d = evaluate(_shell("docker run --rm --cap-add=SYS_ADMIN ubuntu bash"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_cap_add_sys_admin_space_form_gated():
    d = evaluate(_shell("docker run --rm --cap-add SYS_ADMIN ubuntu bash"), EMPTY)
    assert _gated(d)


def test_cap_add_all_gated():
    d = evaluate(_shell("docker run --cap-add=ALL busybox sh"), EMPTY)
    assert _gated(d)


def test_host_root_bind_mount_gated():
    d = evaluate(_shell("docker run -v /:/host --rm alpine chroot /host bash"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_host_root_bind_mount_via_mount_flag_gated():
    d = evaluate(_shell(
        "docker run --mount type=bind,source=/,target=/host alpine chroot /host bash"), EMPTY)
    assert _gated(d)


def test_nsenter_target_1_mount_gated():
    d = evaluate(_shell(
        "nsenter --target 1 --mount --uts --ipc --net --pid bash"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_nsenter_short_form_gated():
    d = evaluate(_shell("nsenter -t 1 -m -u -n -i sh"), EMPTY)
    assert _gated(d)


def test_nsenter_flag_order_reversed_gated():
    """--mount before --target must also match — the guard checks both
    orders, the same reasoning KUBE_EXEC_CRED_STRONG_RE's own either-order
    triad check documents."""
    d = evaluate(_shell("nsenter --mount --target 1 sh"), EMPTY)
    assert _gated(d)


def test_case_insensitive():
    d = evaluate(_shell("DOCKER RUN --PRIVILEGED -it ALPINE SH"), EMPTY)
    assert _gated(d)


# ---- benign / must-not-gate --------------------------------------------------

def test_ordinary_docker_run_not_gated():
    assert not _gated(evaluate(_shell("docker run --rm -it ubuntu bash"), EMPTY))


def test_ordinary_volume_mount_not_gated():
    assert not _gated(evaluate(
        _shell("docker run -v /home/user/repo:/work --rm myimage"), EMPTY))


def test_docker_build_not_gated():
    assert not _gated(evaluate(_shell("docker build -t myimage ."), EMPTY))


def test_docker_compose_up_not_gated():
    assert not _gated(evaluate(_shell("docker-compose up -d"), EMPTY))


def test_docker_ps_not_gated():
    assert not _gated(evaluate(_shell("docker ps -a"), EMPTY))


def test_unrelated_cap_add_not_gated():
    """A capability with no escape reach (SYS_ADMIN/ALL are the only ones
    gated) must not false-positive."""
    assert not _gated(evaluate(_shell("docker run --cap-add NET_ADMIN busybox"), EMPTY))


def test_pid_host_alone_not_gated():
    """--pid=host alone (no --privileged/--cap-add) has real, ordinary uses
    (process-monitoring containers) and, alone, doesn't grant the
    CAP_SYS_ADMIN an escape actually needs — a disclosed, deliberate gap,
    see rule_container_escape_protect's own docstring."""
    assert not _gated(evaluate(_shell("docker run --pid=host --rm alpine top"), EMPTY))


def test_nsenter_non_pid1_not_gated():
    """nsenter targeting an ordinary (non-1) PID is routine debugging, not a
    host-escape primitive — only PID 1 (the canonical host-init target) is
    gated, a disclosed scope limit."""
    assert not _gated(evaluate(_shell("nsenter -t 12345 -m ls"), EMPTY))


def test_bare_docker_sock_mention_without_run_not_gated():
    """The socket path appearing in an unrelated command (e.g. `ls -la
    /var/run/docker.sock`) with no docker/podman run|create|exec verb must
    not false-positive."""
    assert not _gated(evaluate(_shell("ls -la /var/run/docker.sock"), EMPTY))


def test_docker_sock_lookalike_filename_not_gated():
    """A path that merely STARTS WITH the socket string (an ordinary backup
    file) is not the real socket — only an exact match, terminated by the
    real `:` SRC:DST separator or a quote/space/end, counts. QA
    (design/consistency round) found the original, unanchored regex
    false-positived here."""
    assert not _gated(evaluate(
        _shell("docker run --rm -v /var/run/docker.sock.bak:/backup alpine ls"), EMPTY))
    assert not _gated(evaluate(
        _shell("docker run --rm -v /var/run/docker.sock-old:/backup alpine ls"), EMPTY))


def test_docker_sock_as_destination_only_not_gated():
    """The socket path appearing only as the container-side DESTINATION
    (not the host-side SOURCE) doesn't actually expose the host socket — an
    arbitrary, harmless real source bound to a path merely NAMED like the
    socket on the container side must not gate. QA (design/consistency
    round) found the original regex matched on either side of the `:`."""
    assert not _gated(evaluate(
        _shell("docker run --rm -v /home/user/fake.sock:/var/run/docker.sock:ro alpine ls"),
        EMPTY))


def test_privileged_equals_false_not_gated():
    """`--privileged=false` is real, valid pflag/cobra explicit-boolean CLI
    syntax both docker and podman accept — a security-conscious script
    being EXPLICIT about not enabling it must not gate. QA
    (design/consistency round) found the original bare-flag-name-only check
    false-positived here."""
    assert not _gated(evaluate(_shell("docker run --rm --privileged=false alpine"), EMPTY))
    assert not _gated(evaluate(_shell("podman run --rm --privileged=false alpine"), EMPTY))


def test_privileged_equals_true_still_gated():
    d = evaluate(_shell("docker run --rm --privileged=true alpine"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- regression: bypasses found and closed by QA before merge ---------------

def test_cap_add_with_cap_prefix_gated():
    """Docker's own capability normalization treats `CAP_SYS_ADMIN` as
    identical to bare `SYS_ADMIN` — QA (bypass-hunting round) found the
    original bare-name-only check missed this real, daemon-recognized
    spelling entirely."""
    d = evaluate(_shell("docker run --cap-add=CAP_SYS_ADMIN --rm ubuntu bash"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mount_src_alias_for_socket_gated():
    """`src=` is a documented alias for `source=` on `--mount` — QA
    (bypass-hunting round) found the original `source=`-only check missed
    it entirely."""
    d = evaluate(_shell(
        "docker run --mount type=bind,src=/var/run/docker.sock,"
        "dst=/var/run/docker.sock alpine sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_mount_src_alias_for_root_gated():
    d = evaluate(_shell(
        "docker run --mount type=bind,src=/,dst=/host alpine sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_glued_root_mount_no_separator_gated():
    """`-v/:/host` (no space, no `=`) is real docker/podman shorthand-flag
    gluing — the same mechanism that makes `-p8080:80` work — QA
    (bypass-hunting round) found the original `(?:=|\\s+)`-forced separator
    missed it entirely."""
    d = evaluate(_shell("docker run -v/:/host --rm alpine sh"), EMPTY)
    assert _gated(d) and d.rule == RULE


def test_nsenter_all_flag_gated():
    """`nsenter`'s own `--all`/`-a` flag enters EVERY namespace of the
    target process, mount included, without ever spelling `--mount`/`-m`
    literally — QA (bypass-hunting round) found the original mount-only
    check missed this entirely, despite it being arguably the single most
    direct primitive in this guard's whole scope."""
    d = evaluate(_shell("nsenter -t 1 -a /bin/bash"), EMPTY)
    assert _gated(d) and d.rule == RULE
    d2 = evaluate(_shell("nsenter --target 1 --all /bin/bash"), EMPTY)
    assert _gated(d2)


def test_long_ordinary_flag_list_before_privileged_still_gated():
    """A verb-to-flag bounded gap is silently exceeded by an entirely
    ORDINARY, non-adversarial invocation once past roughly a dozen routine
    flags — QA (bypass-hunting round) found this with 15 `-e` flags (~433
    chars). The runtime-verb and escape-flag checks are independent
    (unbounded relative to each other), so no flag count defeats this."""
    flags = " ".join(f"-e VAR{i}=aaaaaaaaaa" for i in range(30))
    d = evaluate(_shell(f"docker run --rm --name x {flags} --privileged image"), EMPTY)
    assert _gated(d) and d.rule == RULE


# ---- modes: ask (default) / deny / monitor / off -----------------------------

def test_default_mode_is_ask():
    d = evaluate(_shell("docker run --privileged alpine sh"), EMPTY)
    assert d.action == Action.ASK and d.rule == RULE


def test_deny_mode_hard_blocks():
    d = evaluate(_shell("docker run --privileged alpine sh"), DENY)
    assert d.blocked and d.action == Action.DENY and d.rule == RULE


def test_monitor_mode_logs_and_allows():
    pol = Policy(container_escape={"mode": "monitor"})
    assert not _gated(evaluate(_shell("docker run --privileged alpine sh"), pol))


def test_off_mode_disables_guard():
    pol = Policy(container_escape={"mode": "off"})
    assert not _gated(evaluate(_shell("docker run --privileged alpine sh"), pol))


def test_mode_off_unquoted_yaml_boolean_disables_guard():
    """YAML 1.1 parses an unquoted `off` as boolean False — the guard must
    still recognize it as 'disabled', the same config-hygiene convention
    every sibling `*_protect` guard's own `mode` knob already applies."""
    pol = Policy(container_escape={"mode": False})
    assert not _gated(evaluate(_shell("docker run --privileged alpine sh"), pol))


def test_policy_allow_regex_exempts_trusted_command():
    pol = Policy(container_escape={"allow": [r"trusted-dind-runner\.sh"]})
    assert not _gated(evaluate(
        _shell("bash trusted-dind-runner.sh && docker run --privileged alpine sh"), pol))
    assert _gated(evaluate(_shell("docker run --privileged alpine sh"), pol))


# ---- human-only override: '# aegis-allow' / AEGIS_ALLOW_CONTAINER_ESCAPE ------

def test_human_can_override_with_trailing_comment():
    d = evaluate(_shell("docker run --privileged alpine sh # aegis-allow"), EMPTY)
    assert not _gated(d)


def test_spawned_agent_cannot_override_with_trailing_comment(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_NAME", "spawned-agent")
    d = evaluate(_shell("docker run --privileged alpine sh # aegis-allow"), EMPTY)
    assert _gated(d)


def test_env_override_allows(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CONTAINER_ESCAPE", "1")
    d = evaluate(_shell("docker run --privileged alpine sh"), EMPTY)
    assert not _gated(d)


# ---- performance / ReDoS -----------------------------------------------------

def test_container_escape_patterns_no_quadratic_blowup():
    from aegis import patterns
    payload_flags = "docker run " + ("-e FOO=bar " * 20000) + "alpine sh"
    payload_v = "docker " + ("run " * 5000) + ("-v " * 5000) + "x"
    payload_nsenter = "nsenter " + ("-t " * 3000) + ("-m " * 3000)
    for adv in (payload_flags, payload_v, payload_nsenter):
        start = time.time()
        patterns.CONTAINER_RUNTIME_VERB_RE.search(adv)
        patterns.CONTAINER_PRIVILEGED_RE.search(adv)
        patterns.CONTAINER_SOCKET_MOUNT_RE.search(adv)
        patterns.CONTAINER_CAP_ADD_RE.search(adv)
        patterns.CONTAINER_ROOT_MOUNT_RE.search(adv)
        patterns.CONTAINER_NSENTER_HOST_RE.search(adv)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"took {elapsed:.2f}s on {adv[:40]!r}..."


def test_engine_no_quadratic_blowup():
    tail = " ".join(["word"] * 20000)
    cmd = "docker run --privileged alpine sh " + tail
    start = time.time()
    evaluate(_shell(cmd), EMPTY)
    elapsed = time.time() - start
    assert elapsed < 1.0, f"rule_container_escape_protect took {elapsed:.2f}s on adversarial input"
