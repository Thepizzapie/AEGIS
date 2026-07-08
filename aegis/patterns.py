"""Curated dangerous-command patterns — battle-tested, cross-shell.

Regex, not naive globs. These back the built-in rules in
``aegis.rules`` that ship secure-by-default.
"""
import re

# Explicit, recorded override: append '# aegis-allow' (or --aegis-allow) to an
# ESCAPABLE guard to confirm intent.
OVERRIDE_RE = re.compile(r"(?:#|--)\s*aegis-allow\b", re.IGNORECASE)  # '# ' (shell) or '-- ' (SQL)

# History-rewriting / destructive git (force-push, reset --hard, rebase, amend,
# branch -D, clean -f).
DESTRUCTIVE_GIT_RE = re.compile(
    r"\bgit\b[^|;&\n]*?\b(?:"
    # force/destructive push: --force/-f/--mirror; a leading-'+' refspec (force-update
    # of any ref); or a space-colon delete of a PROTECTED branch (`push origin :main`).
    # A `src:dst` refspec (`HEAD:main`) and deleting a feature branch (`:old-feature`)
    # are intentionally NOT matched — those are routine.
    r"push[^|;&\n]*?(?:--force\b|--force-with-lease\b|--mirror\b|\s-f\b"
    r"|\s\+[^\s|;&]+|\s:(?:main|master|develop|trunk|release)\b)"
    r"|reset[^|;&\n]*?--hard"
    # rebase is destructive, but its recovery flags restore state — allow those.
    r"|rebase\b(?![^|;&\n]*--(?:abort|continue|skip|quit|edit-todo))"
    r"|commit[^|;&\n]*?--amend"
    # -D force-deletes a branch; -d is the safe (refuses-unmerged) delete. Match -D
    # case-sensitively (scoped (?-i:)) so routine `git branch -d merged` is allowed.
    r"|branch[^|;&\n]*?\s(?-i:-D)\b"
    r"|clean[^|;&\n]*?\s-[a-zA-Z]*f"
    r")",
    re.IGNORECASE,
)

# Recursive force delete across shells: unix `rm` with r+f flags (combined or
# separate), PowerShell Remove-Item/aliases with -Recurse -Force (any order),
# cmd rmdir/rd /s and del /s|/q.
DESTRUCTIVE_DELETE_RE = re.compile(
    # unix rm: recursive (-r / -R / --recursive) AND force (-f / --force), any order,
    # short-combined or GNU long-form.
    r"\brm\b(?=[^|;&\n]*\s(?:-[a-z]*r|--recursive\b))(?=[^|;&\n]*\s(?:-[a-z]*f|--force\b))"
    r"|\b(?:remove-item|ri|rmdir|rd|del|erase)\b(?=[^|;&\n]*-recurse)(?=[^|;&\n]*-force)"
    r"|\b(?:rmdir|rd)\b[^|;&\n]*/s"
    r"|\bdel\b[^|;&\n]*/[sq]"
    r"|\bfind\b[^|;&\n]*-(?:delete\b|exec\s+rm\b)"   # find -delete / -exec rm
    r"|\brimraf\b"                                    # npm rimraf (always recursive-force)
    r"|\bshred\b"                                     # secure delete
    r"|\btruncate\b[^|;&\n]*\s-s\s*0\b"               # zero a file
    r"|\bdd\b[^|;&\n]*\bof=/dev/",                    # overwrite a raw device
    re.IGNORECASE,
)

# Destructive SQL — data/schema loss. Catches it in shell (psql -c "...") AND in a
# DB MCP tool's `query`/`sql` argument (Supabase execute_sql / apply_migration, etc.)
DESTRUCTIVE_SQL_RE = re.compile(
    r"\bdrop\s+(?:table|database|schema|index|view|column|constraint|type|role|user)\b"
    r"|\btruncate\b(?:\s+table)?\s+\w"
    r"|\balter\s+table\b[^;]*\bdrop\b"
    r"|\bdelete\s+from\b(?![^;]*\bwhere\b)"          # DELETE without WHERE
    r"|\bupdate\s+\w[^;]*\bset\b(?![^;]*\bwhere\b)",  # UPDATE without WHERE (mass write)
    re.IGNORECASE,
)

# Destructive migration commands across common tools (reset / downgrade / drop)
DESTRUCTIVE_MIGRATION_RE = re.compile(
    r"\bprisma\b[^|;&\n]*\bmigrate\b[^|;&\n]*\breset\b"
    r"|\bprisma\b[^|;&\n]*\bdb\b[^|;&\n]*--force-reset"
    r"|\balembic\b[^|;&\n]*\bdowngrade\b"
    r"|\bsupabase\b[^|;&\n]*\bdb\b[^|;&\n]*\breset\b"
    r"|\b(?:rails|rake)\b[^|;&\n]*\bdb:(?:drop|reset)\b"
    r"|\bmanage\.py\b[^|;&\n]*\bmigrate\b[^|;&\n]*\bzero\b"
    r"|\bknex\b[^|;&\n]*\bmigrate:rollback\b"
    r"|\bflyway\b[^|;&\n]*\bclean\b"
    r"|\bdbmate\b[^|;&\n]*\b(?:drop|down)\b",
    re.IGNORECASE,
)

# Obfuscation / evasion tells — an agent deliberately hiding what it runs.
EVASION_RE = re.compile(
    r"-(?:e|ec|enc|encodedcommand)\b\s+[A-Za-z0-9+/=]{12,}"   # PowerShell encoded command
    r"|\bbase64\b\s+(?:-d|--decode)\b[^|&;\n]*\|\s*(?:sh|bash|zsh|python|node|iex|pwsh|powershell)"
    r"|\[\s*convert\s*\]::frombase64string"                  # PS FromBase64String
    r"|\bfromcharcode\b|\bchr\s*\(\s*\d",                     # char-code construction
    re.IGNORECASE,
)

# Fetch-and-execute: pull a remote script and pipe it straight into an interpreter
# (curl … | sh, wget … | bash, iex(iwr …)). The classic one-liner that runs code an
# agent never read — and the shape of the 0DIN "clean repo" reverse-shell second
# stage when it surfaces as a shell command. Non-escapable evasion tell.
PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|&;\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|perl|ruby|pwsh|powershell)\b"
    r"|\b(?:iex|invoke-expression)\b[^|;\n]*\(?\s*(?:iwr|invoke-webrequest|curl|wget|new-object\s+net\.webclient)"
    r"|\(\s*(?:iwr|invoke-webrequest)\b[^)]*\)\s*(?:\||\.content\s*\|)\s*iex",
    re.IGNORECASE,
)

# DNS-as-C2 / DNS exfil: pulling a payload or command out of a TXT record (the 0DIN
# stage that hides a base64 reverse-shell in an attacker-controlled DNS TXT record).
# High-signal when the lookup feeds a decoder or interpreter.
DNS_C2_RE = re.compile(
    r"\b(?:dig|drill|kdig)\b[^|;&\n]*(?:\btxt\b|-t\s+txt|\+short)"
    r"|\bnslookup\b[^|;&\n]*-(?:type|q|querytype)=txt\b"
    r"|\bhost\b[^|;&\n]*\s-t\s+txt\b"
    r"|\bResolve-DnsName\b[^|;&\n]*-Type\s+txt\b",
    re.IGNORECASE,
)

# Aegis's own enforcement surface — deleting/editing this disables Aegis.
ENFORCEMENT_PATH_RE = re.compile(
    r"\.aegis(?=[/\\]|\s|['\"]|$)|\.claude[/\\]settings\.json\b", re.IGNORECASE)
# broader: shell delete/move of the whole config dirs (.aegis / .claude). Anchored
# so it matches the DIR (followed by a separator / end / quote), not any filename
# that merely contains '.aegis' or '.claude' (e.g. 'notes.aegis.bak', '.claude-x').
CONFIG_DIR_RE = re.compile(
    r"\.aegis(?=[/\\]|\s|['\"]|$)|\.claude(?=[/\\]|\s|['\"]|$)", re.IGNORECASE)
# Aegis's OWN package source — editing/deleting it could neuter the engine
AEGIS_SOURCE_RE = re.compile(
    r"(?:^|[/\\])aegis[/\\](?:__init__|rules|patterns|engine|policy|gate|attest|"
    r"identity|reaper|normalize|plugins|mcp|loader|cli|config|events|audit|"
    r"accountability|gitsurface|review|context|failures|skills|distribution)\.py\b"
    r"|(?:^|[/\\])aegis[/\\](?:adapters|lifecycle)[/\\]\w+\.py\b",
    re.IGNORECASE,
)
# Aegis's shipped skills (.claude/skills/aegis-*) — they carry the compliance
# guidance a blocked agent is pointed at; rewriting them subverts the guidance.
AEGIS_SKILL_PATH_RE = re.compile(
    r"\.claude[/\\]skills[/\\]aegis-[\w-]+", re.IGNORECASE)
# any move/delete verb (used together with ENFORCEMENT_PATH_RE on shell commands)
DELETE_OR_MOVE_VERB_RE = re.compile(
    r"\b(?:rm|remove-item|ri|rmdir|rd|del|erase|mv|move-item|move|ren|rename-item)\b",
    re.IGNORECASE,
)
AEGIS_UNINSTALL_RE = re.compile(r"\baegis\b[^|;&\n]*\buninstall\b", re.IGNORECASE)
# 'aegis pull' — overwrites the active policy; a hijacked agent that pulls a
# permissive policy and then proceeds unguarded is the self-protect failure mode.
AEGIS_PULL_RE = re.compile(r"\baegis\b[^|;&\n]*\bpull\b", re.IGNORECASE)

# Shell write-redirects (>, >>, tee, Set-Content, Out-File, Add-Content) —
# the self-protect gap: delete/move verbs are caught, but a redirect that
# OVERWRITES a config/policy file is equally dangerous.
WRITE_REDIRECT_RE = re.compile(
    r">{1,2}\s*\S"                                       # bash > / >>
    r"|\btee\b"                                          # tee (writes to file + stdout)
    r"|\b(?:set-content|out-file|add-content|sc)\b",     # PowerShell write cmdlets
    re.IGNORECASE,
)

# Credential stores.
CRED_RE = re.compile(
    r"(?:[/\\]\.(?:ssh|aws|azure|gnupg|kube))(?:[/\\]|\b)"
    r"|[/\\]\.netrc\b|[/\\]\.config[/\\]gh\b"
    r"|[/\\]\.docker[/\\]config\.json\b"
    r"|\bid_rsa\b|\bid_ed25519\b|\.ppk\b"
    r"|[/\\](?:Login Data|Cookies|Web Data)\b"
    r"|\bkey4\.db\b|\blogins\.json\b"
    r"|Microsoft[/\\](?:Credentials|Vault|Protect)\b",
    re.IGNORECASE,
)

# Persistence (autorun, scheduled tasks, services, startup).
PERSIST_RE = re.compile(
    r"\\CurrentVersion\\Run(?:Once)?\b"
    r"|\bschtasks\b[^|;&\n]*?/create\b|Register-ScheduledTask\b"
    r"|\bsc(?:\.exe)?\s+create\b|New-Service\b"
    r"|[/\\]Start Menu[/\\]Programs[/\\]Startup[/\\]"
    r"|\bcrontab\b|/etc/cron",
    re.IGNORECASE,
)

# Exfiltration (upload-a-local-file) across common uploaders. Not exhaustive —
# an in-process python requests.post can't be pattern-matched — but covers the
# CLI tools an agent reaches for: curl (data/upload/form), wget --post-file,
# PowerShell Invoke-*, scp/rsync to a remote, and nc/ncat piping a file.
EXFIL_RE = re.compile(
    r"\bcurl\b[^|;&\n]*?(?:-d\s*@|--data(?:-binary)?\s*@|--data-urlencode\s+\S*@"
    r"|--upload-file\b|\s-T\s|(?:-F|--form)\b[^|;&\n]*@)"
    r"|\bwget\b[^|;&\n]*?--post-file"
    r"|Invoke-(?:RestMethod|WebRequest)\b[^|;&\n]*?-InFile\b"
    # scp/rsync to a user@host: remote. The '@' anchor avoids matching a LOCAL copy
    # of a file whose name contains a dot+colon (e.g. a timestamp 'log.12:30.txt').
    r"|\b(?:scp|rsync)\b[^|;&\n]*\s[^\s|;&]*@[^\s|;&]*:"
    r"|\b(?:nc|ncat|netcat)\b[^|;&\n]*<\s*\S"
    # httpie invoked as a command, piping/attaching a local file (http POST u < f,
    # http -f POST u field@file). Anchored to a command position so an https:// URL
    # argument to another tool does not false-match.
    r"|(?:^|[\s;&|(])https?\s+[^|;&\n]*(?:<\s*\S|@\S)",
    re.IGNORECASE,
)

# Cloud-storage CLI exfiltration — upload a local file/tree to an
# attacker-controlled bucket/container via a cloud storage CLI. A documented gap
# (README "Known gaps"): EXFIL_RE only covers curl/wget/scp/rsync/nc/httpie, so an
# agent with cloud creds already on the box (env vars, an attached IAM role,
# ~/.aws) could stage the same theft through a cloud CLI instead and sail
# straight past the existing exfil guard. Direction-aware where a verb is
# ambiguous (cp/sync/mv/copy can go either way): the negative lookahead requires
# the FIRST path-like argument NOT be a remote URI/remote-name, i.e. the source
# is local — so a legitimate DOWNLOAD (pull an artifact FROM a bucket) is not
# blocked, and a --dryrun/-n/--dry-run preview (no data actually moves) is
# excluded. Verbs that are upload-only regardless of argument order (s3api
# put-object, b2 upload-file, oci os object put, az storage upload) match
# unconditionally; `az storage copy` is direction-checked via its -s/-d flags
# since they can appear in either order. Covers aws s3 / s5cmd (s3://), gsutil /
# gcloud storage (gs://), az storage, rclone (incl. on-the-fly `:provider,...:`
# remotes). Not exhaustive — bucket-to-bucket transfers, alias-only clients (mc,
# doctl) with no scheme in the destination, and shell-level evasions shared by
# every pattern in this module (a value split across a variable, e.g.
# `$SCHEME://bucket`, or dangerous text sitting only in a comment/string) are a
# residual gap, same spirit as the other documented denylist gaps.
CLOUD_EXFIL_RE = re.compile(
    # Each dry-run exclusion requires the flag be the token IMMEDIATELY after
    # the verb — not "somewhere in a leading run of dash-tokens" (tried and
    # broken: pflag-style parsers, e.g. rclone's, let a real VALUE-taking flag
    # silently swallow a following token as its argument — `--exclude
    # --dry-run` is really `--exclude` with the literal string "--dry-run" as
    # its pattern, so no dry-run ever engages and the transfer is real — but a
    # regex with no per-flag arity table can't tell "--dry-run" the flag from
    # "--dry-run" a preceding flag's value). Two earlier attempts also failed:
    # scanning the whole clause let the flag be spoofed inside an
    # attacker-controlled destination argument; bounding at the destination's
    # scheme marker then let it be spoofed inside the SOURCE argument instead.
    # Requiring the single fixed first-token position removes any place before
    # it for another flag to sit, so there is nothing left to swallow it —
    # at the cost of not recognizing a dry-run flag placed after some other
    # flag (a false positive, the safe direction for a non-escapable guard).
    r"\baws\b[^|;&\n]*\bs3\b[^|;&\n]*\b(?:cp|sync|mv)\b"
    r"(?!\s--dryrun(?=\s|[|;&\n]|$))"
    r"\s+(?!s3://)\S+[^|;&\n]*\bs3://"
    r"|\baws\b[^|;&\n]*\bs3api\b[^|;&\n]*\bput-object\b"
    r"|\bs5cmd\b[^|;&\n]*\b(?:cp|mv|sync)\b\s+(?!s3://)\S+[^|;&\n]*\bs3://"
    r"|\bgsutil\b[^|;&\n]*\b(?:cp|mv|rsync)\b"
    r"(?!\s(?:-n|--dry-run)(?=\s|[|;&\n]|$))"
    r"\s+(?!gs://)\S+[^|;&\n]*\bgs://"
    r"|\bgcloud\b[^|;&\n]*\bstorage\b[^|;&\n]*\b(?:cp|mv|rsync)\b"
    r"(?!\s--dry-run(?=\s|[|;&\n]|$))"
    r"\s+(?!gs://)\S+[^|;&\n]*\bgs://"
    r"|\baz\b[^|;&\n]*\bstorage\b[^|;&\n]*\b(?:blob|file|fs)\b[^|;&\n]*\bupload(?:-batch)?\b"
    r"|\baz\b[^|;&\n]*\bstorage\b[^|;&\n]*\bcopy\b"
    r"(?![^|;&\n]*(?:-s|--source)\s+https?://)[^|;&\n]*(?:-d|--destination)\s+\S*"
    r"(?:blob|file)\.core\.\w"
    r"|\bb2\b[^|;&\n]*\bupload-file\b"
    r"|\boci\b[^|;&\n]*\bos\b[^|;&\n]*\bobject\b[^|;&\n]*\bput\b"
    r"|\brclone\b[^|;&\n]*\b(?:copy|sync|move|copyto|moveto)\b"
    r"(?!\s(?:--dry-run|-n)(?=\s|[|;&\n]|$))"
    r"\s+(?![A-Za-z][\w.-]+:|:\w[\w,.=-]*:)\S+[^|;&\n]*"
    r"\s(?:[A-Za-z][\w.-]+:|:\w[\w,.=-]*:)\S*",
    re.IGNORECASE,
)

# Copy/write programs that can OVERWRITE a file without a delete/move verb or a
# shell redirect — the self-protect gap (cp/dd/install onto the policy file,
# ln over it, a python open(...,'w')). Paired with a config/source path match.
COPY_WRITE_VERB_RE = re.compile(
    r"\b(?:cp|copy|copy-item|cpi|dd|install|ln|link|new-item|ni)\b"
    r"|\bpython[0-9.]*\b[^\n]*\bopen\s*\([^\n]*['\"][wax]",
    re.IGNORECASE,
)

# Bulk / blind dependency installs — a hijacked agent adding supply-chain attack
# payloads (malicious packages, poisoned requirements.txt). Matches the "install
# ALL" forms; targeted single-package installs (npm install lodash) are allowed.
# Creating a new git branch — the strand signal. The explicit new-branch verbs
# (checkout -b, switch -c) are unambiguous; bare 'git branch <name>' is excluded
# (ambiguous with list / -d forms).
NEW_BRANCH_RE = re.compile(
    r"\bgit\b[^|;&\n]*?\b(?:checkout\s+-b|switch\s+-c)\b",
    re.IGNORECASE,
)

BULK_INSTALL_RE = re.compile(
    r"(?:^|[\s;&|(])(?:"
    r"(?:npm|pnpm|bun)\s+(?:install|i|ci)(?![\w-])(?!\s+[\w@])"   # npm install (no pkg)
    r"|yarn(?:\s+install)?(?![\w-])(?!\s+[\w@])"                   # yarn / yarn install
    r"|(?:pip|pip3)\s+install\s+(?:-r|--requirement)"               # pip install -r
    r"|python\s+-m\s+pip\s+install\s+(?:-r|--requirement)"          # python -m pip install -r
    r"|poetry\s+install"                                            # poetry install
    r"|pipenv\s+install(?!\s+[\w@])"                                # pipenv install (no pkg)
    r"|bundle\s+install"                                            # bundle install
    r"|cargo\s+(?:fetch|build|run|test)"                            # cargo (pulls deps)
    r"|go\s+mod\s+(?:download|tidy)"                                # go mod download/tidy
    r")",
    re.IGNORECASE,
)

# ANY dependency install — bulk OR targeted. The install-review gate fires on all of
# these (forced full read of the manifest, then human ask), where the bulk guard only
# caught the install-everything forms. Excludes the no-execute *fetch* forms
# (pip download, npm --ignore-scripts) which don't run package code and are the
# sanctioned first phase of a deep review.
# Leading-context class includes '/' so a path-qualified interpreter
# (./venv/bin/pip install ...) is still recognized.
INSTALL_ANY_RE = re.compile(
    r"(?:^|[\s;&|(/])(?:"
    r"(?:npm|pnpm|bun)\s+(?:install|i|ci|add)\b"                    # npm install/add (+pkg or not)
    r"|yarn\s+(?:install|add)\b|yarn(?=\s*(?:$|[;&|#]))"            # yarn install/add, or bare yarn
    r"|(?:pip|pip3)\s+install\b"                                    # pip install (any)
    r"|python3?\s+-m\s+pip\s+install\b"                             # python -m pip install (any)
    r"|uv\s+(?:pip\s+install|add|sync|install)\b"                  # uv (modern installer)
    r"|pipx\s+(?:install|run)\b"                                    # pipx
    r"|poetry\s+(?:install|add)\b"                                  # poetry install/add
    r"|pipenv\s+install\b"                                          # pipenv install (any)
    r"|(?:bundle|gem)\s+install\b"                                  # bundle/gem install
    r"|cargo\s+(?:install|fetch|build|run|test|add)\b"             # cargo (pulls/runs deps)
    r"|go\s+(?:mod\s+(?:download|tidy)|get|install)\b"             # go get/install/mod
    r"|(?:conda|mamba|micromamba)\s+(?:install|create)\b"          # conda/mamba family
    r")",
    re.IGNORECASE,
)

# MCP server-definition config files — across the common agentic runtimes. These
# declare a `command`/`args`/`url`/`env` per server that is auto-executed on every
# FUTURE session start, with no shell involved when written via Edit/Write. Planting
# or altering an entry here is a durable, cross-session backdoor — a distinct attack
# surface from Aegis's own config (ENFORCEMENT_PATH_RE) or OS persistence (PERSIST_RE).
MCP_CONFIG_PATH_RE = re.compile(
    r"(?:^|[\s'\"/\\=])\.mcp\.json\b"                          # Claude Code (project-scoped)
    r"|(?:^|[\s'\"/\\=])\.claude\.json\b"                      # Claude Code (user-scoped, mcpServers)
    r"|(?:^|[\s'\"/\\=])claude_desktop_config\.json\b"         # Claude Desktop
    r"|(?:^|[\s'\"/\\=])\.cursor[/\\]mcp\.json\b"              # Cursor
    r"|(?:^|[\s'\"/\\=])\.vscode[/\\]mcp\.json\b"              # VS Code / Copilot
    r"|(?:^|[\s'\"/\\=])\.windsurf[/\\]mcp\.json\b"            # Windsurf (project)
    r"|(?:^|[\s'\"/\\=])mcp_config\.json\b",                   # Windsurf (global) / generic
    re.IGNORECASE,
)

# In-place edit / copy-over-target verbs — a config-file overwrite that is NEITHER a
# redirect/tee NOR a delete/move (sed -i, perl -i, batch-mode vim/ex, cp/copy the file
# over the target, dd, or a python/node/ruby/perl one-liner script that writes it).
# Paired with MCP_CONFIG_PATH_RE (the target filename must be literally present) so
# this stays high-signal despite the broad verb list. Deliberately excludes coreutils
# `install` — indistinguishable by regex from `npm install`/`pip install` and would
# false-positive whenever an unrelated install command shares a shell line with a mere
# READ of the config file.
INPLACE_WRITE_RE = re.compile(
    r"\bsed\b[^|;&\n]*-i\b"
    r"|\bperl\b[^|;&\n]*-i\b"
    r"|\b(?:vim?|nvim|ex)\b[^|;&\n]*-c\s*['\"]?(?:wq!?|w\b|write)"
    r"|\bcp\b|\bcopy\b"
    r"|\bdd\b"
    r"|\b(?:python3?|node|ruby|perl)\b[^|;&\n]*\s-[ce]\b",
    re.IGNORECASE,
)

# CLI-based MCP server registration — mutates the same config WITHOUT a file write the
# Edit/Write hook would ever see (`claude mcp add ...`, `codex mcp add ...`, etc.). The
# vendor-qualified form is deliberately unanchored (specific enough: vendor name + mcp
# + add together are unlikely in ordinary text). The bare `mcp add` fallback (no vendor
# name — the reference/generic MCP CLI) IS anchored to command-start position (start of
# string or right after a shell separator ; & | / newline, optional sudo) so it doesn't
# false-positive on a commit message, echoed string, or comment containing the phrase
# "mcp add" — those never begin a command.
MCP_CLI_ADD_RE = re.compile(
    r"\b(?:claude|codex|cursor|windsurf|gemini)\b[^|;&\n]*\bmcp\b[^|;&\n]*\b(?:add|add-json|install)\b"
    r"|(?:^|[;&|\n]\s*)(?:sudo\s+)?mcp\s+add\b",
    re.IGNORECASE,
)

# No-execute *fetch* forms — pull artifacts WITHOUT installing/placing or running any
# package code. These don't trip the gate (a download is not an install). NOTE: this
# deliberately excludes ``npm install --ignore-scripts`` — that still PLACES the
# package on disk, whose top-level import code runs the moment it's required, so it is
# an install and stays gated.
NOEXEC_FETCH_RE = re.compile(
    r"\bpip3?\s+download\b"
    r"|\bnpm\s+pack\b",
    re.IGNORECASE,
)

# Hidden/invisible Unicode used to smuggle instructions past human review at the
# UserPromptSubmit boundary — the text renders as nothing (or as ordinary text)
# to a person reading the prompt, but the model still tokenizes and reads the
# hidden codepoints. Three techniques with ~zero OTHER legitimate use in a
# message TO an agent:
#
#  - Tag-block steganography (U+E0000-U+E007F): Unicode's deprecated language-tag
#    plane, invisible in every renderer. Each tag codepoint is (0x20 + ascii_char),
#    so a run of them ASCII-decodes to arbitrary hidden text. Publicly
#    demonstrated in 2024 ("ASCII smuggling") to hide instructions inside
#    content a human reviewer sees as blank. The ONE standardized legitimate use
#    of this range is a subdivision/region flag emoji — a waving black flag
#    (U+1F3F4) immediately followed by 2-7 lowercase tag-letters and terminated
#    by the cancel tag (U+E007F), e.g. Scotland/England/Wales. That exact,
#    fixed structure is carved out by FLAG_TAG_SEQUENCE_RE below; a tag
#    codepoint appearing OUTSIDE it (no preceding flag, wrong length, missing
#    the cancel tag, or free-standing elsewhere in the text) is not standard
#    emoji usage and stays flagged.
#  - Variation-selector steganography: the identical one-codepoint-per-byte
#    trick in a different plane — VS1-16 (U+FE00-FE0F) and VS17-256
#    (U+E0100-E01EF). A single variation selector is ordinary (it picks one
#    base character's presentation style); nothing in real usage ever stacks
#    two or more back-to-back with no base character between them.
#  - Zero-width run: a chain of invisible joiners/spacers (ZWSP/ZWNJ/ZWJ/word
#    joiner/BOM) with no visible character between them, encoding a hidden
#    payload one bit per codepoint choice. Ordinary text uses these SINGLY (an
#    emoji ZWJ sequence, an Indic ZWNJ) — never chained back-to-back for six or
#    more codepoints running, which is why the run length (not mere presence)
#    is the signal.
HIDDEN_TAG_RE = re.compile("[\U000e0000-\U000e007f]")

# The one standardized, publicly documented, everyday use of tag-block
# codepoints: a subdivision/region flag emoji. rules.rule_hidden_unicode_prompt
# strips every match of this BEFORE testing HIDDEN_TAG_RE, so a legitimate
# flag never trips the guard while a payload hidden alongside — or instead
# of — one still does.
FLAG_TAG_SEQUENCE_RE = re.compile("\U0001f3f4[\U000e0061-\U000e007a]{2,7}\U000e007f")

# Zero-width joiner/spacer/BOM codepoints, named by escape (never as literal
# invisible characters in source — those would be unreviewable in a diff and,
# for a security tool, an uncomfortably on-the-nose thing to embed): ZWSP
# U+200B, ZWNJ U+200C, ZWJ U+200D, word joiner U+2060, ZWNBSP/BOM U+FEFF.
_ZW_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
HIDDEN_ZEROWIDTH_RUN_RE = re.compile(f"[{_ZW_CHARS}]{{6,}}")

# Variation-selector steganography (see the module comment above HIDDEN_TAG_RE):
# VS1-16 (BMP) + the supplementary VS17-256 block. Run of 2+ is the signal.
HIDDEN_VARIATION_RUN_RE = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}")

# Bidirectional text-direction override/isolate controls: LRE U+202A, RLE
# U+202B, PDF U+202C, LRO U+202D, RLO U+202E, LRI U+2066, RLI U+2067, FSI
# U+2068, PDI U+2069. These can visually reorder text so a human reviewer sees
# something different from what the model reads (the "Trojan Source" class of
# attack). Distinct from the plain LRM/RLM direction MARKS (U+200E/U+200F),
# which have everyday legitimate use and are deliberately excluded — ordinary
# RTL text (Arabic/Hebrew) renders correctly via the bidi algorithm without any
# of these explicit override/isolate controls, so this is still a meaningfully
# rare, high-signal pattern.
BIDI_OVERRIDE_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")

# A test-suite invocation, across common toolchains. Backs the opt-in Stop
# verification gate (lifecycle.session.rule_stop_verification_gate): evidence
# that a test run HAPPENED after the last change — presence of the command, not
# a parse of its pass/fail output. Policy can supply its own regexes instead
# (``completion.patterns``).
TEST_CMD_RE = re.compile(
    r"\bpytest\b|\bpython3?\s+-m\s+(?:pytest|unittest)\b|\btox\b|\bnox\b"
    r"|\bnpm\s+(?:run\s+)?test\b|\byarn\s+test\b|\bpnpm\s+(?:run\s+)?test\b"
    r"|\bnpx\s+(?:jest|vitest|mocha|playwright|ava)\b|\bjest\b|\bvitest\b|\bmocha\b"
    r"|\bcargo\s+test\b|\bgo\s+test\b|\bdotnet\s+test\b|\bctest\b"
    r"|\bmvn\b[^|;&\n]*\b(?:test|verify)\b|\bgradlew?\b[^|;&\n]*\btest\b"
    r"|\brake\s+test\b|\brspec\b|\bphpunit\b|\bmix\s+test\b",
    re.IGNORECASE,
)
