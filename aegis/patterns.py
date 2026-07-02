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
    r"accountability|gitsurface)\.py\b"
    r"|(?:^|[/\\])aegis[/\\]adapters[/\\]\w+\.py\b",
    re.IGNORECASE,
)
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
