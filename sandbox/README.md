# Aegis sandbox

Run a coding agent in a throwaway container where the only thing it can reach is
the repo you mount. The container is the containment; Aegis runs inside it as the
policy + audit layer. Neither is enough alone; together they are the honest "hard"
posture.

## Use it

Needs Docker (Docker Desktop on Windows/Mac, or Docker Engine on Linux).

```powershell
# Windows
.\run.ps1                 # sandbox the current directory
.\run.ps1 C:\path\to\repo
```

```bash
# macOS / Linux / WSL
./run.sh                  # sandbox the current directory
./run.sh /path/to/repo
```

That builds the image and drops you into a shell in the box, with Aegis already
wired into the mounted repo. Launch your agent from there.

For VS Code: copy `devcontainer.json` to `.devcontainer/devcontainer.json` in your
repo and "Reopen in Container."

## What each flag does

- `-v <repo>:/work` — the agent's whole filesystem is that one repo. `cat ~/.ssh/id_rsa`
  finds nothing, because there is no `~/.ssh` in the box. Your keys aren't blocked,
  they're not reachable.
- `--network none` — exfiltration has nowhere to send to. For agents that need the
  network, drop this and route egress through an allowlist proxy instead.
- `--cap-drop ALL` + `--security-opt no-new-privileges` — no Linux capabilities, no
  privilege escalation inside the box.
- non-root `agent` user, `AEGIS_AGENT_NAME` set — Aegis treats the agent as an agent,
  so it cannot `# aegis-allow` its own commands.

## Who catches what

| Agent does | Sandbox | Aegis |
|---|---|---|
| read your SSH keys | file isn't in the box | would deny anyway |
| `DROP TABLE users` on the DB | allows (valid connection) | **denies** — the case the sandbox can't see |
| exfil via a denylist bypass (`aws s3 cp`) | `--network none` blocks the send | misses it |
| `rm -rf /` | wipes the container, not your machine | denies |

The sandbox makes Aegis's denylist gaps survivable (worst case is a trashed
container). Aegis catches the intent-level things the OS reads as legal, and gives
you the audit trail. Point `DATABASE_URL` and other credentials at disposable
resources, never production.

## Caveats

- This is Linux-container isolation, not a VM. A container escape (kernel bug) is out
  of scope; for hard multi-tenant isolation use a microVM (Firecracker/gVisor).
- Docker Desktop on Windows runs the box in WSL2 — the mount is your repo only, not
  the Windows host.
