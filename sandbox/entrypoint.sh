#!/usr/bin/env bash
# Wire Aegis into the mounted repo, then hand off. Runs as the unprivileged 'agent'.
set -e

# Set the identity BEFORE the agent runs. This is what makes the "# aegis-allow"
# escape human-only inside the box: with AEGIS_AGENT_NAME set, a spawned agent
# cannot wave itself past an escapable guard. AEGIS_PROJECT confines edits to /work.
export AEGIS_AGENT_NAME="${AEGIS_AGENT_NAME:-sandbox-agent}"
export AEGIS_PROJECT="/work"

if [ -d /work ]; then
  aegis install --project /work --command "$(command -v aegis) hook" >/dev/null 2>&1 || true
fi

exec "$@"
