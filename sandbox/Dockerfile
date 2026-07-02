# Aegis sandbox: run a coding agent in a throwaway container where the only thing
# it can reach is the repo you mount. Aegis enforces policy + audit inside the box.
# The container is the containment; Aegis is the semantics the container can't see.
FROM python:3.12-slim

# Node for the agent runtime (Claude Code is an npm CLI); git for repo work.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged principal: no host privileges even if the agent escapes Aegis.
RUN useradd -m -s /bin/bash agent
USER agent
ENV PATH="/home/agent/.local/bin:${PATH}"

# The policy + audit layer, installed inside the box.
RUN pip install --user --no-cache-dir aegis-hooks
# Bake the agent in too (optional — or install it at run time):
# RUN npm install -g @anthropic-ai/claude-code

WORKDIR /work
COPY --chown=agent:agent entrypoint.sh /home/agent/entrypoint.sh
# Invoke via bash so the entrypoint works regardless of the file's exec bit
# (Windows-authored files don't carry one through git).
ENTRYPOINT ["bash", "/home/agent/entrypoint.sh"]
CMD ["bash"]
