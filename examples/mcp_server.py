"""Runnable example: an MCP server with Aegis enforcing policy on the tool side.

    pip install -e .            # Aegis
    pip install "mcp"           # FastMCP lives in the `mcp` package
    python examples/mcp_server.py

Every tool call is checked against Aegis policy (the secure-by-default built-ins plus
anything in your policy dir) *inside the server*, before it runs — so a client cannot
bypass it. Try a `run_sql` of `DROP TABLE x` or a `delete_record`: the built-in
migration / destructive guards refuse it.
"""
from mcp.server.fastmcp import FastMCP

from aegis import mcp as aegis

app = FastMCP("aegis-demo")

# in-memory "data" so the example actually runs
_RECORDS = {1: "alpha", 2: "beta"}


@app.tool()
@aegis.guarded                      # tool name defaults to the function name
def read_record(record_id: int) -> str:
    """Allowed by default — a benign read."""
    return _RECORDS.get(record_id, "(not found)")


@app.tool()
def run_sql(query: str) -> str:
    """Enforced inline, so we control the refusal text the agent sees."""
    decision = aegis.check("run_sql", {"query": query})
    if decision.blocked:
        return f"refused by Aegis policy ({decision.rule}): {decision.message}"
    return f"(demo) would execute: {query}"


@app.tool()
def delete_record(record_id: int) -> str:
    """Raise-style: aegis.guard raises aegis.Denied on a block."""
    try:
        aegis.guard("delete_record", {"record_id": record_id})
    except aegis.Denied as exc:
        return f"refused: {exc.decision.message}"
    _RECORDS.pop(record_id, None)
    return "deleted"


if __name__ == "__main__":
    app.run()
