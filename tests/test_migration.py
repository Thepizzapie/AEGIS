"""Migration / destructive-SQL protection — across shell AND DB MCP tools."""
from aegis.engine import evaluate
from aegis.events import Event, HookEvent
from aegis.policy import Policy


def _sql(query, tool="mcp__db__execute_sql"):
    # a DB MCP tool call: no shell, SQL is in the `query` arg
    return Event.make(HookEvent.PRE_TOOL_USE, tool=tool, args={"query": query})


def _shell(cmd):
    return Event.make(HookEvent.PRE_TOOL_USE, tool="Bash", args={"command": cmd})


def test_drop_table_via_mcp_blocked():
    assert evaluate(_sql("DROP TABLE users;"), Policy()).rule == "destructive-migration"


def test_truncate_blocked():
    assert evaluate(_sql("truncate table sessions"), Policy()).blocked


def test_alter_drop_column_blocked():
    assert evaluate(_sql("ALTER TABLE users DROP COLUMN email"), Policy()).blocked


def test_delete_without_where_blocked():
    assert evaluate(_sql("DELETE FROM orders"), Policy()).blocked


def test_delete_with_where_allowed():
    assert not evaluate(_sql("DELETE FROM orders WHERE id = 1"), Policy()).blocked


def test_select_and_create_allowed():
    assert not evaluate(_sql("SELECT * FROM users WHERE id = 1"), Policy()).blocked
    assert not evaluate(_sql("CREATE TABLE x (id int)"), Policy()).blocked
    assert not evaluate(_sql("INSERT INTO x VALUES (1)"), Policy()).blocked


def test_psql_shell_drop_blocked():
    assert evaluate(_shell('psql -c "DROP TABLE billing"'), Policy()).blocked


def test_migration_reset_commands_blocked():
    assert evaluate(_shell("npx prisma migrate reset --force"), Policy()).blocked
    assert evaluate(_shell("supabase db reset"), Policy()).blocked
    assert evaluate(_shell("alembic downgrade -1"), Policy()).blocked
    assert evaluate(_shell("rake db:drop"), Policy()).blocked


def test_normal_migration_apply_allowed():
    assert not evaluate(_shell("alembic upgrade head"), Policy()).blocked
    assert not evaluate(_shell("npx prisma migrate deploy"), Policy()).blocked


def test_override_sql_comment():
    assert not evaluate(_sql("DROP TABLE temp_scratch; -- aegis-allow"), Policy()).blocked


def test_override_hash():
    assert not evaluate(_shell("supabase db reset  # aegis-allow"), Policy()).blocked
