import duckdb
import pytest

from tip.logs import generator


@pytest.fixture(scope="module")
def logs(tmp_path_factory):
    out = tmp_path_factory.mktemp("logs")
    counts = generator.generate(out / "jsonl", out / "logs.duckdb", seed=7, days=7)
    con = duckdb.connect(str(out / "logs.duckdb"), read_only=True)
    yield counts, con
    con.close()


def test_generation_is_deterministic(tmp_path, logs):
    counts, _ = logs
    assert generator.generate(tmp_path / "jsonl", tmp_path / "again.duckdb", seed=7, days=7) == counts


def test_every_answer_key_event_exists_in_its_table(logs):
    _, con = logs
    key = con.execute("SELECT event_id, table_name FROM scenario_events").fetchall()
    assert len(key) == 16
    for event_id, table in key:
        assert con.execute(f"SELECT count(*) FROM {table} WHERE event_id = ?", [event_id]).fetchone()[0] == 1


def test_attack_covers_the_kill_chain(logs):
    _, con = logs
    techniques = {r[0] for r in con.execute("SELECT technique_id FROM scenario_events").fetchall()}
    assert {
        "T1566.003",
        "T1059.007",
        "T1105",
        "T1555.003",
        "T1539",
        "T1550.004",
        "T1555.006",
        "T1098.001",
        "T1657",
    } <= techniques


def test_theft_reaches_the_sanctioned_address(logs):
    _, con = logs
    rows = con.execute(
        "SELECT initiated_by, asset, status FROM wallet_withdrawals WHERE to_address = ?",
        [generator.SANCTIONED_ADDRESS],
    ).fetchall()
    assert rows == [("api-key:svc-withdrawals", "USDT", "completed")]


def test_session_replay_reuses_a_real_session(logs):
    """The replayed session must be the victim's own earlier session, or the scenario wouldn't hang together."""
    _, con = logs
    replayed = con.execute(
        "SELECT DISTINCT session_id FROM auth_events WHERE src_ip = ?", [generator.REPLAY_IP]
    ).fetchall()
    assert len(replayed) == 1
    legit = con.execute(
        "SELECT count(*) FROM auth_events WHERE session_id = ? AND src_ip <> ? AND user_name = ?",
        [replayed[0][0], generator.REPLAY_IP, generator.VICTIM],
    ).fetchone()[0]
    assert legit > 0


def test_benign_noise_resembles_the_attack(logs):
    """Detections must be precise: other engineers also run node and curl, and service roles read the same secret."""
    _, con = logs
    q = "SELECT count(*) FROM {t} WHERE {cond} AND event_id NOT IN (SELECT event_id FROM scenario_events)"
    assert con.execute(q.format(t="endpoint_events", cond="process IN ('node', 'curl')")).fetchone()[0] > 100
    assert (
        con.execute(q.format(t="cloud_audit", cond="resource LIKE '%hot-wallet/withdrawal-api-key'")).fetchone()[0] > 10
    )
    assert con.execute(q.format(t="auth_events", cond="country <> 'US'")).fetchone()[0] > 0
