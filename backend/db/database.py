"""SQLite helper: one connection per call, plain SQL queries, rows returned as dicts."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get("ALERT_DB", ROOT / "data" / "app.db"))
SCHEMA = Path(__file__).with_name("schema.sql")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")   # SQLite needs this per connection
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connect() as c:
        c.executescript(SCHEMA.read_text(encoding="utf-8"))


def rows(cur):
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------- analyses
def create_analysis(filename):
    with connect() as c:
        cur = c.execute("INSERT INTO analyses (filename, uploaded_at, status) VALUES (?, ?, 'processing')",
                        (filename, now()))
        return cur.lastrowid


def mark_failed(analysis_id, error):
    with connect() as c:
        c.execute("UPDATE analyses SET status='failed', error=?, finished_at=? WHERE id=?",
                  (str(error)[:2000], now(), analysis_id))


ANALYSIS_COLS = ("id, filename, uploaded_at, finished_at, status, error, n_alerts, n_alert_types, n_incidents, "
                 "n_high, perplexity_smoothed, perplexity_unsmoothed, scenario")


def list_analyses():
    with connect() as c:
        return rows(c.execute(f"SELECT {ANALYSIS_COLS} FROM analyses ORDER BY id DESC"))


def get_analysis(analysis_id, with_insights=False):
    cols = ANALYSIS_COLS + (", insights_json" if with_insights else "")
    with connect() as c:
        r = c.execute(f"SELECT {cols} FROM analyses WHERE id=?", (analysis_id,)).fetchone()
    if r is None:
        return None
    d = dict(r)
    if with_insights:
        d["insights"] = json.loads(d.pop("insights_json") or "{}")
    return d


def delete_analysis(analysis_id):
    with connect() as c:
        return c.execute("DELETE FROM analyses WHERE id=?", (analysis_id,)).rowcount


def _clean(v):
    """numpy / pandas values -> plain Python for sqlite3."""
    if v is None:
        return None
    if hasattr(v, "item"):
        v = v.item()
    if isinstance(v, float) and v != v:  # NaN
        return None
    return v


def save_results(analysis_id, res):
    """Store everything produced by nlp.pipeline.run_pipeline in one transaction."""
    df = res["alerts"]
    with connect() as c:
        inc_db_id = {}
        for inc in res["incidents"]:
            cur = c.execute(
                """INSERT INTO incidents (analysis_id, title, keywords, severity, severity_score, start_time, end_time,
                   n_alerts, summary_template, summary_extractive, recommended_action, slots_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (analysis_id, inc["title"], inc["keywords"], inc["severity"], inc["severity_score"], inc["start_time"],
                 inc["end_time"], inc["n_alerts"], inc["summary_template"], inc["summary_extractive"],
                 inc["recommended_action"], json.dumps(inc["slots"], default=str)))
            inc_db_id[inc["idx"]] = cur.lastrowid
            c.executemany("INSERT INTO relations (incident_id, subject, relation, object, count) VALUES (?,?,?,?,?)",
                          [(cur.lastrowid, str(r["subject"]), r["relation"], str(r["object"]), r["count"])
                           for r in inc["relations"]])

        cols = ["timestamp", "source", "description", "sentence", "level", "src_ip", "dst_ip", "dst_port", "host",
                "user", "mitre_id", "mitre_tactic", "url", "alert_type", "rarity_score", "cluster", "phase",
                "triple_actor", "triple_action", "triple_target"]
        entity_rows = []
        for pos, a in enumerate(df[cols + ["incident_idx"]].to_dict("records")):
            values = [a["timestamp"].isoformat()] + [_clean(a[k]) for k in cols[1:]]
            cur = c.execute(
                f"INSERT INTO alerts (analysis_id, incident_id, {', '.join(cols)}) VALUES (?, ?, {', '.join('?' * len(cols))})",
                [analysis_id, inc_db_id[a["incident_idx"]]] + values)
            alert_id = cur.lastrowid
            entity_rows += [(analysis_id, alert_id, e["text"], e["label"]) for e in res["entities"][pos]]
        c.executemany("INSERT INTO entities (analysis_id, alert_id, text, label) VALUES (?,?,?,?)", entity_rows)

        s = res["stats"]
        c.execute(
            """UPDATE analyses SET status='done', finished_at=?, n_alerts=?, n_alert_types=?, n_incidents=?, n_high=?,
               perplexity_smoothed=?, perplexity_unsmoothed=?, scenario=?, insights_json=? WHERE id=?""",
            (now(), s["n_alerts"], s["n_alert_types"], s["n_incidents"], s["n_high"], s["perplexity_smoothed"],
             str(s["perplexity_unsmoothed"]), res["insights"].get("scenario"),
             json.dumps(res["insights"], default=str), analysis_id))


# ---------------------------------------------------------------- incidents
INCIDENT_LIST_COLS = ("id, analysis_id, title, keywords, severity, severity_score, start_time, end_time, n_alerts, "
                      "summary_template, recommended_action")


def list_incidents(analysis_id):
    with connect() as c:
        return rows(c.execute(
            f"SELECT {INCIDENT_LIST_COLS} FROM incidents WHERE analysis_id=? ORDER BY severity_score DESC, n_alerts DESC",
            (analysis_id,)))


def get_incident(incident_id):
    with connect() as c:
        r = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["slots"] = json.loads(d.pop("slots_json") or "{}")
        d["relations"] = rows(c.execute(
            "SELECT subject, relation, object, count FROM relations WHERE incident_id=? ORDER BY count DESC", (incident_id,)))
    return d


def set_abstractive(incident_id, text):
    with connect() as c:
        c.execute("UPDATE incidents SET summary_abstractive=? WHERE id=?", (text, incident_id))


# ---------------------------------------------------------------- alerts / entities / relations
def get_alerts(analysis_id=None, incident_id=None, limit=None, order="timestamp"):
    where, args = [], []
    if analysis_id is not None:
        where.append("analysis_id=?")
        args.append(analysis_id)
    if incident_id is not None:
        where.append("incident_id=?")
        args.append(incident_id)
    sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY {order}"
    if limit:
        sql += f" LIMIT {int(limit)}"
    with connect() as c:
        return rows(c.execute(sql, args))


def get_entities_summary(analysis_id, limit=500):
    """Distinct entities with how many alerts mention them (GROUP BY)."""
    with connect() as c:
        return rows(c.execute(
            """SELECT text, label, COUNT(*) AS n_mentions, COUNT(DISTINCT alert_id) AS n_alerts
               FROM entities WHERE analysis_id=? GROUP BY text, label ORDER BY n_mentions DESC LIMIT ?""",
            (analysis_id, limit)))


def get_entities_for_alerts(alert_ids):
    if not alert_ids:
        return []
    with connect() as c:
        q = ",".join("?" * len(alert_ids))
        return rows(c.execute(f"SELECT alert_id, text, label FROM entities WHERE alert_id IN ({q})", list(alert_ids)))


def get_relations(analysis_id):
    """All relations of an analysis, summed over incidents (JOIN relations -> incidents)."""
    with connect() as c:
        return rows(c.execute(
            """SELECT r.subject, r.relation, r.object, SUM(r.count) AS count
               FROM relations r JOIN incidents i ON i.id = r.incident_id
               WHERE i.analysis_id=? GROUP BY r.subject, r.relation, r.object ORDER BY count DESC""",
            (analysis_id,)))


# ---------------------------------------------------------------- QA log
def log_qa(analysis_id, question, answer):
    with connect() as c:
        c.execute("INSERT INTO qa_logs (analysis_id, question, answer, asked_at) VALUES (?,?,?,?)",
                  (analysis_id, question, answer, now()))


def get_qa_logs(analysis_id):
    with connect() as c:
        return rows(c.execute("SELECT question, answer, asked_at FROM qa_logs WHERE analysis_id=? ORDER BY id",
                              (analysis_id,)))
