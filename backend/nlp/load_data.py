"""Stage 0 - load raw Wazuh / Suricata alerts and turn them into English sentences.

Input : a JSON array or JSON-lines file of Wazuh alerts (AIT-ADS format; Suricata
        alerts arrive inside Wazuh with decoder "json" (eve.json) or "snort" (fast.log)).
Output: a pandas DataFrame with one row per (deduplicated) alert and the columns
        timestamp, source, description, level, src_ip, dst_ip, dst_port, host, user,
        mitre_id, mitre_tactic, url, sentence

Why ALERT-TO-SENTENCE?
    Raw alert strings like "IDS event." or "Web server 400 error code." are too short
    and too broken for NLP (no subject, no object, no time).  We therefore render every
    structured alert as one plain English sentence, e.g.
        "At 03:57:25, host intranet-server reported 'Web server 400 error code' from
         172.19.131.174 targeting port 80 (level 5)."
    These sentences are the TEXT CORPUS used by every later NLP unit (tokenising,
    language model, POS/NER, dependency parsing, TF-IDF, summarisation, QA).
"""
import json
import re

import pandas as pd

COLUMNS = ["timestamp", "source", "description", "level", "src_ip", "dst_ip", "dst_port",
           "host", "user", "mitre_id", "mitre_tactic", "url"]

# "[**] [1:2013504:6] ET POLICY ... [**]" inside Suricata fast.log lines
FAST_LOG_SIG = re.compile(r"\[\*\*\]\s*\[[\d:]+\]\s*(.+?)\s*\[\*\*\]")
USER_IN_LOG = re.compile(r"user=<([^>]+)>|for (?:invalid )?user (\S+)|for (\S+) from")
PORT_FROM_WEBLOG = {"https": 443, "ssl": 443}


def read_alert_file(path_or_text):
    """Read a JSON array or JSON-lines file (path or already-loaded text) into a list of dicts."""
    if isinstance(path_or_text, (bytes, str)) and not str(path_or_text).lstrip().startswith(("[", "{")):
        with open(path_or_text, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = path_or_text.decode("utf-8") if isinstance(path_or_text, bytes) else path_or_text
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        return [d for d in data if isinstance(d, dict)]
    alerts = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            alerts.append(json.loads(line))
    return alerts


def _split_ip_port(value):
    """'91.189.95.85:80' -> ('91.189.95.85', 80)."""
    if not value:
        return None, None
    if value.count(":") == 1:
        ip, port = value.split(":")
        return ip, int(port) if port.isdigit() else None
    return value, None


def flatten_alert(a):
    """Pick the useful fields out of one nested Wazuh alert (field names found in docs/DATASET.md)."""
    rule = a.get("rule") or {}
    data = a.get("data") or {}
    pre = a.get("predecoder") or {}
    decoder = (a.get("decoder") or {}).get("name") or ""
    mitre = rule.get("mitre") or {}
    full_log = a.get("full_log") or ""
    description = (rule.get("description") or "").strip()

    is_suricata = decoder in ("json", "snort") or "suricata" in (a.get("location") or "")
    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dest_ip") or data.get("dstip")
    dst_port = data.get("dest_port")

    if decoder == "snort":
        # fast.log duplicate of an eve.json alert: recover the real signature text
        dst_ip, dst_port = _split_ip_port(dst_ip)
        m = FAST_LOG_SIG.search(full_log)
        if m and description in ("IDS event.", "First time this IDS alert is generated."):
            description = f"Suricata: Alert - {m.group(1)}"
    if decoder == "web-accesslog":
        loc = a.get("location") or ""
        dst_port = 443 if any(k in loc for k in PORT_FROM_WEBLOG) else 80

    user = data.get("dstuser") or data.get("srcuser")
    if not user:
        m = USER_IN_LOG.search(full_log)
        if m:
            user = next(g for g in m.groups() if g)

    url = data.get("url") or (data.get("http") or {}).get("url")
    try:
        dst_port = int(dst_port) if dst_port not in (None, "") else None
    except ValueError:
        dst_port = None

    return {
        "timestamp": a.get("@timestamp") or data.get("timestamp"),
        "source": "suricata" if is_suricata else "wazuh",
        "description": description.rstrip("."),
        "level": int(rule.get("level") or 0),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "host": pre.get("hostname"),
        "agent_ip": (a.get("agent") or {}).get("ip"),
        "user": user,
        "mitre_id": ",".join(mitre.get("id") or []) or None,
        "mitre_tactic": ",".join(dict.fromkeys(mitre.get("tactic") or [])) or None,
        "url": url,
    }


def alert_to_sentence(row):
    """Render one alert as a plain English sentence (the NLP corpus)."""
    t = row["timestamp"].strftime("%H:%M:%S")
    parts = [f"At {t}, host {row['host']} reported '{row['description']}'"]
    if row.get("user"):
        parts.append(f"for user {row['user']}")
    if row.get("src_ip"):
        parts.append(f"from {row['src_ip']}")
    if row.get("dst_port"):
        parts.append(f"targeting port {int(row['dst_port'])}")
    if row.get("url"):
        parts.append(f"requesting {str(row['url'])[:60]}")
    return " ".join(parts) + f" (level {row['level']})."


def to_dataframe(raw_alerts):
    """List of raw alerts -> clean, deduplicated, time-sorted DataFrame with sentences."""
    rows = [flatten_alert(a) for a in raw_alerts if isinstance(a, dict) and a.get("rule")]
    if not rows:
        raise ValueError("No Wazuh/Suricata alerts found (each alert needs a 'rule' object).")
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # Host name: the agent IP is the only host id on many alerts, so learn
    # "agent ip -> hostname" from alerts that do carry a syslog hostname.
    known = df.dropna(subset=["host"]).groupby("agent_ip")["host"].agg(lambda s: s.mode().iat[0]).to_dict()
    df["host"] = df["host"].fillna(df["agent_ip"].map(known)).fillna(df["agent_ip"]).fillna("unknown")

    # DEDUPLICATE FIRST: the same event is logged several times (Dovecot in 3 log files,
    # Suricata in eve.json + fast.log).  Same second + same description + same endpoints = one alert.
    df["_sec"] = df["timestamp"].dt.floor("s")
    key = ["_sec", "description", "src_ip", "dst_ip", "dst_port", "host", "user", "url"]
    df = df.sort_values(["timestamp", "level"], ascending=[True, False])
    df = df.drop_duplicates(subset=key, keep="first")
    df = df.drop(columns=["_sec", "agent_ip"]).reset_index(drop=True)
    # pandas uses NaN for missing values; turn them into None so "if value:" works
    df["dst_port"] = df["dst_port"].astype("Int64")
    df = df.astype(object).where(df.notna(), None)

    df["sentence"] = df.apply(alert_to_sentence, axis=1)
    return df


def load_alerts(path_or_text):
    """Convenience: file path / text -> DataFrame."""
    return to_dataframe(read_alert_file(path_or_text))


if __name__ == "__main__":
    import sys
    from pathlib import Path
    p = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "data" / "sample" / "sample_alerts.json"
    d = load_alerts(str(p))
    print(d.shape)
    print(d.head(10).to_string())
    for s in d["sentence"].head(5):
        print(s)
