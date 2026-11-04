"""UNIT V - Advanced NLP Applications.

Techniques in this file:
  1. Temporal analysis: events are ordered in time and labelled with an attack PHASE.
     For AIT-ADS data the phase comes from labels.csv windows; otherwise a simple rule maps the MITRE
     tactic to a phase (recon -> initial access -> credential access -> priv-esc ...).
     This mirrors TimeBank-style annotation: EVENTS (alerts), TIME EXPRESSIONS (timestamps, windows)
     and TEMPORAL LINKS between events (BEFORE / AFTER / OVERLAPS between incidents).
  2. Rule-based Semantic Role Labelling: a triple becomes Agent / Action / Patient / Time / Location.
  3. TEMPLATE FILLING (main summary): fill slots {title, what happened, attacker, targets, time window,
     phases, severity, MITRE techniques, rare alerts, recommended action} and render 3-5 sentences.
     ASPECT analysis adds two slots: frequency (one-off / repeated / ongoing) and outcome (attempted / succeeded).
  4. Extractive baseline: pick the alert sentences closest to the incident's TF-IDF centroid.
  5. Abstractive comparison: a small pretrained seq2seq summarizer (distilbart-cnn-6-6, CPU), loaded
     lazily and run only when the user clicks "Generate AI summary".
  6. QA / IR + chatbot: TF-IDF retrieval of relevant alerts + rules over extracted entities/relations.
Machine translation, speech recognition and TTS are documented only (docs/UNIT_MAPPING.md).
"""
import csv
import os
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .unit4_tfidf_ie import feature_text

LABELS_CSV = Path(__file__).resolve().parents[2] / "data" / "raw" / "labels.csv"
LABELS_FALLBACK = Path(__file__).resolve().parents[2] / "data" / "eval" / "labels.csv"
ABSTRACTIVE_MODEL = os.environ.get("SUMMARIZER_MODEL", "sshleifer/distilbart-cnn-6-6")

# ---------------------------------------------------------------- 1. temporal analysis / phases
PHASE_ORDER = ["network_scans", "service_scans", "wpscan", "dirb", "webshell", "cracking", "reverse_shell",
               "privilege_escalation", "service_stop", "dnsteal",
               "reconnaissance", "initial_access", "credential_access", "privilege_escalation_rule",
               "lateral_movement", "exfiltration", "normal"]

# MITRE tactic -> phase, used when the data is not from AIT-ADS. T1078 (Valid Accounts) is attached
# by Wazuh to every successful login, so on its own it does not mean an attack.
TACTIC_PHASE = [("Exfiltration", "exfiltration"), ("Lateral Movement", "lateral_movement"),
                ("Privilege Escalation", "privilege_escalation"), ("Credential Access", "credential_access"),
                ("Initial Access", "initial_access"), ("Reconnaissance", "reconnaissance")]


def load_label_windows():
    path = LABELS_CSV if LABELS_CSV.exists() else LABELS_FALLBACK
    if not path.exists():
        return {}
    windows = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            windows.setdefault(r["scenario"], []).append((r["attack"], float(r["start"]), float(r["end"])))
    return windows


def detect_scenario(timestamps):
    """Which AIT-ADS scenario do these alerts come from? The one whose attack windows contain the most
    alert timestamps (the scenarios happened on different dates, so this is unambiguous)."""
    windows = load_label_windows()
    ts = np.array([t.timestamp() for t in timestamps])
    best, best_n = None, 0
    for scen, ws in windows.items():
        n = sum(int(((ts >= s) & (ts < e)).sum()) for _, s, e in ws)
        if n > best_n:
            best, best_n = scen, n
    return best, windows.get(best, [])


def phase_from_tactic(mitre_id, tactic):
    if not tactic or (mitre_id or "").strip() == "T1078":
        return "normal"
    for t, phase in TACTIC_PHASE:
        if t in tactic:
            return phase
    return "normal"


def assign_phases(df):
    """Returns (phase list, scenario name or None, method string)."""
    scenario, ws = detect_scenario(df["timestamp"])
    if scenario:
        phases = []
        for t in df["timestamp"]:
            x = t.timestamp()
            phases.append(next((a for a, s, e in ws if s <= x < e), "normal"))
        return phases, scenario, "AIT-ADS labels.csv time windows"
    return [phase_from_tactic(m, t) for m, t in zip(df["mitre_id"], df["mitre_tactic"])], None, "MITRE tactic rules"


def temporal_links(incidents):
    """TimeBank-style TLINKs between incidents ordered by start time."""
    inc = sorted(incidents, key=lambda i: i["start_time"])
    links = []
    for a, b in zip(inc, inc[1:]):
        rel = "BEFORE" if a["end_time"] < b["start_time"] else "OVERLAPS"
        links.append({"a": a["title"], "relation": rel, "b": b["title"]})
    return links[:40]


# ---------------------------------------------------------------- 2. rule-based SRL
def srl_roles(triple, alert):
    """Action = the verb found by Unit III. If the description gave no usable verb (e.g. 'Multiple IDS
    events from same source ip'), fall back to 'trigger': the agent's activity triggered the alert."""
    verb = triple.get("action_head") or "trigger"
    return {
        "Agent": triple.get("actor") or "unknown source",
        "Action": f"{verb} ({alert['description'][:60]})",
        "Patient": (f"port {alert['dst_port']}" if alert.get("dst_port") else None) or alert.get("url") or alert.get("user"),
        "Time": alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Location": alert.get("host"),
    }


# ---------------------------------------------------------------- 3. template filling
# Recommended action lookup: first matching keyword (in the alert descriptions) or MITRE tactic wins.
ACTIONS = [
    ("sudo to root", "Verify the sudo/root activity with the account owner, review commands run, and reset credentials if it was not authorised."),
    ("changed uid", "Verify the privilege change, review commands run as root, and reset credentials if it was not authorised."),
    ("exploit", "Patch the software named in the alert (see the CVE), block the source IP and check the host for signs of compromise."),
    ("brute force", "Block the source IP, enforce account lockout and MFA, and check for any successful logins after the failures."),
    ("authentication fail", "Check whether the failures are followed by a success; block the source and enforce lockout if it is guessing passwords."),
    ("invalid user", "Block the source IP and check for successful logins from it; disable unused accounts."),
    ("web server 400", "Block or rate-limit the scanning IP at the firewall/WAF and check the web server for exposed or vulnerable paths (directory brute-forcing / WordPress scanning)."),
    ("common web attack", "Inspect the requested URLs for injection payloads, patch the web application, and block the source at the WAF."),
    ("suspicious url", "Inspect the requested URLs for web-shell or exploit access and scan the web root for uploaded files."),
    ("nmap", "Block the scanning source at the perimeter and review which services were exposed."),
    ("scan", "Block the scanning source at the perimeter and review which services were exposed."),
    ("tls invalid", "Check the TLS clients involved; malformed TLS traffic can indicate tunnelling or non-TLS traffic on TLS ports."),
    ("dns", "Check DNS logs for long or high-volume queries (possible DNS tunnelling / exfiltration) and block the destination."),
    ("dovecot authentication success", "Normal mail logins; confirm the volume and source IPs match expected users."),
    ("clamav", "Routine antivirus update; no action needed."),
]
TACTIC_ACTIONS = {
    "Privilege Escalation": "Review privileged activity on the host and contain it if unauthorised.",
    "Credential Access": "Reset affected credentials and enforce MFA.",
    "Reconnaissance": "Block the scanning source and reduce the exposed attack surface.",
    "Lateral Movement": "Isolate the affected hosts and review remote logins.",
    "Initial Access": "Patch the exposed service, block the source and check the host for signs of compromise.",
}


def recommend_action(descriptions, tactics):
    """descriptions / tactics come from the incident's MOST SEVERE alerts, so a routine alert that happens to sit
    in the same incident (e.g. a ClamAV update) cannot decide the advice for an attack."""
    text = " ".join(descriptions).lower()
    for key, action in ACTIONS:
        if key in text:
            return action
    for t in tactics:
        for k, v in TACTIC_ACTIONS.items():
            if k in (t or ""):
                return v
    return "Review the alerts and confirm whether the activity is expected."


SEV_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
ESCALATING = {"Privilege Escalation": 3, "Credential Access": 2, "Lateral Movement": 2, "Initial Access": 2,
              "Reconnaissance": 1, "Exfiltration": 3}


def incident_severity(g):
    """Score = max Wazuh level + bonuses; mapped to Low / Medium / High / Critical.
      +2 if one source produced >= 50 suspicious (level >= 5) alerts (scan / brute-force volume)
      +MITRE tactic weight (T1078 'valid accounts' on normal logins is ignored)
      +1 if the incident contains very unusual alerts (rarity in the top 5 % of the analysis)."""
    score = int(g["level"].max())
    top_src = g.loc[g["level"] >= 5, "src_ip"].dropna().value_counts()
    if len(top_src) and top_src.iloc[0] >= 50:
        score += 2
    tactic_bonus = 0
    for m, t in zip(g["mitre_id"], g["mitre_tactic"]):
        if t and m != "T1078":
            tactic_bonus = max(tactic_bonus, max((w for k, w in ESCALATING.items() if k in t), default=0))
    score += tactic_bonus
    if g.get("_very_rare") is not None and g["_very_rare"].any():
        score += 1
    label = "Critical" if score >= 12 else "High" if score >= 9 else "Medium" if score >= 6 else "Low"
    return label, score


def _fmt_list(items, n=3):
    items = [str(i) for i in items if i]
    if not items:
        return "none"
    if len(items) <= n:
        return ", ".join(items)
    return ", ".join(items[:n]) + f" and {len(items) - n} more"


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def _duration(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec} s"
    if sec < 3600:
        return f"{sec // 60} min {sec % 60} s"
    return f"{sec // 3600} h {(sec % 3600) // 60} min"


# ---------------------------------------------------------------- aspect analysis
# Two ASPECTS of every incident, decided by simple rules:
#   frequency: one-off (1-2 alerts) / repeated (several alerts within 30 min) / ongoing (spans >= 30 min)
#   outcome  : succeeded if a success alert (login accepted, sudo executed, session opened...) belongs to the
#              activity (see attacker_successes), otherwise attempted (only failures, scans, errors, IDS
#              detections or unrelated logins).
SUCCESS_WORDS = ("success", "accepted", "session opened", "executed", "changed uid", "logged in")


def attacker_successes(g):
    """Success alerts that belong to the attack. The 'attackers' are the source IPs of suspicious alerts
    (level >= 5). A success counts if it comes from one of them, or if it is a local event without a source IP
    (sudo, PAM session) on a host they attacked. With no suspicious source at all, every success counts."""
    success = g[g["description"].str.lower().apply(lambda d: any(w in d for w in SUCCESS_WORDS)).values]
    bad = g[(g["level"] >= 5).values & g["src_ip"].notna().values] if "src_ip" in g else g.iloc[0:0]
    if bad.empty:
        return success
    keep = success["src_ip"].isin(set(bad["src_ip"])) | (success["src_ip"].isna() & success["host"].isin(set(bad["host"])))
    return success[keep.values]


def incident_aspects(g):
    n = len(g)
    span = (g["timestamp"].max() - g["timestamp"].min()).total_seconds()
    frequency = "one-off" if n <= 2 else "ongoing" if span >= 30 * 60 else "repeated"
    hits = attacker_successes(g)["description"] if {"src_ip", "host", "level"} <= set(g.columns) else \
        g.loc[g["description"].str.lower().apply(lambda d: any(w in d for w in SUCCESS_WORDS)).values, "description"]
    outcome = "succeeded" if len(hits) else "attempted"
    evidence = (f"{len(hits)} success alert(s), e.g. '{hits.iloc[0]}'" if len(hits)
                else "no alert reports a success")
    return {"frequency": frequency, "outcome": outcome, "outcome_evidence": evidence}


def fill_template(g, keywords, severity, max_level):
    """Fill the slots for one incident (g = DataFrame of its alerts)."""
    types = g["description"].value_counts()
    srcs = g["src_ip"].dropna().value_counts()
    users = g["user"].dropna().value_counts()
    hosts = g["host"].dropna().value_counts()
    ports = g["dst_port"].dropna().astype(int)
    # ports >= 32768 are ephemeral client ports (Suricata reply direction), not targeted services
    ports = ports[ports < 32768].value_counts()
    mitre = Counter(m for ms in g["mitre_id"].dropna() for m in str(ms).split(","))
    tactics = list(dict.fromkeys(t for ts in g["mitre_tactic"].dropna() for t in str(ts).split(",")))
    phases = [p for p in PHASE_ORDER if p in set(g["phase"])]
    rare = g.sort_values("rarity_score", ascending=False).drop_duplicates("description").head(3)
    start, end = g["timestamp"].min(), g["timestamp"].max()
    main_type = types.index[0]
    main_host = hosts.index[0] if len(hosts) else "unknown host"
    title = f"{main_type} on {main_host}" + (f" from {srcs.index[0]}" if len(srcs) else "")
    return {
        "title": title[:140],
        "what_happened": f"{_plural(len(g), 'alert')}, mainly '{main_type}' ({types.iloc[0]})"
                         + (f", plus {_fmt_list([f'{d} ({c})' for d, c in types.iloc[1:3].items()], 2)}" if len(types) > 1 else ""),
        "attacker": _fmt_list([f"{ip} ({_plural(c, 'alert')})" for ip, c in srcs.items()]) if len(srcs) else
                    (_fmt_list([f"user {u}" for u in users.index]) if len(users) else "unknown"),
        "users": _fmt_list(users.index, 5),
        "hosts": _fmt_list(list(hosts.index), 3),
        "ports": _fmt_list(list(ports.index), 4) if len(ports) else "none",
        "targets": _fmt_list(list(hosts.index), 3) + (f" (ports {_fmt_list(list(ports.index), 4)})" if len(ports) else ""),
        "time_window": (f"{start:%Y-%m-%d} {start:%H:%M:%S}" + (f" to {end:%H:%M:%S}" if start.date() == end.date()
                        else f" to {end:%Y-%m-%d %H:%M:%S}") + f" UTC ({_duration((end - start).total_seconds())})"),
        "start_time": start.isoformat(), "end_time": end.isoformat(),
        "phases": ", ".join(phases) if phases else "normal",
        "severity": severity,
        "max_level": int(max_level),
        "mitre_techniques": _fmt_list([f"{m}" for m, _ in mitre.most_common()], 5),
        "mitre_tactics": _fmt_list(tactics, 4),
        "top_rare_alerts": [r["description"] for _, r in rare.iterrows()],
        "keywords": keywords,
        "recommended_action": recommend_action(
            list(g.loc[g["level"] == g["level"].max(), "description"].value_counts().index[:5]),
            list(dict.fromkeys(t for ts in g.loc[g["level"] == g["level"].max(), "mitre_tactic"].dropna()
                               for t in str(ts).split(",")))),
        **incident_aspects(g),
    }


def render_template(s):
    """Turn the filled slots into a 3-5 sentence paragraph."""
    parts = [f"From {s['time_window']}, {s['targets']} raised {s['what_happened']}."]
    if s["attacker"] != "unknown":
        parts.append(f"The activity came from {s['attacker']}.")
    phase_txt = f" in attack phase(s) {s['phases']}" if s["phases"] != "normal" else ""
    mitre_txt = f"; MITRE {s['mitre_techniques']} - {s['mitre_tactics']}" if s["mitre_techniques"] != "none" else ""
    parts.append(f"Severity is {s['severity']} (max Wazuh level {s['max_level']}{mitre_txt}){phase_txt}.")
    if s.get("frequency"):
        result = "it succeeded" if s["outcome"] == "succeeded" else "it was only attempted"
        parts.append(f"Aspects: {s['frequency']} activity; {result} ({s['outcome_evidence']}).")
    if s["top_rare_alerts"] and s["top_rare_alerts"][0] not in s["what_happened"][:200]:
        parts.append(f"The most unusual alert was '{s['top_rare_alerts'][0]}'.")
    parts.append(f"Recommended action: {s['recommended_action']}")
    return " ".join(parts)


# ---------------------------------------------------------------- 4. extractive baseline
def extractive_summary(sentences, vec, n=3):
    """Pick the n sentences closest to the incident centroid in TF-IDF space (distinct alert types),
    then put them back in time order."""
    uniq = list(dict.fromkeys(sentences))
    if not uniq:
        return ""
    X = vec.transform([feature_text(s) for s in uniq])
    centroid = np.asarray(X.mean(axis=0))
    scores = cosine_similarity(X, centroid).ravel()
    chosen, seen = [], set()
    for i in np.argsort(-scores):
        key = re.search(r"'([^']+)'", uniq[i])
        key = key.group(1) if key else uniq[i]
        if key in seen:
            continue
        seen.add(key)
        chosen.append(i)
        if len(chosen) == n:
            break
    # fewer distinct alert types than n: fill up with the next best sentences
    for i in np.argsort(-scores):
        if len(chosen) >= min(n, len(uniq)):
            break
        if i not in chosen:
            chosen.append(i)
    return " ".join(uniq[i] for i in sorted(chosen))


def representative_sentences(sentences, vec, n=12):
    """Input for the abstractive model: up to n distinct, representative sentences."""
    uniq = list(dict.fromkeys(sentences))[:2000]
    X = vec.transform([feature_text(s) for s in uniq])
    scores = cosine_similarity(X, np.asarray(X.mean(axis=0))).ravel()
    out, seen = [], set()
    for i in np.argsort(-scores):
        k = re.search(r"'([^']+)'", uniq[i])
        k = k.group(1) if k else uniq[i]
        if k not in seen:
            seen.add(k)
            out.append(i)
        if len(out) == n:
            break
    return [uniq[i] for i in sorted(out)]


# ---------------------------------------------------------------- 5. abstractive (pretrained, optional)
@lru_cache(maxsize=1)
def _load_summarizer():
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(ABSTRACTIVE_MODEL)
    model = AutoModelForSeq2SeqLM.from_pretrained(ABSTRACTIVE_MODEL)
    model.eval()
    return tok, model


def abstractive_summary(text, max_length=90):
    """Run the pretrained summarizer on CPU. Raises on failure; the API turns that into a clean error."""
    import torch
    tok, model = _load_summarizer()
    prefix = "summarize: " if "t5" in ABSTRACTIVE_MODEL.lower() else ""
    ids = tok(prefix + text, return_tensors="pt", truncation=True, max_length=768)
    with torch.no_grad():
        out = model.generate(**ids, max_length=max_length, min_length=25, num_beams=2, no_repeat_ngram_size=3)
    return tok.decode(out[0], skip_special_tokens=True).strip()


# ---------------------------------------------------------------- 6. QA / IR chatbot
IP_Q = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def retrieve(question, sentences, k=5, vec_cache=None):
    """Information retrieval: TF-IDF cosine between the question and every alert sentence."""
    if vec_cache is None:
        vec = TfidfVectorizer(token_pattern=r"[a-z0-9][a-z0-9_\-.]+", sublinear_tf=True)
        try:
            X = vec.fit_transform([s.lower() for s in sentences])
        except ValueError:          # no usable words at all -> nothing to retrieve
            return []
    else:
        vec, X = vec_cache
    q = vec.transform([question.lower()])
    sims = cosine_similarity(q, X).ravel()
    order = np.argsort(-sims)[:k]
    return [(int(i), float(sims[i])) for i in order if sims[i] > 0]


def answer_question(question, alerts, relations, incidents, vec_cache=None):
    """Rule-based intent detection over the extracted facts + IR for supporting evidence.

    alerts    : DataFrame of the analysis' alerts (with sentence, src_ip, host, user, ...)
    relations : list of dicts {subject, relation, object, n}
    incidents : list of dicts {id, title, severity, start_time, end_time, n_alerts}
    Returns (answer text, list of supporting alert row positions, intent name).
    """
    q = question.lower().strip()
    ips = IP_Q.findall(q)
    sub = alerts
    if ips:
        sub = alerts[(alerts["src_ip"].isin(ips)) | (alerts["dst_ip"].isin(ips))]
    support_df = sub

    def top(series, n=8):
        vc = series.dropna().value_counts()
        more = f" and {len(vc) - n} more" if len(vc) > n else ""
        return ", ".join(f"{k} ({v})" for k, v in vc.head(n).items()) + more

    asks_for_ip = re.search(r"\b(which|what) ips?\b|\bwho\b|\bsource ips?\b|\battacker'?s? ips?\b", q)
    intent = "search"
    if (re.search(r"\bhosts?\b|\bmachines?\b|\bservers?\b|\bsystems?\b", q) and not asks_for_ip
            and ("attack" in q or "target" in q or ips or "which" in q)):
        intent = "hosts"
        if ips:
            hosts = [r["object"] for r in relations if r["subject"] in ips and r["relation"] == "ATTACKED"]
            ans = (f"{', '.join(ips)} attacked: {', '.join(dict.fromkeys(hosts))}." if hosts else
                   f"{', '.join(ips)} appears on hosts: {top(sub['host']) or 'none'}.")
        else:
            ans = "Hosts with alerts: " + top(alerts[alerts["level"] >= 5]["host"] if (alerts["level"] >= 5).any() else alerts["host"]) + "."
    elif re.search(r"\bports?\b", q):
        intent = "ports"
        ans = "Targeted ports: " + (top(sub["dst_port"].dropna().astype(int)) or "none recorded") + "."
    elif re.search(r"succe|log(ged)? ?in\b|get in|break in|compromis", q):
        intent = "success"
        ok = attacker_successes(sub)            # same rule as the incident aspect "succeeded"
        no_attacker = not ((sub["level"] >= 5) & sub["src_ip"].notna()).any()
        if no_attacker:
            ans = ("There is no suspicious source (no alert of level >= 5 with a source IP), so no attacker. "
                   f"{len(ok)} success alert(s) are normal activity" + (f", e.g. '{ok.iloc[0]['description']}'." if len(ok) else "."))
            support_df = ok if len(ok) else sub
        elif len(ok):
            first = ok.sort_values("timestamp").iloc[0]
            ans = (f"Yes: {len(ok)} success alert(s) from the suspicious source(s); the first at "
                   f"{first['timestamp']:%Y-%m-%d %H:%M:%S} UTC: '{first['description']}'"
                   + (f" from {first['src_ip']}" if first["src_ip"] else "")
                   + (f" for user {first['user']}" if first["user"] else "") + f" on {first['host']}.")
            support_df = ok
        else:
            ans = "No: no alert from the suspicious source(s) reports a successful login, session or command."
    elif re.search(r"\bip|attacker|source|who\b", q):
        intent = "ips"
        att = alerts[alerts["level"] >= 5]
        ans = "Source IPs with suspicious alerts (level >= 5): " + (top(att["src_ip"]) or "none") + "."
        support_df = att
    elif re.search(r"\busers?\b|account", q):
        intent = "users"
        ans = "Users seen: " + (top(sub["user"]) or "none") + "."
        support_df = sub[sub["user"].notna()]
    elif re.search(r"when|start|begin|first|end|last|time", q):
        intent = "time"
        att = sub[sub["phase"] != "normal"] if (sub["phase"] != "normal").any() else sub
        if (att["level"] >= 5).any():          # ignore routine low-level alerts inside the windows
            att = att[att["level"] >= 5]
        if len(att):
            ans = (f"The {'attack-phase ' if (sub['phase'] != 'normal').any() else ''}activity starts at "
                   f"{att['timestamp'].min():%Y-%m-%d %H:%M:%S} UTC and ends at {att['timestamp'].max():%Y-%m-%d %H:%M:%S} UTC. "
                   f"Phases in order: {', '.join(p for p in PHASE_ORDER if p in set(att['phase']))}.")
            support_df = att.sort_values("timestamp").head(3)
        else:
            ans = "No matching alerts."
    elif re.search(r"mitre|technique|tactic|att&ck", q):
        intent = "mitre"
        m = sub[sub["mitre_id"].notna()]
        ans = ("MITRE techniques: " + top(m["mitre_id"].str.split(",").explode()) + ". Tactics: " + top(m["mitre_tactic"].str.split(",").explode(), 6) + ".") if len(m) else "No MITRE techniques in these alerts."
        support_df = m
    elif "how many" in q or "count" in q or "number of" in q:
        intent = "count"
        words = [w for w in re.findall(r"[a-z]+", q) if w not in {"how", "many", "count", "number", "of", "the", "were", "was", "are", "there", "did", "in", "total", "s"}]
        stems = {"failed": "fail", "logins": "login", "login": "login", "failures": "fail", "scans": "scan", "errors": "error"}
        keys = [stems.get(w, w.rstrip("s")) for w in words]
        desc = sub["description"].str.lower()
        mask = np.ones(len(sub), dtype=bool)
        syn = {"fail": ["fail", "invalid"], "login": ["login", "authentication", "logon"]}
        for k in keys:
            alts = syn.get(k, [k])
            mask &= desc.apply(lambda d: any(a in d for a in alts)).values
        hit = sub[mask] if keys else sub
        ans = f"{len(hit)} alerts match ({', '.join(keys) if keys else 'all'})." + (f" Most common: {top(hit['description'], 3)}." if len(hit) else "")
        support_df = hit
    elif re.search(r"severe|critical|serious|important|worst|high", q):
        intent = "severity"
        inc = sorted(incidents, key=lambda i: (-SEV_ORDER.get(i["severity"], 0), -i["n_alerts"]))[:3]
        ans = "Most severe incidents: " + "; ".join(f"#{i['id']} {i['title']} [{i['severity']}, {i['n_alerts']} alerts]" for i in inc) + "."
    elif re.search(r"recommend|what (should|to) do|next|mitigat|action", q):
        intent = "action"
        inc = sorted(incidents, key=lambda i: (-SEV_ORDER.get(i["severity"], 0), -i["n_alerts"]))[:2]
        ans = " ".join(f"For '{i['title']}': {i['recommended_action']}" for i in inc)
    else:
        ans = None

    # supporting evidence: IR over the (filtered) alert sentences
    sentences = list(support_df["sentence"])
    if not sentences:
        sentences, support_df = list(alerts["sentence"]), alerts
    hits = retrieve(question, sentences, k=5, vec_cache=vec_cache if support_df is alerts else None)
    if not hits:
        hits = [(i, 0.0) for i in range(min(3, len(sentences)))]
    positions = [support_df.index[i] for i, _ in hits]
    if ans is None:
        ans = "Here are the alerts most relevant to your question (TF-IDF retrieval)."
    return ans, positions, intent


# ---------------------------------------------------------------- NLP Lab demo
def demo(text, triple, alert_like):
    return {"srl": srl_roles(triple, alert_like)}


if __name__ == "__main__":
    import pandas as pd
    t = pd.Timestamp("2022-01-24T03:57:25Z")
    print(srl_roles({"actor": "172.19.131.174", "action": "error code"},
                    {"timestamp": t, "dst_port": 80, "host": "intranet-server", "description": "x"}))
    print(phase_from_tactic("T1110", "Credential Access"))
