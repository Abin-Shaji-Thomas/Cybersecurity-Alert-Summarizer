"""The full NLP pipeline:  load -> Unit I -> Unit II -> Unit III -> Unit IV -> Unit V.

run_pipeline(df) takes the DataFrame from load_data.to_dataframe() and returns plain Python
structures that db/database.py stores in SQLite.

Speed caps (so it runs on a normal laptop CPU):
  * alerts are deduplicated in load_data before anything else;
  * spaCy (POS/NER/dependency) runs on at most SPACY_CAP unique sentence patterns (the time of day is
    removed first, so identical alerts at different times are parsed once). Rare patterns go first;
    alerts beyond the cap get their entities/triple from the structured fields instead;
  * word co-occurrence vectors use at most VECTOR_CAP sentences.
"""
import random
import re
import time
from collections import Counter

import numpy as np

from . import unit1_preprocess_lm as u1
from . import unit2_pos_ner_parse as u2
from . import unit3_dependency_semantics as u3
from . import unit4_tfidf_ie as u4
from . import unit5_summarize_qa as u5

SPACY_CAP = 3000
VECTOR_CAP = 20000
TIME_PREFIX = re.compile(r"^At \d{2}:\d{2}:\d{2}, ")


def _fallback_entities(a):
    """Entities from structured fields, for alerts beyond the spaCy cap."""
    ents = []
    if a.get("host"):
        ents.append({"text": a["host"], "label": "HOST"})
    if a.get("user"):
        ents.append({"text": a["user"], "label": "USER"})
    if a.get("src_ip"):
        ents.append({"text": a["src_ip"], "label": "IP"})
    if a.get("dst_port"):
        ents.append({"text": str(a["dst_port"]), "label": "PORT"})
    for m in str(a.get("mitre_id") or "").split(","):
        if m:
            ents.append({"text": m, "label": "MITRE_TECHNIQUE"})
    return ents


def run_pipeline(df, log=print):
    t0 = time.time()
    df = df.copy().reset_index(drop=True)
    timings = {}

    # ------------------------------------------------ UNIT I: preprocessing, alert types, LM, rarity
    type_of, alert_types = u1.merge_alert_types(list(df["description"]))
    df["alert_type"] = df["description"].map(type_of)
    lm, lm_stats, token_lists = u1.train_and_evaluate_lm(list(df["sentence"]))
    df["rarity_score"] = u1.rarity_scores(lm, token_lists)
    timings["unit1"] = round(time.time() - t0, 2)
    log(f"unit1 done: {len(alert_types)} alert types, test PP {lm_stats['perplexity_test_smoothed']}")

    # ------------------------------------------------ UNIT II + III: spaCy NER, dependency triples
    t = time.time()
    u2.add_host_patterns(df["host"].unique())
    keys = df["sentence"].str.replace(TIME_PREFIX, "", regex=True)
    df["_key"] = keys
    key_rarity = df.groupby("_key")["rarity_score"].max().sort_values(ascending=False)
    parse_keys = list(key_rarity.index[:SPACY_CAP])
    nlp = u2.get_nlp()
    parsed = {}
    for k, doc in zip(parse_keys, nlp.pipe(parse_keys, batch_size=256)):
        parsed[k] = (u2.extract_entities(doc), u3.extract_triple(doc))
    entities, triples = [], []
    for a in df.to_dict("records"):
        if a["_key"] in parsed:
            ents, tri = parsed[a["_key"]]
            # MITRE ids are a structured field, not part of the sentence: add them for parsed alerts too
            ents = ents + [e for e in _fallback_entities(a) if e["label"] == "MITRE_TECHNIQUE"]
        else:
            ents = _fallback_entities(a)
            tri = {"actor": a["src_ip"] or a["user"], "action": a["description"].lower(), "action_head": None,
                   "target": a["host"] + (f":{a['dst_port']}" if a["dst_port"] else "")}
        entities.append(ents)
        triples.append(tri)
    timings["unit2_3"] = round(time.time() - t, 2)
    log(f"unit2/3 done: parsed {len(parsed)} unique patterns of {key_rarity.size}")

    # ------------------------------------------------ UNIT IV: TF-IDF clusters -> incidents, PMI, vectors
    t = time.time()
    clu = u4.cluster_alerts(df)
    df["cluster"] = clu["cluster"]
    incident_of = u4.split_incidents(df, clu["cluster"])
    df["_incident"] = df.index.map(incident_of)

    phases, scenario, phase_method = u5.assign_phases(df)
    df["phase"] = phases

    sample = token_lists if len(token_lists) <= VECTOR_CAP else random.Random(0).sample(token_lists, VECTOR_CAP)
    vocab, M = u3.cooccurrence_vectors(sample)
    P = u4.ppmi_matrix(M)
    neighbours = {w: u3.cosine_neighbours(w, vocab, P) for w in u3.QUERY_WORDS if w in vocab}
    neighbours_raw = {w: u3.cosine_neighbours(w, vocab, M) for w in u3.QUERY_WORDS if w in vocab}
    word_eval = u4.evaluate_word_pairs(vocab, P)
    word_eval_raw = u4.evaluate_word_pairs(vocab, M)
    pmi = u4.pmi_pairs(token_lists)
    clu_purity = u4.purity(df["cluster"], df["phase"]) if scenario else None
    inc_purity = u4.purity(df["_incident"], df["phase"]) if scenario else None
    timings["unit4"] = round(time.time() - t, 2)
    log(f"unit4 done: k={clu['k']} silhouette={clu['silhouette']} incidents={df['_incident'].nunique()}")

    # ------------------------------------------------ UNIT V: severity, template filling, summaries
    t = time.time()
    df["_very_rare"] = df["rarity_score"] >= df["rarity_score"].quantile(0.95)
    vec = clu["vectorizer"]
    incidents = []
    order = df.groupby("_incident")["timestamp"].min().sort_values().index
    new_id = {old: i for i, old in enumerate(order)}
    df["incident_idx"] = df["_incident"].map(new_id)
    for old in order:
        g = df[df["_incident"] == old]
        sev, score = u5.incident_severity(g)
        slots = u5.fill_template(g, clu["keywords"][int(g["cluster"].iloc[0])], sev, g["level"].max())
        rel = Counter()
        for i in g.index:
            for r in u4.extract_relations(df.loc[i], entities[i], triples[i]):
                rel[r] += 1
        incidents.append({
            "idx": new_id[old],
            "title": slots["title"],
            "keywords": ", ".join(slots["keywords"]),
            "severity": sev,
            "severity_score": score,
            "start_time": slots["start_time"],
            "end_time": slots["end_time"],
            "n_alerts": len(g),
            "summary_template": u5.render_template(slots),
            "summary_extractive": u5.extractive_summary(list(g["sentence"]), vec),
            "recommended_action": slots["recommended_action"],
            "slots": slots,
            "relations": [{"subject": s, "relation": r, "object": o, "count": c} for (s, r, o), c in rel.most_common(60)],
        })
    timings["unit5"] = round(time.time() - t, 2)

    # SRL roles for each alert are computed on demand in the API (cheap); store triples per alert
    df["triple_actor"] = [tr.get("actor") for tr in triples]
    # action verb (Unit III); alerts beyond the spaCy cap reuse the verb found for the same description
    verb_of_desc = {}
    for d, tr in zip(df["description"], triples):
        if tr.get("action_head"):
            verb_of_desc.setdefault(d, tr["action_head"])
    df["triple_action"] = [tr.get("action_head") or verb_of_desc.get(d) for d, tr in zip(df["description"], triples)]
    df["triple_target"] = [tr.get("target") for tr in triples]

    sev_counts = Counter(i["severity"] for i in incidents)
    insights = {
        "scenario": scenario,
        "phase_method": phase_method,
        "unit1": {
            "lm": lm_stats,
            "alert_types": alert_types[:30],
            "n_alert_types": len(alert_types),
            "n_descriptions": int(df["description"].nunique()),
            "rarest_alerts": (df.sort_values("rarity_score", ascending=False).drop_duplicates("description")
                              .head(10)[["description", "sentence", "rarity_score"]].to_dict("records")),
            "commonest_alerts": (df.sort_values("rarity_score").drop_duplicates("description")
                                 .head(5)[["description", "sentence", "rarity_score"]].to_dict("records")),
        },
        "unit2_3": {"n_parsed_patterns": len(parsed), "n_unique_patterns": int(key_rarity.size),
                    "spacy_cap": SPACY_CAP,
                    "entity_label_counts": dict(Counter(e["label"] for ents in entities for e in ents).most_common())},
        "unit3": {"neighbours_ppmi": neighbours, "neighbours_counts": neighbours_raw, "vocab_size": len(vocab)},
        "unit4": {
            "k": clu["k"], "silhouette": clu["silhouette"], "k_scores": clu["k_scores"],
            "cluster_keywords": {str(k): v for k, v in clu["keywords"].items()},
            "cluster_sizes": {str(k): int(v) for k, v in Counter(df["cluster"]).items()},
            "purity_clusters": clu_purity, "purity_incidents": inc_purity,
            "pmi_pairs": pmi,
            "word_pca": u4.word_pca(vocab, P),
            "alert_pca": u4.alert_pca(clu),
            "word_similarity_ppmi": word_eval, "word_similarity_counts": word_eval_raw,
        },
        "unit5": {"temporal_links": u5.temporal_links(incidents),
                  "phase_counts": dict(Counter(df["phase"]).most_common()),
                  "severity_counts": dict(sev_counts)},
        "timings_sec": {**timings, "total": round(time.time() - t0, 2)},
    }

    stats = {
        "n_alerts": len(df),
        "n_alert_types": len(alert_types),
        "n_incidents": len(incidents),
        "n_high": sev_counts.get("High", 0) + sev_counts.get("Critical", 0),
        "perplexity_smoothed": lm_stats["perplexity_test_smoothed"],
        "perplexity_unsmoothed": lm_stats["perplexity_test_unsmoothed"],
    }
    log(f"pipeline finished in {insights['timings_sec']['total']} s")
    return {"alerts": df, "entities": entities, "incidents": incidents, "insights": insights, "stats": stats,
            "lm": lm, "vectorizer": vec, "vocab": vocab, "vectors": P}


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    from .load_data import load_alerts
    path = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[2] / "data" / "sample" / "sample_alerts.json")
    res = run_pipeline(load_alerts(path))
    print(json.dumps(res["stats"], indent=1))
    for inc in sorted(res["incidents"], key=lambda i: -i["severity_score"])[:8]:
        print(f"[{inc['severity']}] {inc['n_alerts']:5d}  {inc['title']}")
        print("   ", inc["summary_template"])
