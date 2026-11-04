"""Evaluation of the whole pipeline on the two development scenarios of AIT-ADS.

Run from the backend folder:   .venv\\Scripts\\python -m nlp.evaluate          (add --no-abstractive to skip the model)

What is measured (every number comes from actually running the code):
  * Unit I   - bigram LM perplexity on held-out sentences, unsmoothed vs Laplace-smoothed
  * Unit II  - NER precision / recall / F1 against data/eval/ner_gold.csv (50 sentences)
               HMM (our Viterbi) vs spaCy POS agreement on alert sentences
  * Unit III - triple (actor, action, target) precision / recall against data/eval/triples_gold.csv
  * Unit IV  - clustering silhouette, purity against the attack-phase labels, word-similarity check
  * Unit V   - ROUGE-1/2/L of the template, extractive and abstractive summaries against the hand-written
               references in data/eval/reference_summaries.csv (25 incidents)
Outputs: data/eval/results.json (served by GET /api/evaluation), docs/RESULTS.md and docs/figures/*.png
"""
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / "data" / "eval"
RAW = ROOT / "data" / "raw" / "ait_ads"
DOCS = ROOT / "docs"
FIG = DOCS / "figures"
SCENARIOS = ["russellmitchell", "shaw"]


def read_csv(name):
    with open(EVAL / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def prf(tp, n_pred, n_gold):
    p = tp / n_pred if n_pred else 0.0
    r = tp / n_gold if n_gold else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3), "tp": tp, "n_pred": n_pred, "n_gold": n_gold}


# ---------------------------------------------------------------- Unit II: NER
def evaluate_ner():
    """Exact match on (entity text, label) per sentence. Only our security labels are scored, because
    the gold file only annotates those (spaCy's DATE/TIME/ORG... predictions are ignored)."""
    from .unit2_pos_ner_parse import SEC_LABELS, extract_entities, get_nlp
    gold_rows = read_csv("ner_gold.csv")
    nlp = get_nlp()
    per_label = Counter(), Counter(), Counter()  # tp, pred, gold
    errors = []
    for row, doc in zip(gold_rows, nlp.pipe([r["sentence"] for r in gold_rows])):
        gold = Counter(tuple(x.rsplit("|", 1)) for x in row["entities"].split(";") if x)
        pred = Counter((e["text"], e["label"]) for e in extract_entities(doc) if e["label"] in SEC_LABELS)
        tp = gold & pred
        for (_, lab), c in tp.items():
            per_label[0][lab] += c
        for (_, lab), c in pred.items():
            per_label[1][lab] += c
        for (_, lab), c in gold.items():
            per_label[2][lab] += c
        if tp != gold or tp != pred:
            errors.append({"id": row["id"], "missed": sorted(f"{t}|{l}" for t, l in (gold - pred).elements()),
                           "spurious": sorted(f"{t}|{l}" for t, l in (pred - gold).elements())})
    tp, npred, ngold = (sum(c.values()) for c in per_label)
    labels = sorted(set(per_label[1]) | set(per_label[2]))
    return {
        "n_sentences": len(gold_rows),
        "micro": prf(tp, npred, ngold),
        "per_label": {l: prf(per_label[0][l], per_label[1][l], per_label[2][l]) for l in labels},
        "errors": errors,
    }


def evaluate_hmm_vs_spacy():
    """Agreement (not accuracy - there is no gold POS for alerts) between our HMM+Viterbi and spaCy."""
    from .unit2_pos_ner_parse import compare_taggers, get_nlp
    rows = [r for r in read_csv("ner_gold.csv") if r["origin"] != "analyst-note"]
    agree = total = 0
    confusions = Counter()
    for doc in get_nlp().pipe([r["sentence"] for r in rows]):
        tags, _ = compare_taggers(doc)
        agree += sum(t["agree"] for t in tags)
        total += len(tags)
        confusions.update(f"HMM {t['hmm']} / spaCy {t['spacy']}" for t in tags if not t["agree"])
    return {"n_sentences": len(rows), "n_tokens": total, "agreement": round(agree / total, 3),
            "top_disagreements": [{"pair": k, "count": v} for k, v in confusions.most_common(6)]}


# ---------------------------------------------------------------- Unit III: triples
def evaluate_triples():
    from .unit3_dependency_semantics import evaluate_triples as score, extract_triples
    gold = read_csv("triples_gold.csv")
    pred = extract_triples([g["sentence"] for g in gold])
    res = score(pred, gold)
    res["rows"] = [{"id": g["id"], "gold": [g["actor"], g["action_head"], g["target"]],
                    "pred": [p["actor"], p["action_head"], p["target"]],
                    "correct": [str(p.get(k) or "").lower() for k in ("actor", "action_head", "target")]
                               == [str(g.get(k) or "").lower() for k in ("actor", "action_head", "target")]}
                   for g, p in zip(gold, pred)]
    return res


# ---------------------------------------------------------------- Unit V: ROUGE
def find_incident(incidents, ref):
    for inc in incidents:
        if inc["start_time"][:19] == ref["incident_start"] and inc["title"].startswith(ref["main_alert_type"]):
            return inc
    return None


def evaluate_rouge(scenario_runs, with_abstractive=True):
    from rouge_score import rouge_scorer
    from . import unit5_summarize_qa as u5
    scorer = rouge_scorer.RougeScorer(["rouge1", "rouge2", "rougeL"], use_stemmer=True)
    refs = read_csv("reference_summaries.csv")
    systems = ["template", "extractive"] + (["abstractive"] if with_abstractive else [])
    per_item, sums, n = [], {s: Counter() for s in systems}, 0
    abstractive_error, abs_seconds = None, []
    for ref in refs:
        run = scenario_runs[ref["scenario"]]
        inc = find_incident(run["incidents"], ref)
        if inc is None:
            per_item.append({"scenario": ref["scenario"], "incident_start": ref["incident_start"], "matched": False})
            continue
        outs = {"template": inc["summary_template"], "extractive": inc["summary_extractive"]}
        if "abstractive" in systems and abstractive_error is None:
            df = run["alerts"]
            sents = list(df.loc[df["incident_idx"] == inc["idx"], "sentence"])
            try:
                t = time.time()
                outs["abstractive"] = u5.abstractive_summary(" ".join(u5.representative_sentences(sents, run["vectorizer"])))
                abs_seconds.append(time.time() - t)
            except Exception as e:  # noqa: BLE001 - model unavailable: report it, keep the other systems
                abstractive_error = f"{type(e).__name__}: {e}"
        if abstractive_error and "abstractive" in systems:
            systems.remove("abstractive")
            sums.pop("abstractive")
        item = {"scenario": ref["scenario"], "incident_start": ref["incident_start"], "title": inc["title"],
                "matched": True, "reference": ref["reference"], "outputs": outs, "scores": {}}
        for s in systems:
            sc = scorer.score(ref["reference"], outs[s])
            item["scores"][s] = {k: round(v.fmeasure, 4) for k, v in sc.items()}
            for k, v in sc.items():
                sums[s][k] += v.fmeasure
        n += 1
        per_item.append(item)
    mean = {s: {k: round(sums[s][k] / n, 4) for k in ("rouge1", "rouge2", "rougeL")} for s in systems} if n else {}
    return {"n_references": len(refs), "n_matched": n, "mean_f1": mean, "items": per_item,
            "abstractive_model": u5.ABSTRACTIVE_MODEL if "abstractive" in systems else None,
            "abstractive_error": abstractive_error,
            "abstractive_seconds_per_summary": round(sum(abs_seconds) / len(abs_seconds), 2) if abs_seconds else None}


# ---------------------------------------------------------------- scenario runs (Units I + IV)
def run_scenarios():
    from .load_data import load_alerts
    from .pipeline import run_pipeline
    runs, summary = {}, {}
    for scen in SCENARIOS:
        path = RAW / f"{scen}_wazuh.json"
        if not path.exists():
            sys.exit(f"Missing {path}. Run: .venv\\Scripts\\python scripts\\download_data.py")
        t = time.time()
        df = load_alerts(str(path))
        print(f"[{scen}] {len(df)} alerts after dedup, running pipeline ...")
        res = run_pipeline(df, log=lambda m: print(f"   {m}"))
        ins = res["insights"]
        phases = Counter(res["alerts"]["phase"])
        summary[scen] = {
            "n_alerts": res["stats"]["n_alerts"], "n_alert_types": res["stats"]["n_alert_types"],
            "n_incidents": res["stats"]["n_incidents"], "n_high_or_critical": res["stats"]["n_high"],
            "seconds": round(time.time() - t, 1),
            "lm": ins["unit1"]["lm"],
            "clustering": {"k": ins["unit4"]["k"], "silhouette": ins["unit4"]["silhouette"],
                           "k_scores": ins["unit4"]["k_scores"],
                           "purity_clusters": ins["unit4"]["purity_clusters"],
                           "purity_incidents": ins["unit4"]["purity_incidents"],
                           # purity a trivial "everything in one cluster" answer would get
                           "purity_majority_baseline": round(phases.most_common(1)[0][1] / len(res["alerts"]), 4)},
            "word_similarity_ppmi": ins["unit4"]["word_similarity_ppmi"],
            "word_similarity_counts": ins["unit4"]["word_similarity_counts"],
            "phase_counts": dict(phases.most_common()),
        }
        runs[scen] = res
    return runs, summary


# ---------------------------------------------------------------- figures + markdown
def make_figures(r):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    FIG.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    blue, orange, green = "#2a6fdb", "#d95926", "#199e70"
    files = []

    # ROUGE
    mean = r["summarization"]["mean_f1"]
    systems = list(mean)
    metrics = ["rouge1", "rouge2", "rougeL"]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    w = 0.8 / len(systems)
    for i, (s, c) in enumerate(zip(systems, [blue, orange, green])):
        xs = [m + i * w for m in range(3)]
        bars = ax.bar(xs, [mean[s][m] for m in metrics], w * 0.95, label=s, color=c)
        ax.bar_label(bars, fmt="%.2f", fontsize=8)
    ax.set_xticks([m + w * (len(systems) - 1) / 2 for m in range(3)], ["ROUGE-1", "ROUGE-2", "ROUGE-L"])
    ax.set_ylabel("mean F1")
    ax.set_title(f"Summaries vs {r['summarization']['n_matched']} reference summaries")
    ax.legend(frameon=False)
    files.append(_save(fig, "rouge.png"))

    # NER per label
    pl = r["ner"]["per_label"]
    labs = list(pl)
    fig, ax = plt.subplots(figsize=(7, 3.4))
    bars = ax.bar(labs, [pl[l]["f1"] for l in labs], color=blue)
    ax.bar_label(bars, labels=[f"{pl[l]['f1']:.2f}\n(n={pl[l]['n_gold']})" for l in labs], fontsize=7)
    ax.set_ylim(0, 1.25)
    ax.set_ylabel("F1")
    ax.set_title(f"NER F1 per label (micro F1 = {r['ner']['micro']['f1']:.2f})")
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    files.append(_save(fig, "ner_f1.png"))

    # perplexity
    fig, ax = plt.subplots(figsize=(6, 3.2))
    scen = list(r["scenarios"])
    tr = [r["scenarios"][s]["lm"]["perplexity_train_smoothed"] for s in scen]
    te = [r["scenarios"][s]["lm"]["perplexity_test_smoothed"] for s in scen]
    b1 = ax.bar([i - 0.2 for i in range(len(scen))], tr, 0.38, label="train (Laplace)", color=blue)
    b2 = ax.bar([i + 0.2 for i in range(len(scen))], te, 0.38, label="held-out (Laplace)", color=orange)
    ax.bar_label(b1, fmt="%.1f", fontsize=8)
    ax.bar_label(b2, fmt="%.1f", fontsize=8)
    ax.set_xticks(range(len(scen)), scen)
    ax.set_ylabel("perplexity")
    ax.set_title("Bigram LM perplexity (unsmoothed held-out = infinity)")
    ax.legend(frameon=False)
    files.append(_save(fig, "perplexity.png"))

    # silhouette vs k
    fig, ax = plt.subplots(figsize=(6, 3.2))
    for s, c in zip(scen, [blue, orange]):
        ks = r["scenarios"][s]["clustering"]["k_scores"]
        ax.plot([k["k"] for k in ks], [k["silhouette"] for k in ks], marker="o", ms=3, color=c, label=s)
    ax.set_xlabel("k (number of KMeans clusters)")
    ax.set_ylabel("silhouette (cosine)")
    ax.set_title("Choosing k by silhouette score")
    ax.legend(frameon=False)
    files.append(_save(fig, "silhouette.png"))

    # word similarity
    fig, ax = plt.subplots(figsize=(6, 3.2))
    for i, s in enumerate(scen):
        pairs = r["scenarios"][s]["word_similarity_ppmi"]["pairs"]
        for rel, c, off in [(1, green, -0.12), (0, orange, 0.12)]:
            ys = [p["cosine"] for p in pairs if p["related"] == rel]
            ax.scatter([i + off] * len(ys), ys, color=c, s=18, alpha=0.8,
                       label=("related pair" if rel else "unrelated pair") if i == 0 else None)
    ax.set_xticks(range(len(scen)), scen)
    ax.set_ylabel("cosine (PPMI vectors)")
    ax.set_title("Word-similarity check")
    ax.legend(frameon=False)
    files.append(_save(fig, "word_similarity.png"))
    return files


def _save(fig, name):
    import matplotlib.pyplot as plt
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=150)
    plt.close(fig)
    return f"docs/figures/{name}"


def write_markdown(r):
    sm, ner, tri, hmm = r["summarization"], r["ner"], r["triples"], r["hmm_vs_spacy"]
    L = ["# Results", "",
         f"Generated by `python -m nlp.evaluate` on {r['generated_at']} (total {r['seconds']} s). "
         "Every number below comes from that run; the JSON version is `data/eval/results.json`.", "",
         "Gold files (`data/eval/*.csv`) are **DRAFT – student to review**: hand-labelled from the real alerts, "
         "but not yet checked by a second annotator.", "",
         "## Data", "", "| Scenario | Alerts (deduplicated) | Alert types | Incidents | High/Critical | Pipeline time |",
         "|---|---|---|---|---|---|"]
    for s, v in r["scenarios"].items():
        L.append(f"| {s} | {v['n_alerts']:,} | {v['n_alert_types']} | {v['n_incidents']} | {v['n_high_or_critical']} | {v['seconds']} s |")
    L += ["", "## Unit V – Summarisation (ROUGE F1, mean over matched incidents)", "",
          f"{sm['n_matched']} of {sm['n_references']} reference summaries matched an incident "
          "(same scenario, start time and main alert type).", "",
          "| System | ROUGE-1 | ROUGE-2 | ROUGE-L |", "|---|---|---|---|"]
    for s, m in sm["mean_f1"].items():
        L.append(f"| {s} | {m['rouge1']:.4f} | {m['rouge2']:.4f} | {m['rougeL']:.4f} |")
    if sm["abstractive_model"]:
        L += ["", f"Abstractive model: `{sm['abstractive_model']}` on CPU, "
                  f"{sm['abstractive_seconds_per_summary']} s per summary."]
    if sm["abstractive_error"]:
        L += ["", f"Abstractive summarizer failed: `{sm['abstractive_error']}`"]
    L += ["", "![ROUGE](figures/rouge.png)", "",
          "## Unit II – Named entity recognition", "",
          f"{ner['n_sentences']} sentences, exact match on (text, label). Micro P = {ner['micro']['precision']}, "
          f"R = {ner['micro']['recall']}, **F1 = {ner['micro']['f1']}**.", "",
          "| Label | Precision | Recall | F1 | Gold |", "|---|---|---|---|---|"]
    for l, v in ner["per_label"].items():
        L.append(f"| {l} | {v['precision']} | {v['recall']} | {v['f1']} | {v['n_gold']} |")
    L += ["", "![NER](figures/ner_f1.png)", "",
          f"HMM (own Viterbi, trained on the NLTK treebank sample) vs spaCy POS agreement on {hmm['n_sentences']} "
          f"alert sentences ({hmm['n_tokens']} tokens): **{hmm['agreement']}**. "
          "This is agreement, not accuracy; there is no gold POS for alert text.", "",
          "## Unit III – Triple extraction (actor, action, target)", "",
          f"{tri['n_gold']} gold sentences. A triple counts as correct only if all three parts match. "
          f"Precision = {tri['precision']}, Recall = {tri['recall']}, F1 = {tri['f1']}.", "",
          "| Field | Accuracy |", "|---|---|"]
    for k, v in tri["field_accuracy"].items():
        L.append(f"| {k} | {v} |")
    L += ["", "| Scenario | Unsmoothed held-out PP | Laplace held-out PP | Laplace train PP | Test sentences with an unseen bigram |",
          "|---|---|---|---|---|"]
    L.insert(L.index("| Scenario | Unsmoothed held-out PP | Laplace held-out PP | Laplace train PP | Test sentences with an unseen bigram |"),
             "## Unit I – Bigram language model (perplexity)\n")
    for s, v in r["scenarios"].items():
        lm = v["lm"]
        L.append(f"| {s} | {lm['perplexity_test_unsmoothed']} | {lm['perplexity_test_smoothed']} | "
                 f"{lm['perplexity_train_smoothed']} | {lm['test_sentences_with_zero_prob_unsmoothed']} of {lm['n_test_sentences']} |")
    L += ["", "![Perplexity](figures/perplexity.png)", "",
          "## Unit IV – Clustering and vectors", "",
          "| Scenario | k | Silhouette | Purity (clusters) | Purity (incidents) | Majority baseline | Word pairs: related > unrelated |",
          "|---|---|---|---|---|---|---|"]
    for s, v in r["scenarios"].items():
        c, w = v["clustering"], v["word_similarity_ppmi"]
        L.append(f"| {s} | {c['k']} | {c['silhouette']} | {c['purity_clusters']} | {c['purity_incidents']} | "
                 f"{c['purity_majority_baseline']} | {w['pairwise_accuracy']} ({w['n_pairs_in_vocab']} pairs) |")
    L += ["", "Purity is measured against the attack-phase label of each alert (labels.csv time windows). "
          "Most alerts are `normal` background, so the majority baseline is already high; incidents beat it "
          "because they also split on time gaps.", "",
          "Word pairs: probability that a hand-picked related pair has a higher cosine than an unrelated pair "
          "(PPMI-weighted co-occurrence vectors; counts-only vectors are in results.json).", "",
          "![Silhouette](figures/silhouette.png)", "", "![Word similarity](figures/word_similarity.png)", ""]
    (DOCS / "RESULTS.md").write_text("\n".join(L), encoding="utf-8")


def main(with_abstractive=True):
    t0 = time.time()
    print("NER / HMM / triples ...")
    # gold-file evaluations first, with a fresh spaCy pipeline (no host names learnt from scenario data)
    ner, hmm, triples = evaluate_ner(), evaluate_hmm_vs_spacy(), evaluate_triples()
    runs, scen = run_scenarios()
    print("ROUGE" + (" (+ abstractive model, this takes a few minutes)" if with_abstractive else "") + " ...")
    rouge = evaluate_rouge(runs, with_abstractive)
    results = {"generated_at": time.strftime("%Y-%m-%d %H:%M"), "seconds": None,
               "scenarios": scen, "summarization": rouge, "ner": ner, "hmm_vs_spacy": hmm, "triples": triples,
               "caps": {"spacy_unique_patterns": 3000, "cooccurrence_sentences": 20000,
                        "silhouette_sample": 2000, "max_k": 15}}
    results["figures"] = make_figures(results)
    results["seconds"] = round(time.time() - t0, 1)
    (EVAL / "results.json").write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    write_markdown(results)
    print(json.dumps({"rouge": rouge["mean_f1"], "ner": ner["micro"], "triples": {k: triples[k] for k in ("precision", "recall", "f1")},
                      "hmm_agreement": hmm["agreement"]}, indent=1))
    print(f"saved data/eval/results.json, docs/RESULTS.md, docs/figures/ in {results['seconds']} s")


if __name__ == "__main__":
    main(with_abstractive="--no-abstractive" not in sys.argv)
