"""UNIT IV - Embeddings & Information Extraction.

Techniques in this file:
  1. TF-IDF (scikit-learn): each alert sentence -> sparse vector; words frequent in this alert but
     rare overall get high weight.  KMeans on these vectors groups similar alerts; the number of
     clusters k is chosen by the SILHOUETTE score; clusters are then split at large time gaps, and
     every (cluster, time segment) is one INCIDENT.  Top TF-IDF words of a cluster = its keywords.
  2. PMI / PPMI (our own code): PMI(x, y) = log2( P(x, y) / (P(x) P(y)) ) - how much more often two
     words occur together than chance.  PPMI = max(PMI, 0) re-weights the Unit III count vectors.
  3. Visualising embeddings: 2-D PCA of word vectors and of alert vectors (coordinates sent to the
     frontend, which draws them with a Recharts scatter plot).
  4. Evaluating vector models: hand-picked similar / dissimilar word pairs (similar pairs should get
     a higher cosine) + cluster silhouette and purity against the attack-phase labels.
  5. Relation extraction (rule-based on NER entities + triples):
        (src_ip, ATTACKED, host), (user, LOGGED_INTO, host), (src_ip, SCANNED, port),
        (user, ESCALATED_TO, root), (alert type, MAPS_TO, mitre_id)
  6. Events & time: every alert becomes an event (time, actor, action, target, severity); timestamps
     are normalised to UTC and sorted -> timeline.
"""
import math
import re
import warnings
from collections import Counter, defaultdict

import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA, TruncatedSVD
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics import silhouette_score

from .unit1_preprocess_lm import normalize, tokenize

TIME_GAP_MINUTES = 30      # a pause longer than this inside a cluster starts a new incident
MAX_K = 15                 # largest number of clusters tried
SILHOUETTE_SAMPLE = 2000   # cap on points used for silhouette (it is O(n^2))
# KMeans warns when a k is larger than the number of distinct points; silhouette then rejects that k anyway
warnings.filterwarnings("ignore", message="Number of distinct clusters")


# ---------------------------------------------------------------- 1. TF-IDF + clustering
USER_RE = re.compile(r"for user \S+")
# Words every alert sentence contains because of our template carry no information -> stop words.
TEMPLATE_STOP = {"host", "reported", "targeting", "port", "level", "user", "requesting", "alert", "suricata", "et"}
STOP_WORDS = sorted(ENGLISH_STOP_WORDS | TEMPLATE_STOP)


def feature_text(sentence):
    """Text used for clustering: normalized sentence, no time-of-day, user names masked
    (otherwise every mail user would pull logins into a different cluster)."""
    return USER_RE.sub("for user <USER>", normalize(sentence).replace("at <TIME>, ", ""))


def build_tfidf(texts):
    # lowercase=False: normalize() already lower-cased the words and we want to keep <IP>, <URL> tags
    vec = TfidfVectorizer(token_pattern=r"<[A-Z]+>|[a-z][a-z0-9_\-.]+", sublinear_tf=True, min_df=1,
                          lowercase=False, stop_words=STOP_WORDS)
    X = vec.fit_transform(texts)
    return vec, X


def choose_k_and_cluster(X, weights, seed=42):
    """Try k = 2..MAX_K, keep the k with the best silhouette score."""
    n = X.shape[0]
    if n < 3:
        return np.zeros(n, dtype=int), 1, None, []
    scores = []
    best = (None, -1.0, None)
    for k in range(2, min(MAX_K, n - 1) + 1):
        km = KMeans(n_clusters=k, n_init=5, random_state=seed)
        labels = km.fit_predict(X, sample_weight=weights)
        if len(set(labels)) < 2:
            continue
        idx = np.arange(n) if n <= SILHOUETTE_SAMPLE else np.random.RandomState(seed).choice(n, SILHOUETTE_SAMPLE, replace=False)
        s = float(silhouette_score(X[idx], labels[idx], metric="cosine"))
        scores.append({"k": k, "silhouette": round(s, 4)})
        if s > best[1]:
            best = (labels, s, k)
    if best[0] is None:
        return np.zeros(n, dtype=int), 1, None, scores
    return best[0], best[2], round(best[1], 4), scores


def cluster_keywords(vec, X, labels, top=5):
    terms = np.array(vec.get_feature_names_out())
    out = {}
    for c in sorted(set(labels)):
        rows = X[labels == c]
        centroid = np.asarray(rows.mean(axis=0)).ravel()
        best = [t for t in terms[np.argsort(-centroid)] if not t.startswith("<")][:top]
        out[int(c)] = best
    return out


def cluster_alerts(df):
    """Cluster unique feature texts (weighted by how often they occur) -> cluster id per alert.
    Working on unique texts keeps KMeans fast even for tens of thousands of alerts."""
    feats = df["sentence"].map(feature_text)
    uniq = feats.value_counts()
    texts = list(uniq.index)
    vec, X = build_tfidf(texts)
    labels, k, sil, k_scores = choose_k_and_cluster(X, uniq.values.astype(float))
    label_of = dict(zip(texts, labels))
    return {
        "cluster": feats.map(label_of).astype(int).values,
        "k": k, "silhouette": sil, "k_scores": k_scores,
        "keywords": cluster_keywords(vec, X, labels),
        "vectorizer": vec, "X_unique": X, "unique_texts": texts, "unique_labels": labels,
        "unique_counts": uniq.values,
    }


def split_incidents(df, clusters):
    """Incident = consecutive alerts of the same cluster with no pause > TIME_GAP_MINUTES."""
    df = df.assign(_cluster=clusters).sort_values("timestamp")
    incident_of = {}
    next_id = 0
    for _, g in df.groupby("_cluster", sort=False):
        gaps = g["timestamp"].diff().dt.total_seconds().fillna(0) > TIME_GAP_MINUTES * 60
        segment = gaps.cumsum().values
        for s in np.unique(segment):
            for idx in g.index[segment == s]:
                incident_of[idx] = next_id
            next_id += 1
    return incident_of  # {row index -> incident number}


def top_tfidf_terms(text, vec, top=8):
    row = vec.transform([feature_text(text)]).toarray().ravel()
    terms = vec.get_feature_names_out()
    order = np.argsort(-row)[:top]
    return [{"term": terms[i], "weight": round(float(row[i]), 4)} for i in order if row[i] > 0]


# ---------------------------------------------------------------- 2. PMI / PPMI
def pmi_pairs(token_lists, min_count=3, top=20):
    """Sentence-level PMI: P(x) = fraction of sentences containing x, P(x,y) = containing both.
    Counted on UNIQUE sentences so one flooding alert type cannot dominate."""
    uniq = {tuple(sorted(set(t for t in toks if not t.startswith("<")))) for toks in token_lists}
    n = len(uniq)
    single, pair = Counter(), Counter()
    for words in uniq:
        single.update(words)
        for i in range(len(words)):
            for j in range(i + 1, len(words)):
                pair[(words[i], words[j])] += 1
    rows = []
    for (x, y), c in pair.items():
        if c < min_count:
            continue
        pmi = math.log2((c / n) / ((single[x] / n) * (single[y] / n)))
        rows.append({"w1": x, "w2": y, "pmi": round(pmi, 3), "count": c})
    rows.sort(key=lambda r: (-r["pmi"], -r["count"]))
    return rows[:top]


def ppmi_matrix(M):
    """PPMI re-weighting of a word-context count matrix."""
    total = M.sum()
    if total == 0:
        return M
    pw = M.sum(axis=1, keepdims=True) / total
    pc = M.sum(axis=0, keepdims=True) / total
    with np.errstate(divide="ignore", invalid="ignore"):
        pmi = np.log2((M / total) / (pw * pc))
    pmi[~np.isfinite(pmi)] = 0
    return np.maximum(pmi, 0)


# ---------------------------------------------------------------- 3. PCA for visualisation
def word_pca(vocab, M, n_words=60):
    words = [w for w in vocab if not w.startswith("<")][:n_words]
    if len(words) < 3:
        return []
    rows = M[[vocab.index(w) for w in words]]
    rows = rows / (np.linalg.norm(rows, axis=1, keepdims=True) + 1e-12)
    xy = PCA(n_components=2, random_state=0).fit_transform(rows)
    return [{"word": w, "x": round(float(a), 4), "y": round(float(b), 4)} for w, (a, b) in zip(words, xy)]


def alert_pca(clu, max_points=600):
    X = clu["X_unique"]
    n = X.shape[0]
    if n < 3:
        return []
    idx = np.argsort(-clu["unique_counts"])[:max_points]
    xy = TruncatedSVD(n_components=2, random_state=0).fit_transform(X[idx])
    return [{"x": round(float(a), 4), "y": round(float(b), 4), "cluster": int(clu["unique_labels"][i]),
             "text": clu["unique_texts"][i][:120], "count": int(clu["unique_counts"][i])}
            for (a, b), i in zip(xy, idx)]


# ---------------------------------------------------------------- 4. evaluating vectors
# Hand-picked pairs: (word1, word2, expected) with expected 1 = related, 0 = unrelated.
WORD_PAIRS = [
    ("opened", "closed", 1), ("handshake", "record", 1), ("tls", "ssl", 1), ("error", "code", 1),
    ("authentication", "success", 1), ("login", "session", 1), ("sshd", "insecure", 1), ("nmap", "scan", 1),
    ("forbidden", "directory", 1), ("smtp", "welcome", 1), ("dovecot", "authentication", 1),
    ("sudo", "root", 1), ("web", "server", 1), ("invalid", "handshake", 1), ("suricata", "alert", 1),
    ("dovecot", "nmap", 0), ("handshake", "forbidden", 0), ("sudo", "tls", 0), ("smtp", "sudo", 0),
    ("clamav", "nmap", 0), ("authentication", "handshake", 0), ("forbidden", "welcome", 0),
    ("session", "tls", 0), ("error", "dovecot", 0), ("root", "smtp", 0),
]


def evaluate_word_pairs(vocab, M, pairs=WORD_PAIRS):
    from .unit3_dependency_semantics import cosine
    rows = []
    for a, b, rel in pairs:
        c = cosine(vocab, M, a, b)
        if c is not None:
            rows.append({"w1": a, "w2": b, "related": rel, "cosine": round(c, 4)})
    sim = [r["cosine"] for r in rows if r["related"]]
    dis = [r["cosine"] for r in rows if not r["related"]]
    wins = sum(1 for s in sim for d in dis if s > d)
    return {
        "pairs": rows, "n_pairs_in_vocab": len(rows), "n_pairs_total": len(pairs),
        "mean_cosine_related": round(float(np.mean(sim)), 4) if sim else None,
        "mean_cosine_unrelated": round(float(np.mean(dis)), 4) if dis else None,
        # probability that a random related pair scores higher than a random unrelated pair
        "pairwise_accuracy": round(wins / (len(sim) * len(dis)), 4) if sim and dis else None,
    }


def purity(clusters, labels):
    """Purity = (1/N) * sum over clusters of the count of its most common true label."""
    by = defaultdict(Counter)
    for c, l in zip(clusters, labels):
        by[c][l] += 1
    n = len(labels)
    return round(sum(cnt.most_common(1)[0][1] for cnt in by.values()) / n, 4) if n else None


# ---------------------------------------------------------------- 5. relation extraction
LOGIN_WORDS = ("authentication success", "login session opened", "accepted", "logged in", "login:")
SCAN_WORDS = ("scan", "nmap", "400 error", "probe", "user-agent")


def extract_relations(alert, entities, triple):
    """Rules over the NER entities (IP/USER/HOST/PORT/MITRE) and the dependency triple."""
    desc = (alert.get("description") or "").lower()
    ips = [e["text"] for e in entities if e["label"] == "IP"]
    users = [e["text"] for e in entities if e["label"] == "USER"]
    actor = (triple or {}).get("actor") or (ips[0] if ips else None)
    host = alert.get("host")
    port = alert.get("dst_port")
    rels = []
    if actor and actor in ips and host and (alert["level"] >= 5 or alert["source"] == "suricata"):
        rels.append((actor, "ATTACKED", host))
    if actor and actor in ips and port and any(w in desc for w in SCAN_WORDS):
        rels.append((actor, "SCANNED", f"port {port}"))
    for u in users:
        if any(w in desc for w in LOGIN_WORDS):
            rels.append((u, "LOGGED_INTO", host))
        if "sudo to root" in desc or "changed uid" in desc:
            rels.append((u, "ESCALATED_TO", "root"))
    if alert.get("mitre_id"):
        for m in str(alert["mitre_id"]).split(","):
            rels.append((alert["description"][:80], "MAPS_TO", m))
    return rels


# ---------------------------------------------------------------- 6. events & time
def to_event(alert, triple, severity):
    return {
        "time": alert["timestamp"].isoformat(),
        "actor": (triple or {}).get("actor") or alert.get("src_ip") or alert.get("user"),
        "action": alert["description"],
        "target": (triple or {}).get("target") or alert.get("host"),
        "severity": severity,
    }


# ---------------------------------------------------------------- NLP Lab demo
def demo(text, vec=None):
    out = {"feature_text": feature_text(text), "tokens": tokenize(text)}
    if vec is not None:
        out["tfidf_top_terms"] = top_tfidf_terms(text, vec)
    else:
        v, _ = build_tfidf([feature_text(text)])
        out["tfidf_top_terms"] = top_tfidf_terms(text, v)
    return out


if __name__ == "__main__":
    sents = ["host mail reported 'Dovecot Authentication Success' for user a from 1.1.1.1",
             "host mail reported 'Dovecot Authentication Success' for user b from 1.1.1.2",
             "host web reported 'Web server 400 error code' from 2.2.2.2 targeting port 80",
             "host web reported 'Web server 400 error code' from 2.2.2.2 targeting port 443",
             "host web reported 'SURICATA TLS invalid handshake' from 3.3.3.3 targeting port 443"]
    vec, X = build_tfidf([feature_text(s) for s in sents])
    print(choose_k_and_cluster(X, np.ones(len(sents)))[1:3])
    print(pmi_pairs([tokenize(s) for s in sents], min_count=1)[:5])
