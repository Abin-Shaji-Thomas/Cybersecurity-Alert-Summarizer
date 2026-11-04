"""UNIT I - Introduction to NLP & Language Modeling.

Techniques in this file:
  1. Text processing   - lowercase, clean and MASK security indicators with regular expressions
                         (IP -> <IP>, port -> <PORT>, hash -> <HASH>, URL -> <URL>, number -> <NUM>),
                         then tokenize. Masking makes "from 10.0.0.1" and "from 10.0.0.2" the same
                         pattern, so the models learn the *language* of alerts, not specific addresses.
  2. Sentence segmentation - NLTK sent_tokenize splits multi-sentence text (pasted logs, summaries).
  3. Minimum edit distance - our own dynamic-programming Levenshtein distance. Used to merge
                         near-duplicate alert descriptions into "alert types" with counts.
  4. N-gram language model - our own bigram model with Laplace (add-one) smoothing. We measure
                         perplexity on a held-out split (generalisation) with and without smoothing,
                         and use each alert's perplexity as a RARITY SCORE: unusual alerts surprise the
                         model (high perplexity) and get higher priority in the summaries.
"""
import math
import random
import re
from collections import Counter

import nltk

# ---------------------------------------------------------------- 1. text processing
# Order matters: URLs before IPs (URLs can contain IPs), IP:port before bare IPs, hashes before numbers.
MASKS = [
    ("<URL>", re.compile(r"(?:https?://\S+|(?<![\w/])/[\w\-./%?=&]*)")),
    ("<IP> <PORT>", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")),
    ("<IP>", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("<HASH>", re.compile(r"\b[a-fA-F0-9]{32,64}\b")),
    ("port <PORT>", re.compile(r"\bport \d{1,5}\b", re.I)),
    ("<TIME>", re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b")),
    ("<NUM>", re.compile(r"\b\d+\b")),
]
TOKEN_RE = re.compile(r"<[A-Z]+>|[a-z]+(?:[-_'][a-z]+)*")


def mask_text(text):
    """Replace indicators (IPs, ports, URLs, hashes, numbers) with placeholder tags."""
    out = text
    for tag, pattern in MASKS:
        out = pattern.sub(tag, out)
    return out


def normalize(text):
    """Lowercase + mask + collapse spaces. Tags stay upper-case so they are easy to see."""
    masked = mask_text(text)
    lowered = re.sub(r"(<[A-Z]+>)|([^<]+)", lambda m: m.group(1) or m.group(2).lower(), masked)
    return re.sub(r"\s+", " ", lowered).strip()


def tokenize(text):
    """Normalize then split into word tokens and <TAG> tokens (punctuation dropped)."""
    return TOKEN_RE.findall(normalize(text))


# ---------------------------------------------------------------- 2. sentence segmentation
def split_sentences(text):
    """NLTK Punkt sentence segmentation (handles abbreviations like 'e.g.' and decimals)."""
    return nltk.sent_tokenize(text)


# ---------------------------------------------------------------- 3. minimum edit distance
def edit_distance(a, b):
    """Levenshtein distance by dynamic programming (insert = delete = substitute = 1).

    D[i][j] = minimum edits to turn a[:i] into b[:j]
            = min(D[i-1][j] + 1,           # delete a[i-1]
                  D[i][j-1] + 1,           # insert b[j-1]
                  D[i-1][j-1] + (a[i-1] != b[j-1]))  # substitute (free if equal)
    We keep only two rows of the table to save memory.
    """
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def edit_distance_table(a, b):
    """Full DP table (for the NLP Lab page, so the student can show the grid)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
    return d


def merge_alert_types(descriptions, threshold=0.2):
    """Group near-duplicate descriptions into alert types.

    Two normalized descriptions belong to the same type when
    edit_distance / max(len) <= threshold (e.g. "web server 400 error code" vs
    "web server 500 error code" differ by 1 character).  Greedy: each description joins the
    first existing type whose representative is close enough, otherwise it starts a new type.
    We only compare UNIQUE normalized strings, so this stays fast even for 40k alerts.
    Returns (type_of: {description -> type label}, types: [{label, count, members}]).
    """
    counts = Counter(descriptions)
    norm_counts = Counter()
    norm_of = {}
    for desc, c in counts.items():
        n = normalize(desc)
        norm_of[desc] = n
        norm_counts[n] += c

    reps = []  # list of [representative, total_count, members]
    rep_of_norm = {}
    for n, c in norm_counts.most_common():  # most frequent first -> becomes the representative
        for rep in reps:
            if edit_distance(n, rep[0]) / max(len(n), len(rep[0]), 1) <= threshold:
                rep[1] += c
                rep[2].append(n)
                rep_of_norm[n] = rep[0]
                break
        else:
            reps.append([n, c, [n]])
            rep_of_norm[n] = n

    type_of = {d: rep_of_norm[norm_of[d]] for d in counts}
    types = [{"label": r[0], "count": r[1], "members": r[2]} for r in sorted(reps, key=lambda r: -r[1])]
    return type_of, types


# ---------------------------------------------------------------- 4. bigram language model
class BigramLM:
    """Bigram language model P(w_i | w_{i-1}) with optional Laplace (add-one) smoothing.

    Unsmoothed (MLE):   P(w | v) = C(v, w) / C(v)
    Laplace smoothing:  P(w | v) = (C(v, w) + 1) / (C(v) + V)      V = vocabulary size
    Without smoothing any unseen bigram gets probability 0 -> perplexity becomes infinite on new
    text. Add-one smoothing "steals" a little probability mass from seen bigrams for unseen ones,
    which is what lets the model GENERALISE to the held-out split.
    """

    def __init__(self, smoothing=True):
        self.smoothing = smoothing
        self.unigrams = Counter()
        self.bigrams = Counter()
        self.vocab = set()

    def fit(self, token_lists):
        for toks in token_lists:
            seq = ["<s>"] + toks + ["</s>"]
            self.vocab.update(seq)
            self.unigrams.update(seq[:-1])
            self.bigrams.update(zip(seq[:-1], seq[1:]))
        self.vocab.add("<UNK>")
        return self

    def prob(self, prev, word):
        if word not in self.vocab:
            word = "<UNK>"
        if prev not in self.vocab:
            prev = "<UNK>"
        c_bigram = self.bigrams[(prev, word)]
        c_prev = self.unigrams[prev]
        if self.smoothing:
            return (c_bigram + 1) / (c_prev + len(self.vocab))
        return c_bigram / c_prev if c_prev else 0.0

    def sentence_logprob(self, toks):
        seq = ["<s>"] + toks + ["</s>"]
        total = 0.0
        for v, w in zip(seq[:-1], seq[1:]):
            p = self.prob(v, w)
            if p == 0:
                return float("-inf"), len(seq) - 1
            total += math.log(p)
        return total, len(seq) - 1

    def perplexity(self, token_lists):
        """PP = exp(-(1/N) * sum log P(w_i | w_{i-1})) over all N predicted tokens."""
        log_sum, n = 0.0, 0
        for toks in token_lists:
            lp, k = self.sentence_logprob(toks)
            if lp == float("-inf"):
                return float("inf")
            log_sum += lp
            n += k
        return math.exp(-log_sum / max(n, 1))


def sentence_perplexity(lm, toks):
    lp, n = lm.sentence_logprob(toks)
    return float("inf") if lp == float("-inf") else math.exp(-lp / max(n, 1))


def train_and_evaluate_lm(sentences, test_fraction=0.2, seed=42):
    """Train on 80 % of the alert sentences, report perplexity on the held-out 20 %.

    We split on UNIQUE masked sentences so the test set really contains unseen patterns
    (otherwise the held-out set would be full of exact copies of training sentences).
    Returns (smoothed_model_trained_on_all, stats dict).
    """
    token_lists = [tokenize(s) for s in sentences]
    unique = sorted({tuple(t) for t in token_lists})
    rng = random.Random(seed)
    rng.shuffle(unique)
    n_test = max(1, int(len(unique) * test_fraction)) if len(unique) > 1 else 0
    test = [list(t) for t in unique[:n_test]]
    train = [list(t) for t in unique[n_test:]] or test

    smoothed = BigramLM(smoothing=True).fit(train)
    unsmoothed = BigramLM(smoothing=False).fit(train)
    stats = {
        "n_train_sentences": len(train),
        "n_test_sentences": len(test),
        "vocab_size": len(smoothed.vocab),
        "perplexity_train_smoothed": round(smoothed.perplexity(train), 3),
        "perplexity_train_unsmoothed": round(unsmoothed.perplexity(train), 3),
        "perplexity_test_smoothed": round(smoothed.perplexity(test), 3) if test else None,
        "perplexity_test_unsmoothed": unsmoothed.perplexity(test) if test else None,
    }
    # how many test sentences contain at least one unseen bigram (=> P = 0 without smoothing)
    zero = sum(1 for t in test if unsmoothed.sentence_logprob(t)[0] == float("-inf"))
    stats["test_sentences_with_zero_prob_unsmoothed"] = zero
    if stats["perplexity_test_unsmoothed"] == float("inf"):
        stats["perplexity_test_unsmoothed"] = "infinity"
    else:
        stats["perplexity_test_unsmoothed"] = round(stats["perplexity_test_unsmoothed"], 3)

    full_model = BigramLM(smoothing=True).fit(token_lists)  # final model on everything for rarity
    return full_model, stats, token_lists


def rarity_scores(lm, token_lists):
    """Per-alert perplexity under the smoothed LM = how surprising the alert text is."""
    return [round(sentence_perplexity(lm, t), 3) for t in token_lists]


# ---------------------------------------------------------------- NLP Lab demo
def demo(text, lm=None, compare_with="web server 400 error code"):
    toks = tokenize(text)
    sents = split_sentences(text)
    norm = normalize(text)
    short_a = norm[:30]
    short_b = compare_with[:30]
    out = {
        "original": text,
        "masked": mask_text(text),
        "normalized": norm,
        "tokens": toks,
        "sentences": sents,
        "edit_distance": {
            "a": short_a, "b": short_b,
            "distance": edit_distance(norm, compare_with),
            "table_a": "dosvc", "table_b": "dovecot",  # small fixed example for the DP grid
            "table": edit_distance_table("dosvc", "dovecot"),
        },
    }
    if lm is not None:
        seq = ["<s>"] + toks + ["</s>"]
        out["bigrams"] = [
            {"prev": v, "word": w, "prob": round(lm.prob(v, w), 5), "count": lm.bigrams[(v, w)]}
            for v, w in zip(seq[:-1], seq[1:])
        ]
        out["perplexity"] = round(sentence_perplexity(lm, toks), 3)
    return out


if __name__ == "__main__":
    s = "At 03:57:25, host intranet-server reported 'Web server 400 error code' from 172.19.131.174 targeting port 80 (level 5)."
    print(normalize(s))
    print(tokenize(s))
    print("edit distance kitten/sitting =", edit_distance("kitten", "sitting"))
    lm, stats, _ = train_and_evaluate_lm([s, s.replace("400", "500"), "At 01:00:00, host mail reported 'Dovecot Authentication Success' (level 3)."] * 3)
    print(stats)
    print(demo(s, lm)["perplexity"])
