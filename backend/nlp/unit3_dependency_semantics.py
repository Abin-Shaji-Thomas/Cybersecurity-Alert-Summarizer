"""UNIT III - Dependency Parsing & Semantic Representations.

Parsing background (explained, not re-implemented):
  * spaCy's parser is TRANSITION-BASED: it reads words left to right with a stack and a buffer and a
    neural network picks actions (SHIFT, LEFT-ARC, RIGHT-ARC) - fast, linear time, greedy.
  * GRAPH-BASED parsers instead score every possible head->dependent arc and pick the maximum
    spanning tree (Chu-Liu/Edmonds, implemented below as a toy demo) - slower but look at the whole
    sentence at once.
  * NEURAL CONSTITUENCY parsing (e.g. Kitaev & Klein) encodes the sentence with a neural network and
    scores labelled spans (phrases like NP/VP), then a CKY-style search builds the best phrase tree.
    We only show constituency parsing with the toy CKY in Unit II (documentation only for the neural one).

Techniques implemented here:
  1. Dependency parsing with spaCy, and HEAD-FINDING for noun phrases (the head of
     "web server 400 error code" is "code"; its compound modifiers give "error code").
  2. Triple extraction (actor, action, target) from the dependency tree.
  3. Parser evaluation: precision / recall of extracted triples against hand-labelled gold triples.
  4. Lexical semantics: WordNet synonyms + hypernyms to normalise action words (attempted -> try).
  5. Vector semantics: word vectors = rows of a word-context co-occurrence matrix built from our own
     alert corpus; cosine similarity gives nearest neighbours.
  6. Graph-based parsing: our own Chu-Liu/Edmonds maximum spanning tree on one toy sentence with
     hand-picked arc scores (concept demo, compared with spaCy's transition-based parse).
"""
import re
from collections import Counter
from functools import lru_cache

import numpy as np

from .unit1_preprocess_lm import tokenize
from .unit2_pos_ner_parse import get_nlp

# ---------------------------------------------------------------- 1. head finding
NOUNY = {"NOUN", "PROPN", "NUM", "X"}


def np_head(token):
    """Head-finding rule for a noun phrase: follow 'compound' arcs to the rightmost noun.
    In spaCy the head of an NP is already the token the modifiers point to, so the head is
    simply the token itself; we then collect its compound/amod/nmod children for a readable phrase."""
    mods = [c for c in token.children if c.dep_ in ("compound", "amod", "nmod") and c.i < token.i]
    words = [m for m in mods if not m.is_punct] + [token]
    return token, " ".join(w.text for w in sorted(words, key=lambda w: w.i))


def noun_phrase_heads(doc):
    """Every noun chunk with its head word (shown on the NLP Lab page)."""
    return [{"phrase": nc.text, "head": nc.root.text, "head_dep": nc.root.dep_} for nc in doc.noun_chunks]


# ---------------------------------------------------------------- 2. triple extraction
def _quote_span(doc):
    q = [i for i, t in enumerate(doc) if t.text in ("'", "\"")]
    return (q[0], q[-1]) if len(q) >= 2 else (-1, -1)


def _find_pobj(doc, prep_word):
    """Object of a preposition ('from X'), ignoring prepositions INSIDE the quoted alert text
    (e.g. "... errors from same source ip" is part of the description, not the actor)."""
    qa, qb = _quote_span(doc)
    for t in doc:
        if t.dep_ in ("prep", "agent") and t.lower_ == prep_word and not (qa < t.i < qb):
            objs = [c for c in t.children if c.dep_ == "pobj"]
            # accept the parse only if the object is an entity (IP / USER / HOST); on long sentences the
            # small parser sometimes attaches "from" to a later noun such as "level" or "port"
            if objs and objs[0].ent_type_:
                return objs[0]
    # parser attached the object elsewhere: take the word right after the preposition
    for t in doc:
        if t.lower_ == prep_word and not (qa < t.i < qb) and t.i + 1 < len(doc):
            nxt = doc[t.i + 1]
            if nxt.lower_ == "user" and t.i + 2 < len(doc):
                return doc[t.i + 2]
            return nxt
    return None


# Nouns that are NOT actions, so they are skipped when looking for the action word:
#  * the OUTCOME or the report itself ("authentication success", "400 error code", "IDS event");
#  * the THING or PLACE involved ("web server", "host", "port"): WordNet would turn "server" into "serve".
OUTCOME_NOUNS = {"success", "failure", "error", "code", "event", "alert", "message", "len", "header",
                 "record", "traffic", "reply", "id", "ip", "source", "index", "file", "directory",
                 "server", "web", "host", "port", "user", "database", "domain", "tld", "website"}


@lru_cache(maxsize=4096)
def noun_to_verb(noun):
    """Nominalisation -> verb with WordNet derivational morphology (Unit III lexical semantics):
    attack -> attack, authentication -> authenticate, update -> update, access -> access.
    Returns None when WordNet knows no related verb."""
    from nltk.corpus import wordnet as wn
    verbs = Counter()
    for lemma in wn.lemmas(noun, pos="n"):
        for d in lemma.derivationally_related_forms():
            if d.synset().pos() == "v":
                verbs[d.name().lower()] += 1
    if not verbs:
        return None
    if noun in verbs:              # the same word is also a verb (attack, update, attempt)
        return noun
    return verbs.most_common(1)[0][0]


def _action_from_quote(doc):
    """The quoted alert description says what happened. Returns (action verb lemma, action phrase).
      1. a real verb inside the quote (executed, changed, closed) -> its lemma;
      2. otherwise the head noun phrase, and its head noun is turned into a verb with WordNet
         (skipping outcome nouns like 'success' / 'code', whose modifiers carry the action)."""
    qa, qb = _quote_span(doc)
    span = doc[qa + 1:qb] if qa >= 0 else doc
    verbs = [t for t in span if t.pos_ == "VERB" and t.dep_ not in ("amod",)]
    if verbs:
        v = verbs[-1]
        obj = [c for c in v.children if c.dep_ in ("dobj", "xcomp")]
        return v.lemma_.lower(), (v.lemma_ + (" " + obj[0].text if obj else "")).lower()
    nouns = [t for t in span if t.pos_ in NOUNY and t.dep_ in ("dobj", "appos", "ROOT", "nsubj", "pobj", "conj")]
    if not nouns:
        nouns = [t for t in span if t.pos_ in NOUNY]
    if not nouns:
        return None, span.text.lower()
    head, phrase = np_head(nouns[-1])
    # candidates: the head noun first, then its modifiers right-to-left ("authentication success")
    mods = sorted((t for t in span if t.i < head.i and t.pos_ in NOUNY), key=lambda t: -t.i)
    for cand in [head] + mods:
        word = cand.lemma_.lower()
        if word in OUTCOME_NOUNS or not word.isalpha():
            continue
        verb = noun_to_verb(word)
        if verb:
            return verb, phrase.lower()
    return None, phrase.lower()


def extract_triple(doc):
    """(actor, action, target) for one alert sentence.

    actor  = object of the preposition 'from' (the source IP); else the user ('for user X')
    action = verb of the quoted alert description (a verb inside it, else its head noun turned
             into a verb with WordNet); 'action' keeps the readable phrase, 'action_head' the verb
    target = the reporting host (nsubj of 'reported') plus the targeted port if any
    """
    actor_tok = _find_pobj(doc, "from")
    user_tok = _find_pobj(doc, "for")
    actor = actor_tok.text if actor_tok is not None else (user_tok.text if user_tok is not None else None)

    host = None
    for t in doc:
        if t.dep_ == "nsubj" and t.head.lemma_ == "report":
            # "host 172.27.180.4 reported": the subject may be the keyword "host" itself -> take its value
            host = doc[t.i + 1].text if t.lower_ == "host" and t.i + 1 < len(doc) else t.text
            break
    if host is None:
        ents = [e.text for e in doc.ents if e.label_ == "HOST"]
        host = ents[0] if ents else None
    port = None
    for e in doc.ents:
        if e.label_ == "PORT":
            port = e.text
    target = host + (f":{port}" if port and host else "") if host else (f"port {port}" if port else None)

    action_head, action_phrase = _action_from_quote(doc)
    return {"actor": actor, "action": action_phrase, "action_head": action_head, "target": target}


def extract_triples(texts, batch_size=256):
    nlp = get_nlp()
    return [extract_triple(d) for d in nlp.pipe(texts, batch_size=batch_size)]


# ---------------------------------------------------------------- 3. parser / triple evaluation
def evaluate_triples(pred, gold):
    """A predicted triple is correct when actor, target and action head all match the gold triple
    (case-insensitive; the action is compared as a verb lemma, so 'attempted' == 'attempt').
    Precision = correct / predicted-non-empty, Recall = correct / gold."""
    def key(t):
        return (str(t.get("actor") or "").lower(), str(t.get("action_head") or "").lower(),
                str(t.get("target") or "").lower())
    correct = sum(1 for p, g in zip(pred, gold) if key(p) == key(g))
    n_pred = sum(1 for p in pred if p.get("actor") or p.get("target"))
    field_acc = {f: round(sum(str(p.get(f) or "").lower() == str(g.get(f) or "").lower()
                              for p, g in zip(pred, gold)) / max(len(gold), 1), 3)
                 for f in ("actor", "action_head", "target")}
    p = correct / n_pred if n_pred else 0.0
    r = correct / len(gold) if gold else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3),
            "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0,
            "n_gold": len(gold), "n_correct": correct, "field_accuracy": field_acc}


# ---------------------------------------------------------------- 4. lexical semantics (WordNet)
@lru_cache(maxsize=2048)
def wordnet_info(word, pos="v"):
    """Synonyms (lemmas of the first synset) and hypernyms (more general concepts)."""
    from nltk.corpus import wordnet as wn
    syns = wn.synsets(word, pos=pos) or wn.synsets(word)
    if not syns:
        return {"word": word, "canonical": word, "synonyms": [], "hypernyms": [], "definition": None}
    s = syns[0]
    lemmas = [l.name().replace("_", " ") for l in s.lemmas()]
    return {"word": word, "synset": s.name(), "canonical": lemmas[0], "synonyms": lemmas[:6],
            "hypernyms": [h.name().split(".")[0].replace("_", " ") for h in s.hypernyms()][:4],
            "definition": s.definition()}


def normalize_action(verb):
    """attempted / tried -> 'try'  (same WordNet synset => same canonical action)."""
    return wordnet_info(verb.lower())["canonical"] if verb else verb


# ---------------------------------------------------------------- 5. vector semantics
def cooccurrence_vectors(token_lists, window=2, max_vocab=600, min_count=2):
    """Word vectors from a word x context-word count matrix.

    For each word, count which words occur within +/- `window` positions. Row i of the matrix is
    the vector of word i ("you shall know a word by the company it keeps").
    Vocabulary capped at the `max_vocab` most frequent words to keep the matrix small.
    """
    freq = Counter(w for toks in token_lists for w in toks)
    vocab = [w for w, c in freq.most_common(max_vocab) if c >= min_count]
    index = {w: i for i, w in enumerate(vocab)}
    M = np.zeros((len(vocab), len(vocab)), dtype=np.float64)
    for toks in token_lists:
        ids = [index.get(w) for w in toks]
        for i, wi in enumerate(ids):
            if wi is None:
                continue
            for j in range(max(0, i - window), min(len(ids), i + window + 1)):
                if j != i and ids[j] is not None:
                    M[wi, ids[j]] += 1
    return vocab, M


def cosine_neighbours(word, vocab, M, k=5):
    if word not in vocab:
        return []
    i = vocab.index(word)
    norms = np.linalg.norm(M, axis=1) + 1e-12
    sims = (M @ M[i]) / (norms * norms[i])
    order = [j for j in np.argsort(-sims) if j != i][:k]
    return [{"word": vocab[j], "cosine": round(float(sims[j]), 3)} for j in order]


def cosine(vocab, M, a, b):
    if a not in vocab or b not in vocab:
        return None
    va, vb = M[vocab.index(a)], M[vocab.index(b)]
    return float(va @ vb / ((np.linalg.norm(va) * np.linalg.norm(vb)) + 1e-12))


QUERY_WORDS = ["ssh", "sshd", "scan", "login", "failed", "authentication", "error", "web", "suricata",
               "tls", "dovecot", "sudo", "user", "success", "attack"]


# ---------------------------------------------------------------- 6. graph-based parsing (concept demo)
# A graph-based parser scores EVERY possible head -> dependent arc and returns the maximum spanning tree.
# Real parsers learn the scores with a neural network; here they are hand-picked for one toy sentence.
MST_WORDS = ["ROOT", "attacker", "scanned", "the", "server"]
MST_SCORES = {  # (head, dependent): score
    (0, 2): 25, (0, 1): 5, (0, 4): 4, (0, 3): 1,
    (2, 1): 20, (1, 2): 30,            # attacker <-> scanned: the greedy choice makes a CYCLE
    (2, 4): 15, (4, 3): 12, (2, 3): 3, (1, 4): 3, (3, 4): 2, (4, 2): 2,
    (1, 3): 2, (3, 1): 1, (4, 1): 4, (3, 2): 1,
}


def _find_cycle(head_of):
    for start in head_of:
        seen, v = [], start
        while v in head_of and v not in seen:
            seen.append(v)
            v = head_of[v]
        if v in seen:
            return seen[seen.index(v):]
    return None


def chu_liu_edmonds(nodes, scores, root=0, steps=None):
    """Maximum spanning tree (Chu-Liu/Edmonds).
    1. every word picks its best-scoring head;
    2. no cycle -> that is the tree;
    3. a cycle -> contract it into one node, re-score arcs entering it
       (score - score of the cycle arc it would replace), solve recursively, then expand."""
    steps = [] if steps is None else steps
    best = {d: max((h for h in nodes if (h, d) in scores), key=lambda h: scores[(h, d)])
            for d in nodes if d != root}
    cycle = _find_cycle(best)
    steps.append({"best_heads": {d: h for d, h in best.items()}, "cycle": cycle})
    if not cycle:
        return best, steps
    c = max(n for n in nodes if isinstance(n, int)) + 1 + len(steps) * 100   # id of the contracted node
    new_scores, origin = {}, {}
    for (h, d), s in scores.items():
        if h in cycle and d in cycle:
            continue
        if d in cycle:                   # arc entering the cycle: replaces the cycle arc into d
            key, val = (h, c), s - scores[(best[d], d)]
        elif h in cycle:                 # arc leaving the cycle
            key, val = (c, d), s
        else:
            key, val = (h, d), s
        if key not in new_scores or val > new_scores[key]:
            new_scores[key], origin[key] = val, (h, d)
    sub, steps = chu_liu_edmonds([n for n in nodes if n not in cycle] + [c], new_scores, root, steps)
    tree = {}
    for d, h in sub.items():
        oh, od = origin[(h, d)]
        tree[od] = oh
    for v in cycle:                      # keep the remaining cycle arcs
        tree.setdefault(v, best[v])
    return tree, steps


def mst_demo():
    """Graph-based parse of the toy sentence, plus spaCy's transition-based parse of the same words."""
    tree, steps = chu_liu_edmonds(list(range(len(MST_WORDS))), MST_SCORES)
    w = MST_WORDS
    doc = get_nlp()(" ".join(w[1:]))
    return {
        "words": w,
        "scores": [{"head": w[h], "dep": w[d], "score": s} for (h, d), s in sorted(MST_SCORES.items(), key=lambda x: -x[1])],
        "greedy": [{"head": w[h], "dep": w[d]} for d, h in steps[0]["best_heads"].items()],
        "cycle": [w[v] for v in (steps[0]["cycle"] or [])],
        "tree": [{"head": w[h], "dep": w[d], "score": MST_SCORES[(h, d)]} for d, h in sorted(tree.items())],
        "total_score": sum(MST_SCORES[(h, d)] for d, h in tree.items()),
        "spacy": [{"head": "ROOT" if t.dep_ == "ROOT" else t.head.text, "dep": t.text, "label": t.dep_} for t in doc],
    }


# ---------------------------------------------------------------- NLP Lab demo
def demo(text, vocab=None, M=None):
    doc = get_nlp()(text)
    triple = extract_triple(doc)
    verbs = sorted({t.lemma_.lower() for t in doc if t.pos_ == "VERB"})
    out = {
        "noun_phrase_heads": noun_phrase_heads(doc),
        "triple": triple,
        "wordnet": [wordnet_info(v) for v in (verbs + ["attempt", "try"])[:6]],
        "mst": mst_demo(),
    }
    if vocab is not None:
        words = [w for w in dict.fromkeys(tokenize(text)) if w in vocab and not w.startswith("<")][:4]
        out["neighbours"] = {w: cosine_neighbours(w, vocab, M) for w in words}
    return out


if __name__ == "__main__":
    s = "At 03:57:25, host intranet-server reported 'Web server 400 error code' from 172.19.131.174 targeting port 80 (level 5)."
    print(demo(s)["triple"])
    print(wordnet_info("attempted"), wordnet_info("tried")["canonical"])
    toks = [tokenize(x) for x in [s, s.replace("400", "500"), "host mail reported ssh login failed from <IP>"] * 3]
    v, M = cooccurrence_vectors(toks)
    print(cosine_neighbours("server", v, M))
