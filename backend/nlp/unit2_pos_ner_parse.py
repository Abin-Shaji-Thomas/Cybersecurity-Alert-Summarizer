"""UNIT II - POS Tagging & Syntactic Parsing.

Techniques in this file:
  1. POS tagging with spaCy (a trained neural tagger) - the "industrial" baseline.
  2. HMM POS tagger written by us: transition P(tag_i | tag_{i-1}) and emission P(word | tag)
     counted from the NLTK Penn Treebank sample, decoded with our own VITERBI algorithm.
     We compare its tags with spaCy's on alert sentences (both mapped to the universal tagset).
  3. Security NER: spaCy EntityRuler patterns for IP, PORT, CVE, MITRE_TECHNIQUE, HOST, USER,
     PROTOCOL and TOOL/MALWARE, on top of spaCy's built-in statistical entities (TIME, CARDINAL...).
  4. CFG + CKY: a tiny toy context-free grammar in Chomsky Normal Form for sentences like
     "the attacker scanned the server" and our own CKY parser that fills the parse table
     bottom-up and recovers the tree. This is a CONCEPT DEMO (the grammar only knows ~40 words);
     real alert parsing in this project is done by spaCy's dependency parser.
  5. Dependency grammar: head -> dependent arcs for a sentence (used again in Unit III).
"""
import math
import re
from collections import Counter, defaultdict
from functools import lru_cache

import nltk
import spacy
from spacy.lang.char_classes import ALPHA, ALPHA_LOWER, ALPHA_UPPER, CONCAT_QUOTES, LIST_ELLIPSES, LIST_ICONS
from spacy.language import Language
from spacy.tokens import Span
from spacy.util import compile_infix_regex

# ---------------------------------------------------------------- spaCy + security NER
PROTOCOLS = ["ssh", "sshd", "http", "https", "tls", "ssl", "smtp", "imap", "pop3", "dns", "ftp", "tcp",
             "udp", "icmp", "rdp", "smb", "ldap"]
TOOLS = ["nmap", "dirb", "wpscan", "hydra", "metasploit", "meterpreter", "netcat", "mimikatz", "sqlmap",
         "nikto", "dnsteal", "john", "hashcat", "cobalt strike", "webshell", "web shell", "reverse shell",
         "ransomware", "trojan", "backdoor", "botnet", "rootkit", "keylogger", "malware", "virus"]
DEFAULT_HOSTS = ["intranet-server", "mail", "webserver", "vpn", "inet-firewall", "inet-dns", "cloud-share",
                 "internal-share", "davey-mail", "morris-mail", "web-01", "db-01"]

IP_RE = r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$"
SEC_LABELS = {"IP", "PORT", "CVE", "MITRE_TECHNIQUE", "HOST", "USER", "PROTOCOL", "TOOL"}


def _patterns(hosts):
    pats = [
        {"label": "IP", "pattern": [{"TEXT": {"REGEX": IP_RE}}]},
        {"label": "PORT", "pattern": [{"LOWER": "port"}, {"TEXT": {"REGEX": r"^\d{1,5}$"}}]},
        {"label": "CVE", "pattern": [{"TEXT": {"REGEX": r"^(?i:cve)-\d{4}-\d{4,7}$"}}]},
        {"label": "MITRE_TECHNIQUE", "pattern": [{"TEXT": {"REGEX": r"^T\d{4}(?:\.\d{3})?$"}}]},
        {"label": "USER", "pattern": [{"LOWER": "user"}, {"TEXT": {"REGEX": r"^[A-Za-z_][\w.\-]{1,40}$"},
                                                           "LOWER": {"NOT_IN": ["authentication", "login", "for", "from"]}}]},
        {"label": "HOST", "pattern": [{"LOWER": "host"}, {"TEXT": {"REGEX": r"^[A-Za-z][\w.\-]{1,60}$"}}]},
    ]
    pats += [{"label": "HOST", "pattern": [{"LOWER": h.lower()}]} for h in hosts]
    pats += [{"label": "PROTOCOL", "pattern": [{"LOWER": p}]} for p in PROTOCOLS]
    pats += [{"label": "TOOL", "pattern": [{"LOWER": w} for w in t.split()]} for t in TOOLS]
    return pats


@Language.component("trim_keyword_ents")
def trim_keyword_ents(doc):
    """'user andrea.moss' / 'host mail' / 'port 22': keep only the value as the entity text,
    but remember the label. (The keyword is needed to *find* the entity, not part of it.)"""
    new_ents = []
    for ent in doc.ents:
        if ent.label_ in ("USER", "HOST", "PORT") and len(ent) > 1 and ent[0].lower_ in ("user", "host", "port"):
            new_ents.append(Span(doc, ent.start + 1, ent.end, label=ent.label_))
        else:
            new_ents.append(ent)
    doc.ents = new_ents
    return doc


@lru_cache(maxsize=1)
def get_nlp():
    """Load spaCy once. Hyphens inside words are NOT split, so 'intranet-server', 'CVE-2021-44228'
    and 'andrea.moss' stay single tokens (important for hostnames/usernames)."""
    nlp = spacy.load("en_core_web_sm")
    infixes = LIST_ELLIPSES + LIST_ICONS + [
        r"(?<=[{al}{q}])\.(?=[{au}{q}])".format(al=ALPHA_LOWER, au=ALPHA_UPPER, q=CONCAT_QUOTES),
        r"(?<=[{a}]),(?=[{a}])".format(a=ALPHA),
        r"(?<=[{a}0-9])[:<>=/](?=[{a}])".format(a=ALPHA),
    ]
    nlp.tokenizer.infix_finditer = compile_infix_regex(infixes).finditer
    ruler = nlp.add_pipe("entity_ruler", before="ner", config={"overwrite_ents": True})
    ruler.add_patterns(_patterns(DEFAULT_HOSTS))
    nlp.add_pipe("trim_keyword_ents", after="ner")
    return nlp


def add_host_patterns(hosts):
    """Let the pipeline teach the ruler the host names seen in an uploaded file (gazetteer)."""
    ruler = get_nlp().get_pipe("entity_ruler")
    known = {p["pattern"][0].get("LOWER") for p in ruler.patterns if p["label"] == "HOST" and len(p["pattern"]) == 1}
    new = [h for h in {str(h).lower() for h in hosts if h} if h not in known and " " not in h]
    if new:
        ruler.add_patterns([{"label": "HOST", "pattern": [{"LOWER": h}]} for h in new])


def extract_entities(doc, keep_cardinal=False):
    """Security entities + spaCy's built-in ones. CARDINAL is dropped by default: in our sentences it is
    almost always the Wazuh level number ("level 5"), which is not useful as an entity."""
    return [{"text": e.text, "label": e.label_, "start": e.start_char, "end": e.end_char}
            for e in doc.ents if keep_cardinal or e.label_ != "CARDINAL"]


def pos_tags(doc):
    return [{"text": t.text, "pos": t.pos_, "tag": t.tag_} for t in doc if not t.is_space]


def dependency_arcs(doc):
    """Dependency grammar: every word has exactly one HEAD; the arc label says the relation."""
    return [{"i": t.i, "text": t.text, "dep": t.dep_, "head_i": t.head.i, "head": t.head.text, "pos": t.pos_}
            for t in doc if not t.is_space]


# ---------------------------------------------------------------- HMM POS tagger + Viterbi
def _norm_word(w):
    """Collapse numbers/IPs to one symbol so the HMM can tag unseen numbers."""
    w = w.lower()
    if re.fullmatch(r"[\d.,:/\-]+", w) and any(c.isdigit() for c in w):
        return "<NUM>"
    return w


# spaCy universal POS -> NLTK universal tagset, so the two taggers can be compared
SPACY_TO_UNIVERSAL = {"PROPN": "NOUN", "AUX": "VERB", "CCONJ": "CONJ", "SCONJ": "ADP", "PART": "PRT",
                      "PUNCT": ".", "SYM": ".", "INTJ": "X", "SPACE": "X"}


class HMMTagger:
    """First-order HMM:  tags are hidden states, words are observations.

    P(tags, words) = prod_i P(t_i | t_{i-1}) * P(w_i | t_i)
    Transition and emission probabilities are relative-frequency counts with add-one smoothing.
    """

    def fit(self, tagged_sents):
        self.trans = defaultdict(Counter)
        self.emit = defaultdict(Counter)
        self.vocab = set()
        for sent in tagged_sents:
            prev = "<s>"
            for w, t in sent:
                w = _norm_word(w)
                self.trans[prev][t] += 1
                self.emit[t][w] += 1
                self.vocab.add(w)
                prev = t
            self.trans[prev]["</s>"] += 1
        self.tags = sorted(self.emit)
        self.V = len(self.vocab) + 1
        return self

    def log_trans(self, prev, t):
        row = self.trans[prev]
        return math.log((row[t] + 1) / (sum(row.values()) + len(self.tags) + 1))

    def log_emit(self, t, w):
        row = self.emit[t]
        return math.log((row[_norm_word(w)] + 1) / (sum(row.values()) + self.V))

    def viterbi(self, words):
        """Viterbi = dynamic programming over the tag lattice.

        v[i][t] = best log-probability of any tag sequence for words[:i+1] that ends in tag t
                = max_{t'} v[i-1][t'] + log P(t | t') + log P(w_i | t)
        back[i][t] remembers the best t' so we can walk back and read off the best path.
        """
        if not words:
            return []
        v = [{t: self.log_trans("<s>", t) + self.log_emit(t, words[0]) for t in self.tags}]
        back = [{}]
        for i in range(1, len(words)):
            v.append({})
            back.append({})
            for t in self.tags:
                best_prev = max(self.tags, key=lambda p: v[i - 1][p] + self.log_trans(p, t))
                v[i][t] = v[i - 1][best_prev] + self.log_trans(best_prev, t) + self.log_emit(t, words[i])
                back[i][t] = best_prev
        last = max(self.tags, key=lambda t: v[-1][t] + self.log_trans(t, "</s>"))
        path = [last]
        for i in range(len(words) - 1, 0, -1):
            path.append(back[i][path[-1]])
        return path[::-1]


@lru_cache(maxsize=1)
def get_hmm():
    """Train on the NLTK Penn Treebank sample (~3,900 sentences), universal tagset, traces removed."""
    from nltk.corpus import treebank
    from nltk.tag.mapping import map_tag
    sents = []
    for s in treebank.tagged_sents():
        sents.append([(w, map_tag("en-ptb", "universal", t)) for w, t in s if t != "-NONE-"])
    return HMMTagger().fit(sents)


def compare_taggers(doc):
    """Tag the same tokens with our HMM and spaCy; return both and the agreement rate."""
    words = [t.text for t in doc if not t.is_space]
    hmm_tags = get_hmm().viterbi(words)
    spacy_tags = [SPACY_TO_UNIVERSAL.get(t.pos_, t.pos_) for t in doc if not t.is_space]
    rows = [{"word": w, "hmm": h, "spacy": s, "agree": h == s} for w, h, s in zip(words, hmm_tags, spacy_tags)]
    agree = sum(r["agree"] for r in rows) / max(len(rows), 1)
    return rows, round(agree, 3)


# ---------------------------------------------------------------- toy CFG (CNF) + CKY
# Every rule is either  A -> B C  (two non-terminals)  or  A -> word  (Chomsky Normal Form).
CNF_GRAMMAR = {
    "binary": [
        ("S", "NP", "VP"),
        ("VP", "V", "NP"),
        ("VP", "VP", "PP"),
        ("NP", "Det", "N"),
        ("NP", "Det", "NOM"),
        ("NOM", "N", "N"),
        ("NP", "NP", "PP"),
        ("PP", "P", "NP"),
    ],
    "lexical": {
        "Det": ["the", "a", "an", "this", "that"],
        "N": ["attacker", "server", "host", "port", "ports", "user", "login", "password", "scan", "network",
              "firewall", "shell", "file", "website", "account", "web", "mail", "admin", "intruder", "alert"],
        "NP": ["attacker", "ssh", "root", "nmap", "it", "he", "they", "<ip>", "<num>"],
        "V": ["scanned", "attacked", "accessed", "targeted", "probed", "cracked", "uploaded", "used",
              "reported", "blocked", "compromised", "opened", "stole", "brute-forced"],
        "P": ["on", "from", "with", "to", "via", "against", "at", "of"],
    },
}
DEFAULT_CKY_SENTENCE = "the attacker scanned the web server from 10.35.1.4"


def _cky_word(w):
    w = w.lower()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", w):
        return "<ip>"
    if w.isdigit():
        return "<num>"
    return w


def cky_parse(sentence):
    """CKY: table[i][j] holds every non-terminal that can produce words[i:j].

    1. Diagonal: fill cells of length 1 from lexical rules (A -> word).
    2. For longer spans (length 2..n), try every split point k and every binary rule A -> B C
       with B in table[i][k] and C in table[k][j].
    3. The sentence is grammatical if 'S' is in table[0][n]. Back-pointers give the tree.
    """
    words = [w for w in re.findall(r"[\w.\-]+", sentence)]
    n = len(words)
    lex = defaultdict(set)
    for nt, ws in CNF_GRAMMAR["lexical"].items():
        for w in ws:
            lex[w].add(nt)
    table = [[{} for _ in range(n + 1)] for _ in range(n + 1)]  # table[i][j][A] = backpointer
    for i, w in enumerate(words):
        for nt in lex.get(_cky_word(w), ()):
            table[i][i + 1][nt] = w
    for length in range(2, n + 1):
        for i in range(0, n - length + 1):
            j = i + length
            for k in range(i + 1, j):
                for a, b, c in CNF_GRAMMAR["binary"]:
                    if b in table[i][k] and c in table[k][j] and a not in table[i][j]:
                        table[i][j][a] = (k, b, c)

    def build(i, j, sym):
        bp = table[i][j][sym]
        if isinstance(bp, str):
            return {"label": sym, "word": bp}
        k, b, c = bp
        return {"label": sym, "children": [build(i, k, b), build(k, j, c)]}

    def bracket(node):
        if "word" in node:
            return f"({node['label']} {node['word']})"
        return f"({node['label']} " + " ".join(bracket(c) for c in node["children"]) + ")"

    ok = n > 0 and "S" in table[0][n]
    tree = build(0, n, "S") if ok else None
    grid = [[sorted(table[i][j].keys()) if j > i else None for j in range(1, n + 1)] for i in range(n)]
    unknown = [w for w in words if not lex.get(_cky_word(w))]
    return {"words": words, "table": grid, "parsed": ok, "tree": tree,
            "bracketed": bracket(tree) if tree else None, "unknown_words": unknown}


def grammar_as_text():
    lines = [f"{a} -> {b} {c}" for a, b, c in CNF_GRAMMAR["binary"]]
    lines += [f"{nt} -> " + " | ".join(ws) for nt, ws in CNF_GRAMMAR["lexical"].items()]
    return lines


# ---------------------------------------------------------------- NLP Lab demo
def demo(text, cky_text=None):
    nlp = get_nlp()
    doc = nlp(text)
    hmm_rows, agree = compare_taggers(doc)
    cky = cky_parse(cky_text or text)
    used_default = False
    if not cky["parsed"] and not cky_text:
        cky = cky_parse(DEFAULT_CKY_SENTENCE)
        used_default = True
    return {
        "pos": pos_tags(doc),
        "hmm_vs_spacy": hmm_rows,
        "hmm_spacy_agreement": agree,
        "entities": extract_entities(doc),
        "dependencies": dependency_arcs(doc),
        "cky": cky,
        "cky_used_default_sentence": used_default,
        "grammar": grammar_as_text(),
    }


if __name__ == "__main__":
    s = ("At 03:57:25, host intranet-server reported 'sshd: authentication failed' for user andrea.moss "
         "from 172.19.131.174 targeting port 22 (level 5). Exploit for CVE-2021-44228 used T1190 via nmap.")
    d = demo(s)
    print("ENTITIES", [(e["text"], e["label"]) for e in d["entities"]])
    print("HMM vs spaCy agreement", d["hmm_spacy_agreement"])
    print(cky_parse(DEFAULT_CKY_SENTENCE)["bracketed"])
