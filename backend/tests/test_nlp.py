"""Unit tests for the algorithms we implemented ourselves (run: .venv\\Scripts\\python -m pytest -q)."""
import math

from nlp import unit1_preprocess_lm as u1
from nlp import unit2_pos_ner_parse as u2
from nlp import unit3_dependency_semantics as u3


# ---------------------------------------------------------------- Unit I
def test_edit_distance_textbook_examples():
    assert u1.edit_distance("kitten", "sitting") == 3
    assert u1.edit_distance("intention", "execution") == 5      # Levenshtein, substitution cost 1
    assert u1.edit_distance("", "abc") == 3
    assert u1.edit_distance("same", "same") == 0
    assert u1.edit_distance_table("ab", "ab")[-1][-1] == 0


def test_merge_alert_types_groups_near_duplicates():
    type_of, types = u1.merge_alert_types(["Web server 400 error code"] * 3 + ["Web server 500 error code",
                                                                              "Dovecot Authentication Success"])
    assert type_of["Web server 500 error code"] == type_of["Web server 400 error code"]
    assert len(types) == 2 and types[0]["count"] == 4


def test_masking_and_tokens():
    toks = u1.tokenize("From 10.0.0.1 targeting port 22 at 12:04:31")
    assert "<IP>" in toks and "<PORT>" in toks and "<TIME>" in toks


def test_bigram_perplexity_and_smoothing():
    train = [["a", "b"], ["a", "b"], ["a", "c"]]
    mle = u1.BigramLM(smoothing=False).fit(train)
    # P(a|<s>) = 1, P(b|a) = 2/3, P(</s>|b) = 1  ->  PP = (2/3) ** (-1/3)
    assert math.isclose(mle.perplexity([["a", "b"]]), (2 / 3) ** (-1 / 3), rel_tol=1e-9)
    assert mle.perplexity([["b", "a"]]) == float("inf")               # unseen bigram, no smoothing
    lap = u1.BigramLM(smoothing=True).fit(train)
    assert math.isfinite(lap.perplexity([["b", "a"]]))                # add-one smoothing generalises
    # Laplace: P(b|a) = (2 + 1) / (3 + V)
    assert math.isclose(lap.prob("a", "b"), 3 / (3 + len(lap.vocab)))


# ---------------------------------------------------------------- Unit II
def test_viterbi_tiny_hmm():
    hmm = u2.HMMTagger().fit([[("the", "DET"), ("dog", "NOUN"), ("runs", "VERB")],
                             [("a", "DET"), ("cat", "NOUN"), ("sleeps", "VERB")],
                             [("the", "DET"), ("cat", "NOUN"), ("runs", "VERB")]])
    assert hmm.viterbi(["the", "dog", "sleeps"]) == ["DET", "NOUN", "VERB"]
    assert hmm.viterbi([]) == []


def test_cky_toy_grammar():
    res = u2.cky_parse("the attacker scanned the web server from 10.35.1.4")
    assert res["parsed"]
    assert res["bracketed"].startswith("(S (NP (Det the) (N attacker))")
    assert "S" in res["table"][0][-1]
    assert not u2.cky_parse("scanned the the attacker")["parsed"]


def test_security_ner():
    doc = u2.get_nlp()("At 03:57:25, host intranet-server reported 'sshd: authentication failed' for user andrea.moss "
                       "from 172.19.131.174 targeting port 22. Exploit for CVE-2021-44228 used T1190 via nmap.")
    ents = {(e["text"], e["label"]) for e in u2.extract_entities(doc)}
    for expected in [("172.19.131.174", "IP"), ("CVE-2021-44228", "CVE"), ("22", "PORT"), ("andrea.moss", "USER"),
                     ("intranet-server", "HOST"), ("T1190", "MITRE_TECHNIQUE"), ("nmap", "TOOL")]:
        assert expected in ents


# ---------------------------------------------------------------- Unit III
def test_triple_extraction():
    doc = u2.get_nlp()("At 14:39:14, host intranet-server reported 'Common web attack' from 172.24.249.224 "
                       "targeting port 80 (level 6).")
    t = u3.extract_triple(doc)
    assert (t["actor"], t["action_head"], t["target"]) == ("172.24.249.224", "attack", "intranet-server:80")


def test_wordnet_normalises_actions():
    assert u3.normalize_action("attempted") == u3.normalize_action("tried")
    assert u3.noun_to_verb("authentication") == "authenticate"
