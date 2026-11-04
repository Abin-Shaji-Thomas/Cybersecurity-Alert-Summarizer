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


def test_chu_liu_edmonds_breaks_cycle():
    d = u3.mst_demo()
    assert set(d["cycle"]) == {"attacker", "scanned"}                    # greedy heads form a cycle
    tree = {(a["head"], a["dep"]) for a in d["tree"]}
    assert tree == {("ROOT", "scanned"), ("scanned", "attacker"), ("scanned", "server"), ("server", "the")}
    assert d["total_score"] == 72


def test_hmm_masks_alert_tokens():
    assert u2.hmm_input("172.19.131.174") == "address"
    assert u2.hmm_input("intranet-server") == "server"
    assert u2.hmm_input("(") == "-LRB-"


def test_incident_aspects():
    import pandas as pd
    from nlp.unit5_summarize_qa import incident_aspects, srl_roles
    t = pd.to_datetime(["2022-01-29T13:00:00Z", "2022-01-29T13:01:00Z", "2022-01-29T13:02:00Z"])
    g = pd.DataFrame({"timestamp": t, "description": ["PAM: User login failed"] * 3})
    assert incident_aspects(g)["frequency"] == "repeated" and incident_aspects(g)["outcome"] == "attempted"
    g.loc[2, "description"] = "sshd: authentication success"
    assert incident_aspects(g)["outcome"] == "succeeded"
    assert incident_aspects(g.head(1))["frequency"] == "one-off"
    roles = srl_roles({"actor": "1.2.3.4", "action_head": None}, {"description": "Multiple IDS events", "timestamp": t[0]})
    assert roles["Action"].startswith("trigger")


def test_aspect_and_action_follow_the_attacker():
    import pandas as pd
    from nlp.unit5_summarize_qa import fill_template, incident_aspects
    t = pd.to_datetime(["2022-03-17T13:20:00Z", "2022-03-17T13:20:10Z", "2022-03-17T13:21:00Z"])
    g = pd.DataFrame({"timestamp": t, "level": [12, 12, 3],
                      "description": ["Suricata: Alert - ET EXPLOIT X (CVE-2021-3156)"] * 2 + ["sshd: authentication success"],
                      "src_ip": ["203.0.113.9", "203.0.113.9", "10.0.0.15"],      # the login is from an unrelated admin IP
                      "mitre_id": ["T1068", "T1068", None], "mitre_tactic": ["Privilege Escalation"] * 2 + [None],
                      "user": [None, None, "admin"], "host": ["webserver"] * 3, "dst_port": [80, 80, None],
                      "phase": ["normal"] * 3, "rarity_score": [5.0, 5.0, 2.0]})
    assert incident_aspects(g)["outcome"] == "attempted"
    g.loc[2, "description"] = "ClamAV database update"
    assert "antivirus" not in fill_template(g, [], "Critical", 12)["recommended_action"].lower()
