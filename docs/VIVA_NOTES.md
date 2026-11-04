# Viva notes

Short explanations of every part of the project, each followed by three likely questions with short answers.
Numbers quoted here come from `docs/RESULTS.md` (re-run `python -m nlp.evaluate` if you change the code).

---

## 0. Loader and alert-to-sentence — `backend/nlp/load_data.py`

Reads a Wazuh alert file (JSON array or one JSON object per line) and flattens each nested alert into one row:
timestamp, source, description, level, src/dst IP, port, host, user, MITRE id/tactic, URL. The field paths were
found by inspecting the real AIT-ADS files (docs/DATASET.md). Duplicates are removed first: Dovecot events are logged 3 times
and Suricata events twice. Each alert is then rendered as one English sentence ("At 03:57:25, host intranet-server reported
'Web server 400 error code' from 172.19.131.174 targeting port 80 (level 5)."). These sentences are the corpus every NLP unit works on.

* **Why turn alerts into sentences?** Raw descriptions like "IDS event." have no subject, object or time, so parsers and
  language models have nothing to work with. A sentence puts who / what / where / when into normal grammar.
* **How do you deduplicate?** Alerts with the same second, description, source, destination, port, host, user and URL are kept once.
* **Where does the host name come from when it is missing?** From an agent-IP → hostname map learnt from the alerts that do carry `predecoder.hostname`.

## 1. Unit I — `unit1_preprocess_lm.py`

Text processing masks indicators with regular expressions (IP → `<IP>`, port → `<PORT>`, URL, hash, numbers) and tokenises.
NLTK Punkt splits multi-sentence text. Our own dynamic-programming Levenshtein distance merges near-duplicate
descriptions into alert types (e.g. "web server 400 error code" and "web server 500 error code"). Our own bigram language
model is trained on 80 % of the unique masked sentences. Its perplexity is measured on the other 20 %, with and without Laplace
smoothing. The perplexity of each alert is its *rarity score*: unusual alerts come first in summaries.

* **Why does unsmoothed perplexity become infinite?** A held-out sentence with a bigram never seen in training gets probability 0, and log 0 = −∞.
  9 of 31 held-out russellmitchell sentences contain such a bigram.
* **What does add-one smoothing do?** P(w|v) = (C(v,w)+1)/(C(v)+V): every bigram gets a small non-zero probability, taken from the seen ones.
* **What is the edit distance recurrence?** D[i][j] = min(D[i−1][j]+1, D[i][j−1]+1, D[i−1][j−1]+cost), where cost is 0 if the characters are equal and 1 otherwise. kitten→sitting = 3.

## 2. Unit II — `unit2_pos_ner_parse.py`

spaCy gives POS tags, the dependency parse and statistical entities. Our HMM tagger counts tag→tag transitions and tag→word
emissions on the NLTK Penn Treebank sample. Our own Viterbi algorithm finds the best tag sequence. Security NER adds EntityRuler
patterns for IP, PORT, CVE, MITRE technique, HOST, USER, PROTOCOL and TOOL, plus a gazetteer of host names learnt from the
uploaded file. A toy CNF grammar and our own CKY parser show constituency parsing for "the attacker scanned the web server
from 10.35.1.4".

* **What does Viterbi store?** v[i][t] = best log-probability of tagging words 0..i ending in tag t, plus a back-pointer to the previous tag. Cost O(n·T²).
* **Why does the HMM agree with spaCy only 0.678 of the time?** It was trained on Wall Street Journal text and has never seen IPs or
  host names (domain shift). We mask them first (IP → "address", intranet-server → "server", ( → -LRB-), which raised
  agreement from 0.558 to 0.678. Words like "level" and "targeting" in our template are still tagged differently.
* **Why must the grammar be in Chomsky Normal Form for CKY?** CKY combines exactly two adjacent sub-spans per rule (A → B C) or one word (A → w), so every cell is filled from two smaller cells.

## 3. Unit III — `unit3_dependency_semantics.py`

spaCy's dependency parser is transition-based (stack + buffer + SHIFT/ARC actions chosen by a neural network). Graph-based
parsing is shown with our own Chu-Liu/Edmonds maximum spanning tree on a toy sentence (best head per word, contract the cycle,
re-score, expand), and neural constituency parsing is explained in comments only. From the tree we extract triples: the actor is the object of
"from" (or the user), the action is the verb of the quoted description, and the target is the subject of "reported" plus the port.
If the description has no verb, the head noun is turned into a verb with WordNet derivational morphology
(authentication → authenticate). Triples are scored against 20 gold triples. Word vectors are rows of a word × context co-occurrence matrix.

* **Triple scores?** P = R = 0.65. Actor accuracy 0.95 and target accuracy 1.0, but verb accuracy only 0.7: "400 error code"
  has no action word (gold label "request"), and "handshake message" becomes "shake_hands" (gold "send").
* **How does Chu-Liu/Edmonds work?** Each word takes its best-scoring head. If that makes a cycle (attacker ↔ scanned), the cycle
  becomes one node, arcs into it are re-scored as score − score of the cycle arc they replace, the smaller problem is solved and
  the cycle is expanded again. Our toy tree (score 72) equals spaCy's parse.
* **What is head-finding?** Choosing the word that represents a phrase. In "web server 400 error code" the head is "code", and the others are compound modifiers.
* **How are synonyms normalised?** WordNet: "attempted" and "tried" share the synset try.v.01, so both map to the canonical action "try".

## 4. Unit IV — `unit4_tfidf_ie.py`

TF-IDF vectors of the normalised sentences are clustered with KMeans. k (2–15) is chosen by silhouette score, and clusters are
split where there is a pause of more than 30 minutes; each piece is an incident. Top TF-IDF words of a cluster are its keywords. Our own
PMI finds word pairs that co-occur more than chance, and PPMI re-weights the co-occurrence vectors. PCA projects word and alert vectors
to 2-D for the scatter plots. Rules over NER entities and triples extract relations (ATTACKED, SCANNED, LOGGED_INTO, ESCALATED_TO,
MAPS_TO). Each alert becomes a time-stamped event for the timeline.

* **What does silhouette measure?** (b − a)/max(a, b): a = mean distance to the point's own cluster, b = mean distance to the nearest other cluster. It ranges from −1 to 1.
  We get 0.28 (russellmitchell) and 0.32 (shaw).
* **Why is purity 0.83 / 0.97 not as impressive as it looks?** Most alerts are `normal` background. Putting everything in one
  cluster would already score 0.62 / 0.82 (the majority baseline). Incidents beat that baseline.
* **PMI formula?** PMI(x,y) = log2 P(x,y) / (P(x)P(y)). It is positive when x and y appear together more often than chance; PPMI sets negatives to 0.

## 5. Unit V — `unit5_summarize_qa.py`

Each alert gets an attack phase, from the AIT-ADS labels.csv time windows or otherwise from MITRE tactic rules. Incidents get
TimeBank-style BEFORE/OVERLAPS links. Template filling is the main summary: slots (what happened, attacker, targets, time
window, phases, severity, MITRE, rarest alert, recommended action) are filled from the incident's alerts and rendered as 3–5
sentences. Aspect analysis adds frequency (one-off / repeated / ongoing) and outcome (attempted / succeeded) to each incident. The baselines are the sentences closest to the TF-IDF centroid (extractive) and distilbart-cnn-6-6 on CPU (abstractive,
on demand). Rule-based SRL maps triples to Agent / Action / Patient / Time / Location. The Q&A chatbot detects the
intent with rules, answers from the extracted facts and shows TF-IDF-retrieved supporting alerts. SRL's Action is the verb of
the triple, or "trigger" if the alert has no action word.

* **Which summary is best and why?** Template: ROUGE-1 0.47, against 0.33 extractive and 0.35 abstractive. The slots
  contain exactly the facts an analyst writes (who, what, when, target), and the pretrained model was trained on news, not alerts.
* **Why not rely on the abstractive model?** It mostly copies alert sentences and can corrupt facts. In one run it shortened an IP
  address to "172.19.18", which is dangerous in a security report.
* **How does QA work without an LLM?** Regular expressions pick an intent (hosts, ports, IPs, time, MITRE, count, severity, action).
  Pandas answers it from the structured fields and extracted relations, and TF-IDF cosine retrieves the supporting alerts.

## 6. Pipeline — `pipeline.py`

`run_pipeline(df)` runs Unit I → V in order and returns plain Python data for the database. Speed caps keep it fast on a laptop CPU.
spaCy parses at most 3,000 unique sentence patterns (time of day removed, rarest first); the rest get entities from the structured
fields. Co-occurrence vectors use at most 20,000 sentences, and silhouette uses a 2,000-point sample. Full russellmitchell (21,354 alerts)
takes about 28 s and the 1,467-alert sample about 10 s.

* **Why parse unique patterns only?** Thousands of alerts differ only in time; parsing one copy gives the same result.
* **What happens to alerts beyond the spaCy cap?** Their entities and triple come from the structured fields (IP, host, port, user).
* **What is the order of the stages?** load → masking, alert types, LM → NER + triples → TF-IDF clusters, incidents, phases, vectors → severity, templates, summaries.

## 7. Database — `backend/db/`

SQLite with a hand-written schema: analyses, alerts, incidents, entities, relations, qa_logs. Every child references
its parent with ON DELETE CASCADE, so deleting an analysis cleans everything up. Queries are plain SQL through `sqlite3` with `?`
parameters (no SQL injection). Small JSON columns hold data that is always read as a whole (template slots, corpus insights).
See docs/DATABASE.md for the ER diagram.

* **Why is `PRAGMA foreign_keys = ON` needed?** SQLite does not enforce foreign keys unless this is set on each connection.
* **Which normal form?** Mostly 3NF. There is deliberate denormalisation: `entities.analysis_id` and the counters in `analyses`, to avoid joins/COUNT on every page load.
* **Why indexes?** SQLite does not index foreign keys automatically; we filter alerts by analysis, incident and time.

## 8. API — `backend/main.py`, `backend/routers/`

FastAPI with four routers (analyses, incidents, lab, evaluation). An upload creates a row with status `processing` and starts the
pipeline as a BackgroundTask. The React app polls `GET /api/analyses/{id}` until the status is `done` or `failed`. Errors are JSON
`{"detail": ...}` with proper status codes (400 bad file, 404 unknown id, 409 still processing, 413 too large, 503 AI model unavailable).
The NLP Lab endpoint runs one pasted alert through all five units. The PDF endpoint builds a reportlab document.

* **Why a background task?** A big file takes ~30 s; the HTTP request returns immediately and the UI shows progress.
* **What is CORS and why is it needed?** The browser blocks calls from :5173 (Vite) to :8000 (API) unless the API allows that origin.
* **How do you validate uploads?** Extension (.json/.jsonl/.ndjson), size ≤ 150 MB, not empty, starts with `[` or `{`. Non-alert JSON fails cleanly as status `failed`.

## 9. Frontend — `frontend/src/`

React + Vite with React Router: Dashboard, Analysis view (Incidents, Timeline, Entities & Relations, Ask), Incident detail,
NLP Lab, Evaluation, About. `api.js` holds every backend call (axios) and turns errors into readable messages. Charts are
Recharts (stacked timeline bars by phase, PCA scatter, ROUGE bars); the relation graph is plain SVG. Plain CSS with colour tokens gives one dark
SOC theme. Every page has loading and error states.

* **How does the dashboard know processing finished?** It polls the analysis status every couple of seconds.
* **Why no Redux?** Each page loads its own data with `useEffect`; there is no shared global state worth a store.
* **How is the relation graph drawn?** Nodes (IPs, hosts, users, ports) are placed in columns and the relations are drawn as SVG lines.

## 10. Evaluation — `backend/nlp/evaluate.py`

Runs the pipeline on the full russellmitchell and shaw scenarios and compares the outputs with hand-labelled gold files (DRAFT, to
be reviewed by the student): 25 reference summaries (ROUGE-1/2/L), 50 NER sentences (P/R/F1), 20 triples (P/R). It also reports
perplexity, silhouette, purity against the attack phases with a majority baseline, and the word-pair check. Results go to
data/eval/results.json, docs/RESULTS.md and docs/figures/.

* **What is ROUGE?** n-gram overlap between a system summary and a reference: ROUGE-1 counts words, ROUGE-2 word pairs, ROUGE-L the longest common subsequence.
* **Why is NER F1 0.994 suspiciously high?** Most gold sentences come from our own sentence template, which the rules were written for.
  The 10 free-text analyst notes are the real test. A fair evaluation would need text written by someone else.
* **How are references matched to incidents?** Same scenario, the same start second and the same main alert type.
