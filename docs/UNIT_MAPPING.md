# Syllabus → feature mapping

Every topic of Learning Units I–V, where it is implemented and where it can be seen in the app.
"Own code" = the algorithm is written by us in a few lines (not a library call).
Topics marked **documentation only** are explained here and in code comments but not implemented.

## Course outcomes

| CO | Unit | Covered by |
|---|---|---|
| CO1 | Unit I – Introduction to NLP & language modelling | `unit1_preprocess_lm.py`, NLP Lab Unit I card, corpus perplexity, Evaluation (perplexity) |
| CO2 | Unit II – POS tagging & syntactic parsing | `unit2_pos_ner_parse.py`, Entities tab, NLP Lab Unit II card (HMM vs spaCy, CKY grid), Evaluation (NER) |
| CO3 | Unit III – Dependency parsing & semantic representations | `unit3_dependency_semantics.py`, NLP Lab Unit III card, Evaluation (triples) |
| CO4 | Unit IV – Embeddings & information extraction | `unit4_tfidf_ie.py`, Incidents, Timeline, Relations graph, PCA scatter, Evaluation (silhouette, purity, word pairs) |
| CO5 | Unit V – Advanced NLP applications + the full application | `unit5_summarize_qa.py`, Incident detail (summaries, SRL), Ask tab, PDF, the whole React + FastAPI + SQLite app |

## Unit I – Introduction to NLP & Language Modeling (`backend/nlp/unit1_preprocess_lm.py`)

| Topic | File / function | UI | Explanation |
|---|---|---|---|
| Text processing | `mask_text`, `normalize`, `tokenize` | NLP Lab → Unit I | Lowercase and regex-mask IPs, ports, URLs, hashes, numbers (`<IP>`, `<PORT>`...) so models learn alert language, not addresses. |
| Sentence segmentation | `split_sentences` (NLTK Punkt) | NLP Lab → Unit I | Splits multi-sentence pasted logs/notes into sentences. |
| Minimum edit distance | `edit_distance`, `edit_distance_table` (own DP) | NLP Lab (DP grid), corpus "merged alert types" | Levenshtein distance; `merge_alert_types` merges near-duplicate descriptions (400 vs 500 error code) into alert types. |
| N-gram language models | `BigramLM` (own) | NLP Lab (bigram probabilities) | Bigram model P(w \| previous word) trained on alert sentences. |
| Evaluation: generalisation | `train_and_evaluate_lm` | Lab corpus section, Evaluation | 80/20 split on unique sentences; held-out perplexity measures generalisation. |
| Smoothing | `BigramLM(smoothing=True)` (Laplace) | Lab, Evaluation | Unsmoothed held-out perplexity is infinite (unseen bigrams); add-one smoothing makes it finite. |
| Perplexity as rarity | `rarity_scores` | Incident table "rarity", "top rare alerts" slot | Unusual alerts surprise the LM and are mentioned first in summaries. |

## Unit II – POS Tagging & Syntactic Parsing (`backend/nlp/unit2_pos_ner_parse.py`)

| Topic | File / function | UI | Explanation |
|---|---|---|---|
| POS tagging | `pos_tags` (spaCy) | NLP Lab → Unit II | Neural tagger baseline. |
| HMM for POS tagging | `HMMTagger.fit` (own counts), `get_hmm` | NLP Lab (HMM vs spaCy table), Evaluation | Transition + emission probabilities from the NLTK Penn Treebank sample. |
| Viterbi | `HMMTagger.viterbi` (own) | NLP Lab, `tests/test_nlp.py` | Dynamic programming over the tag lattice to find the best tag sequence. |
| Named entities & NER | `get_nlp` (spaCy + EntityRuler), `extract_entities` | Entities tab, Incident entities, Evaluation (P/R/F1) | IP, PORT, CVE, MITRE_TECHNIQUE, HOST, USER, PROTOCOL, TOOL patterns + spaCy's statistical entities. |
| Context-free grammar | `CNF_GRAMMAR`, `grammar_as_text` | NLP Lab (grammar listing) | Toy grammar in Chomsky Normal Form for "the attacker scanned the server". Concept demo. |
| CKY parsing | `cky_parse` (own) | NLP Lab (CKY table grid + tree) | Bottom-up chart parsing with back-pointers. |
| Dependency grammar | `dependency_arcs` | NLP Lab (arcs table) | Head → dependent arcs, used by Unit III. |

## Unit III – Dependency Parsing & Semantic Representations (`backend/nlp/unit3_dependency_semantics.py`)

| Topic | File / function | UI | Explanation |
|---|---|---|---|
| Transition-based dependency parsing | spaCy parser (`get_nlp`) | NLP Lab arcs | spaCy uses a stack/buffer transition system with a neural classifier (explained in the module docstring). |
| Graph-based dependency parsing | — | **documentation only** | Explained in the module docstring (maximum spanning tree over scored arcs). |
| Neural constituency parsing | — | **documentation only** | Explained in the module docstring (span scoring + CKY-style search); constituency parsing is shown with our toy CKY. |
| Heads & head-finding | `np_head`, `noun_phrase_heads` | NLP Lab → Unit III | Head word of each noun phrase and its compound modifiers. |
| Triple extraction | `extract_triple` | Timeline actor/target, SRL, NLP Lab | (actor, action, target) from the dependency tree. |
| Evaluating parsers | `evaluate_triples` | Evaluation page | Precision / recall of triples against `data/eval/triples_gold.csv`. |
| Lexical semantics | `wordnet_info`, `normalize_action`, `noun_to_verb` | NLP Lab (WordNet table) | WordNet synonyms/hypernyms; derivational morphology turns "authentication" into "authenticate". |
| Vector semantics | `cooccurrence_vectors`, `cosine_neighbours`, `cosine` | Lab corpus "nearest neighbours" | Word vectors = rows of a word × context co-occurrence matrix over our corpus. |

## Unit IV – Embeddings & Information Extraction (`backend/nlp/unit4_tfidf_ie.py`)

| Topic | File / function | UI | Explanation |
|---|---|---|---|
| TF-IDF | `build_tfidf`, `top_tfidf_terms` | NLP Lab (top terms), incident keywords | scikit-learn TF-IDF on normalised alert sentences. |
| Clustering into incidents | `cluster_alerts`, `choose_k_and_cluster`, `split_incidents` | Incidents tab | KMeans, k chosen by silhouette, split at 30-minute gaps. |
| PMI / PPMI | `pmi_pairs`, `ppmi_matrix` (own) | Lab corpus "PMI pairs" | Word pairs that co-occur more than chance; PPMI re-weights the Unit III vectors. |
| Visualising embeddings | `word_pca`, `alert_pca` | Lab corpus PCA scatter plots | 2-D PCA / SVD coordinates drawn with Recharts. |
| Semantic properties of embeddings | `cosine_neighbours` on PPMI vectors | Lab corpus | Neighbours show that related security words (tls/ssl, handshake/record) end up close. |
| Evaluating vector models | `evaluate_word_pairs`, `purity`, silhouette | Evaluation page | Hand-picked related vs unrelated pairs; cluster silhouette and purity vs attack phases. |
| Relation extraction | `extract_relations` | Entities & Relations graph, PDF | Rules over NER + triples: ATTACKED, SCANNED, LOGGED_INTO, ESCALATED_TO, MAPS_TO. |
| Extracting events & representing time | `to_event`, `/timeline` endpoint | Timeline tab | Each alert → event (time, actor, action, target, severity), UTC-normalised and sorted. |

## Unit V – Advanced NLP Applications (`backend/nlp/unit5_summarize_qa.py`)

| Topic | File / function | UI | Explanation |
|---|---|---|---|
| Temporal analysis | `assign_phases`, `detect_scenario`, `phase_from_tactic` | Timeline colours, phases slot | Attack phase from labels.csv windows (AIT-ADS) or MITRE tactic rules. |
| TimeBank | `temporal_links` | Lab corpus / insights | TimeBank-style events, time expressions and BEFORE/OVERLAPS links between incidents (comments explain the relation). |
| Aspect analysis | `fill_template` slots | Incident detail | **Partial:** each incident is described along fixed aspects (who, what, target, when, severity, action). There is no aspect-based sentiment classifier (alerts carry no opinions). |
| Template filling | `fill_template`, `render_template` | Incident detail (main summary), PDF | Main summary: slots rendered as a 3–5 sentence paragraph. |
| Semantic roles / SRL | `srl_roles` | Incident detail "Semantic roles", NLP Lab | Rule-based Agent / Action / Patient / Time / Location from the triple. |
| Summarisation (extractive) | `extractive_summary` | Incident detail | Sentences closest to the incident's TF-IDF centroid. |
| Summarisation (abstractive) | `abstractive_summary` (distilbart-cnn-6-6) | Incident detail "Generate AI summary" | Pretrained model on CPU, on demand. |
| Question answering & IR | `retrieve`, `answer_question` | Ask tab | TF-IDF retrieval of supporting alerts + rules over entities/relations. |
| Chatbots | `answer_question` intents, `qa_logs` table | Ask tab | Rule-based intent detection (hosts, IPs, time, MITRE, counts...), history logged. |
| Machine translation | — | **documentation only** | Encoder–decoder (seq2seq) models translate between languages; could localise alerts. Not implemented by choice. |
| Speech recognition | — | **documentation only** | Audio → text (e.g. acoustic model + LM, or end-to-end models like Whisper); could take spoken analyst queries. Not implemented by choice. |
| Text-to-speech | — | **documentation only** | Text → audio (e.g. Tacotron + vocoder); could read critical alerts aloud. Not implemented by choice. |

## Full application (CO5)

| Part | Where |
|---|---|
| Pipeline orchestration | `backend/nlp/pipeline.py` (`run_pipeline`) |
| Database | `backend/db/schema.sql`, `backend/db/database.py`, `docs/DATABASE.md` |
| REST API | `backend/main.py`, `backend/routers/*.py` |
| PDF report | `backend/services/pdf_report.py` |
| Frontend | `frontend/src/pages/*.jsx`, `frontend/src/components/*.jsx` |
| Evaluation | `backend/nlp/evaluate.py`, `docs/RESULTS.md` |
