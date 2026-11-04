// About: project description, architecture, syllabus mapping, dataset credit.
const MAPPING = [
  ['I', 'Text processing, regex', 'unit1_preprocess_lm.py · mask_text / tokenize', 'NLP Lab → Unit I'],
  ['I', 'Sentence segmentation', 'split_sentences (NLTK Punkt)', 'NLP Lab → Unit I'],
  ['I', 'Minimum edit distance', 'edit_distance (own DP) → merge_alert_types', 'Lab (DP grid), corpus alert types'],
  ['I', 'N-gram LM, smoothing, generalisation', 'BigramLM (own, Laplace), train_and_evaluate_lm', 'Lab, Evaluation (perplexity), rarity'],
  ['II', 'POS tagging', 'spaCy pos_tags', 'NLP Lab → Unit II'],
  ['II', 'HMM POS tagging', 'HMMTagger + own Viterbi', 'Lab (HMM vs spaCy), Evaluation'],
  ['II', 'Named entities / NER', 'spaCy + EntityRuler (IP, PORT, CVE, MITRE…)', 'Entities tab, Lab, Evaluation'],
  ['II', 'CFG + CKY parsing', 'CNF_GRAMMAR + own cky_parse', 'Lab (CKY table + tree)'],
  ['II', 'Dependency grammar', 'dependency_arcs', 'Lab'],
  ['III', 'Transition-based dependency parsing', 'spaCy parser (stack + buffer + neural classifier)', 'NLP Lab → Unit II arcs'],
  ['III', 'Graph-based dependency parsing', 'chu_liu_edmonds (own MST, toy sentence)', 'NLP Lab → Unit III'],
  ['III', 'Neural constituency parsing', 'explained in comments', 'Documentation only'],
  ['III', 'Heads & head-finding', 'np_head, noun_phrase_heads', 'Lab'],
  ['III', 'Evaluating parsers', 'evaluate_triples (P/R vs gold)', 'Evaluation'],
  ['III', 'Lexical semantics', 'wordnet_info (synonyms/hypernyms)', 'Lab'],
  ['III', 'Vector semantics', 'cooccurrence_vectors, cosine_neighbours', 'Lab corpus section'],
  ['IV', 'TF-IDF', 'build_tfidf, cluster_alerts → incidents', 'Incidents, Lab'],
  ['IV', 'PMI / PPMI', 'pmi_pairs, ppmi_matrix (own)', 'Lab corpus section'],
  ['IV', 'Visualising embeddings', 'word_pca, alert_pca', 'Lab scatter plots'],
  ['IV', 'Evaluating vector models', 'evaluate_word_pairs, silhouette, purity', 'Evaluation'],
  ['IV', 'Relation extraction', 'extract_relations (rules on NER + triples)', 'Entities & Relations graph'],
  ['IV', 'Events & time', 'to_event, timeline endpoint', 'Timeline tab'],
  ['V', 'Temporal analysis, TimeBank', 'assign_phases, temporal_links', 'Timeline, Lab'],
  ['V', 'Aspect analysis', 'incident_aspects (one-off / repeated / ongoing, attempted / succeeded)', 'Incident detail badges + summary'],
  ['V', 'Template filling, SRL', 'fill_template, render_template, srl_roles', 'Incident detail (main summary)'],
  ['V', 'QA & IR, chatbots', 'answer_question, retrieve (TF-IDF)', 'Ask tab'],
  ['V', 'Summarisation (extractive / abstractive)', 'extractive_summary, abstractive_summary (distilbart)', 'Incident detail, Evaluation'],
  ['V', 'Machine translation, speech recognition, TTS', '—', 'Documentation only'],
]

export default function About() {
  return (
    <>
      <div className="page-head"><div><h1>About</h1><div className="subtle">End-semester project · Natural Language Processing (25CS2XXX)</div></div></div>

      <div className="card">
        <h2>What it does</h2>
        <p>A security analyst uploads raw IDS/SIEM alerts (Wazuh + Suricata JSON). Each structured alert is rendered as an English
          sentence, and an NLP pipeline built from the five syllabus units groups related alerts into <b>incidents</b>, extracts
          <b> entities and relations</b>, orders events on a <b>timeline</b>, writes a <b>summary</b> per incident (what, who, to what,
          when, how severe, what to do next) and answers <b>questions</b> about the analysis. Everything runs locally on CPU.</p>
      </div>

      <div className="card">
        <h2>Architecture</h2>
        <div className="arch">
          <div className="box"><b>React + Vite</b><div className="muted">Dashboard, Analysis, Incident, NLP Lab, Evaluation · Recharts</div></div>
          <div className="arrow">⇄</div>
          <div className="box"><b>FastAPI</b><div className="muted">REST JSON API · background tasks · PDF (reportlab)</div></div>
          <div className="arrow">→</div>
          <div className="box"><b>NLP pipeline</b><div className="muted">load → Unit I → II → III → IV → V (NLTK, spaCy, scikit-learn, transformers)</div></div>
          <div className="arrow">⇄</div>
          <div className="box"><b>SQLite</b><div className="muted">analyses, alerts, incidents, entities, relations, qa_logs (plain SQL)</div></div>
        </div>
      </div>

      <div className="card">
        <h2>Syllabus → feature mapping</h2>
        <div className="table-wrap" style={{ maxHeight: 'none' }}>
          <table>
            <thead><tr><th>Unit</th><th>Topic</th><th>Code</th><th>Where to see it</th></tr></thead>
            <tbody>{MAPPING.map((m, i) => <tr key={i}><td>{m[0]}</td><td>{m[1]}</td><td className="mono">{m[2]}</td><td>{m[3]}</td></tr>)}</tbody>
          </table>
        </div>
        <p className="muted">Full mapping with course outcomes: docs/UNIT_MAPPING.md.</p>
        <p className="muted">Author: Abin Shaji Thomas (URK24CS6007), Karunya Institute of Technology and Sciences.</p>
      </div>

      <div className="card">
        <h2>Dataset</h2>
        <p>AIT Alert Data Set (AIT-ADS) — Landauer, M., Skopik, F., Wurzenberger, M. et al., Zenodo record
          <a href="https://zenodo.org/records/8263181" target="_blank" rel="noreferrer"> 8263181</a>, licensed CC BY 4.0.
          Development and evaluation use the <i>russellmitchell</i> and <i>shaw</i> scenarios.</p>
      </div>
    </>
  )
}
