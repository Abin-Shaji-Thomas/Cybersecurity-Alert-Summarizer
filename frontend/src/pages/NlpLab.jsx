// NLP Lab: one pasted alert through every Learning Unit + corpus-level results for an analysis.
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, errorText } from '../api'
import { ErrorBox, Loading } from '../components/Common'
import CorpusInsights from '../components/CorpusInsights'

const DEFAULT_TEXT = "At 03:57:25, host intranet-server reported 'sshd: authentication failed' for user jhall from 172.19.131.174 targeting port 22 (level 5)."

const ENT_COLORS = { IP: '#3987e5', PORT: '#d95926', HOST: '#199e70', USER: '#c98500', CVE: '#d55181', MITRE_TECHNIQUE: '#9085e9', PROTOCOL: '#008300', TOOL: '#e66767' }

function Technique({ name, what, children }) {
  return (
    <div className="technique">
      <h3>{name}</h3>
      <div className="what">{what}</div>
      {children}
    </div>
  )
}

function Tokens({ items }) {
  return <div>{items.map((t, i) => <span key={i} className={`token ${t.startsWith('<') ? 'tag' : ''}`}>{t}</span>)}</div>
}

function Highlighted({ text, ents }) {
  const parts = []
  let pos = 0
  for (const e of [...ents].sort((a, b) => a.start - b.start)) {
    if (e.start < pos) continue
    parts.push(text.slice(pos, e.start))
    const c = ENT_COLORS[e.label] || '#6b7280'
    parts.push(<span key={e.start} className="ent" style={{ background: c + '33', boxShadow: `inset 0 -2px 0 ${c}` }}>{e.text}<small>{e.label}</small></span>)
    pos = e.end
  }
  parts.push(text.slice(pos))
  return <p className="mono" style={{ lineHeight: 2 }}>{parts}</p>
}

function CkyGrid({ cky }) {
  const n = cky.words.length
  return (
    <div className="table-wrap" style={{ maxHeight: 'none' }}>
      <table className="cky">
        <thead><tr><th />{cky.words.map((w, j) => <th key={j}>{j + 1}: {w}</th>)}</tr></thead>
        <tbody>
          {cky.words.map((w, i) => (
            <tr key={i}>
              <th>{i}: {w}</th>
              {Array.from({ length: n }, (_, j) => {
                // table[i][j] = non-terminals that produce words i..j (only j >= i is used)
                if (j < i) return <td key={j} className="empty" />
                const labels = cky.table[i][j] || []
                const isS = i === 0 && j === n - 1 && labels.includes('S')
                return <td key={j} className={isS ? 's' : ''}>{labels.join(', ') || '·'}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function NlpLab() {
  const [params] = useSearchParams()
  const [analyses, setAnalyses] = useState([])
  const [analysisId, setAnalysisId] = useState(params.get('analysis') || '')
  const [text, setText] = useState(DEFAULT_TEXT)
  const [ckyText, setCkyText] = useState('the attacker scanned the web server from 10.35.1.4')
  const [res, setRes] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.listAnalyses().then((a) => {
      const done = a.filter((x) => x.status === 'done')
      setAnalyses(done)
      if (!params.get('analysis') && done.length) setAnalysisId(String(done[0].id))
    }).catch((e) => setError(errorText(e)))
  }, [params])

  const run = async () => {
    setBusy(true)
    setError(null)
    try {
      setRes(await api.lab(text, analysisId ? Number(analysisId) : null, ckyText))
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>NLP Lab</h1>
          <div className="subtle">Run one alert through every Learning Unit and see what each technique does.</div>
        </div>
      </div>

      <div className="card">
        <label className="muted">Alert sentence (or paste a raw Wazuh JSON alert — it is converted to a sentence first)</label>
        <textarea rows={3} value={text} onChange={(e) => setText(e.target.value)} />
        <div className="row" style={{ marginTop: 10 }}>
          <label className="muted">CKY sentence (toy grammar):</label>
          <input type="text" value={ckyText} onChange={(e) => setCkyText(e.target.value)} style={{ flex: 1, width: 'auto', minWidth: 260 }} />
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <label className="muted">Corpus models from:</label>
          <select value={analysisId} onChange={(e) => setAnalysisId(e.target.value)}>
            <option value="">bundled sample</option>
            {analyses.map((a) => <option key={a.id} value={a.id}>#{a.id} {a.filename}</option>)}
          </select>
          <button className="btn-primary" onClick={run} disabled={busy || !text.trim()}>▶ Run through Units I–V</button>
          {busy && <span className="spinner" />}
        </div>
      </div>
      <ErrorBox error={error} />

      {res && <>
        {res.converted_from_json && <div className="notice info">Converted JSON alert → <span className="mono">{res.sentence}</span></div>}
        <p className="muted">Language model, TF-IDF and word vectors trained on: {res.corpus}</p>

        <div className="card unit-card">
          <h2>Unit I <small>Text processing & language modeling</small></h2>
          <div className="grid grid-2">
            <div>
              <Technique name="Regex masking" what="Indicators (IP, port, URL, hash, number, time) are replaced by tags so models learn alert language, not addresses.">
                <p className="mono">{res.unit1.masked}</p>
              </Technique>
              <Technique name="Normalisation + tokenisation" what="Lower-case, collapse spaces, split into word and <TAG> tokens.">
                <Tokens items={res.unit1.tokens} />
              </Technique>
              <Technique name="Sentence segmentation (NLTK Punkt)" what="Splits multi-sentence text; handles abbreviations.">
                <ol style={{ margin: 0, paddingLeft: 18 }}>{res.unit1.sentences.map((s, i) => <li key={i} className="mono">{s}</li>)}</ol>
              </Technique>
              <Technique name="Minimum edit distance (our DP)" what="Levenshtein distance; used to merge near-duplicate alert descriptions into alert types.">
                <p>distance(normalised input, “web server 400 error code”) = <b>{res.unit1.edit_distance.distance}</b></p>
                <p className="muted">DP table for “{res.unit1.edit_distance.table_a}” → “{res.unit1.edit_distance.table_b}” (bottom-right = distance):</p>
                <table className="cky"><tbody>
                  <tr><th /><th>ε</th>{[...res.unit1.edit_distance.table_b].map((c, j) => <th key={j}>{c}</th>)}</tr>
                  {res.unit1.edit_distance.table.map((row, i) => (
                    <tr key={i}><th>{i === 0 ? 'ε' : res.unit1.edit_distance.table_a[i - 1]}</th>
                      {row.map((v, j) => {
                        const last = i === res.unit1.edit_distance.table.length - 1 && j === row.length - 1
                        return <td key={j} className={last ? 's' : ''}>{v}</td>
                      })}</tr>
                  ))}
                </tbody></table>
              </Technique>
            </div>
            <Technique name="Bigram LM with Laplace smoothing (our code)" what="P(w | prev) = (C(prev,w)+1)/(C(prev)+V). Perplexity of this sentence = its rarity score.">
              <p>Sentence perplexity: <b>{res.unit1.perplexity}</b> <span className="muted">(higher = more unusual)</span></p>
              <div className="table-wrap" style={{ maxHeight: 380 }}>
                <table>
                  <thead><tr><th>prev</th><th>word</th><th className="num">count</th><th className="num">P(word|prev)</th></tr></thead>
                  <tbody>{res.unit1.bigrams.map((b, i) => <tr key={i}><td className="mono">{b.prev}</td><td className="mono">{b.word}</td><td className="num">{b.count}</td><td className="num">{b.prob}</td></tr>)}</tbody>
                </table>
              </div>
            </Technique>
          </div>
        </div>

        <div className="card unit-card">
          <h2>Unit II <small>POS tagging, NER & syntactic parsing</small></h2>
          <Technique name="Named entities (spaCy + security EntityRuler)" what="Rule patterns for IP, PORT, HOST, USER, CVE, MITRE technique, protocol, tool on top of spaCy's statistical NER.">
            <Highlighted text={res.sentence} ents={res.unit2.entities} />
          </Technique>
          <div className="grid grid-2">
            <Technique name={`POS: our HMM + Viterbi vs spaCy (agreement ${(res.unit2.hmm_spacy_agreement * 100).toFixed(0)}%)`}
              what="HMM transition/emission counts from the NLTK Penn Treebank sample, decoded with our Viterbi; both mapped to the universal tagset.">
              <div className="table-wrap" style={{ maxHeight: 360 }}>
                <table>
                  <thead><tr><th>word</th><th>HMM</th><th>spaCy</th><th /></tr></thead>
                  <tbody>{res.unit2.hmm_vs_spacy.map((r, i) => <tr key={i}><td className="mono">{r.word}</td><td>{r.hmm}</td><td>{r.spacy}</td><td>{r.agree ? '✓' : '✗'}</td></tr>)}</tbody>
                </table>
              </div>
            </Technique>
            <Technique name="Dependency grammar (spaCy)" what="Each word has one head; the label says the grammatical relation. Feeds the triple extraction in Unit III.">
              <div className="table-wrap" style={{ maxHeight: 360 }}>
                <table>
                  <thead><tr><th>word</th><th>dep</th><th>head</th><th>POS</th></tr></thead>
                  <tbody>{res.unit2.dependencies.map((d) => <tr key={d.i}><td className="mono">{d.text}</td><td><span className="chip">{d.dep}</span></td><td className="mono">{d.head}</td><td>{d.pos}</td></tr>)}</tbody>
                </table>
              </div>
            </Technique>
          </div>
          <Technique name="CFG in Chomsky Normal Form + our CKY parser (concept demo)"
            what="Cell [i, j] lists every non-terminal that can produce words i..j. 'S' in the top-right cell = the sentence is grammatical. The toy grammar knows ~60 words only.">
            {res.unit2.cky_used_default_sentence && <p className="muted">The pasted text is outside the toy grammar, so the default sentence is used.</p>}
            <CkyGrid cky={res.unit2.cky} />
            <p style={{ marginTop: 8 }}>{res.unit2.cky.parsed ? '✓ Parsed:' : `✗ Not in the grammar${res.unit2.cky.unknown_words.length ? ` (unknown words: ${res.unit2.cky.unknown_words.join(', ')})` : ''}`}</p>
            {res.unit2.cky.bracketed && <pre className="tree">{res.unit2.cky.bracketed}</pre>}
            <details style={{ marginTop: 8 }}><summary className="muted">Show grammar</summary><pre className="tree">{res.unit2.grammar.join('\n')}</pre></details>
          </Technique>
        </div>

        <div className="card unit-card">
          <h2>Unit III <small>Dependency parsing & semantic representations</small></h2>
          <div className="grid grid-2">
            <div>
              <Technique name="Triple extraction (actor, action, target)" what="From the dependency tree: object of 'from' = actor, head of the quoted alert = action, subject of 'reported' (+ port) = target.">
                <table className="kv"><tbody>
                  <tr><th>actor</th><td className="mono">{res.unit3.triple.actor || '–'}</td></tr>
                  <tr><th>action</th><td>{res.unit3.triple.action || '–'} <span className="muted">(verb: {res.unit3.triple.action_head || '–'})</span></td></tr>
                  <tr><th>target</th><td className="mono">{res.unit3.triple.target || '–'}</td></tr>
                </tbody></table>
              </Technique>
              <Technique name="Head-finding for noun phrases" what="The head is the word the rest of the phrase depends on.">
                <table><thead><tr><th>noun phrase</th><th>head</th><th>dep</th></tr></thead>
                  <tbody>{res.unit3.noun_phrase_heads.map((n, i) => <tr key={i}><td>{n.phrase}</td><td className="mono">{n.head}</td><td>{n.head_dep}</td></tr>)}</tbody></table>
              </Technique>
            </div>
            <div>
              <Technique name="Lexical semantics (WordNet)" what="Synonyms of the first synset give a canonical action (attempt / try → 'try'); hypernyms are more general concepts.">
                <table><thead><tr><th>word</th><th>canonical</th><th>synonyms</th><th>hypernyms</th></tr></thead>
                  <tbody>{res.unit3.wordnet.map((w, i) => <tr key={i}><td className="mono">{w.word}</td><td>{w.canonical}</td><td className="muted">{w.synonyms.join(', ')}</td><td className="muted">{w.hypernyms.join(', ')}</td></tr>)}</tbody></table>
              </Technique>
              <Technique name="Vector semantics (co-occurrence + PPMI)" what="Word vectors = rows of a word-context count matrix from the alert corpus; nearest neighbours by cosine.">
                {Object.keys(res.unit3.neighbours || {}).length === 0 && <p className="muted">No input word is in the corpus vocabulary.</p>}
                {Object.entries(res.unit3.neighbours || {}).map(([w, ns]) => (
                  <p key={w}><span className="token">{w}</span> → {ns.map((n) => <span key={n.word} className="chip">{n.word} {n.cosine}</span>)}</p>
                ))}
              </Technique>
            </div>
          </div>
          <Technique name="Graph-based dependency parsing: our Chu-Liu/Edmonds MST (concept demo)"
            what="A graph-based parser scores every head → dependent arc and keeps the maximum spanning tree. Scores are hand-picked for this toy sentence; spaCy (transition-based) parses the same words for comparison.">
            {(() => {
              const m = res.unit3.mst
              return (
                <div className="grid grid-3">
                  <div>
                    <h3>1. Arc scores</h3>
                    <div className="table-wrap" style={{ maxHeight: 220 }}><table><tbody>{m.scores.map((a, i) => <tr key={i}><td className="mono">{a.head} → {a.dep}</td><td className="num">{a.score}</td></tr>)}</tbody></table></div>
                  </div>
                  <div>
                    <h3>2. Best head per word</h3>
                    <table><tbody>{m.greedy.map((a, i) => <tr key={i}><td className="mono">{a.head} → {a.dep}</td></tr>)}</tbody></table>
                    <p className="muted">{m.cycle.length ? `Cycle ${m.cycle.join(' ↔ ')} → contracted into one node and re-scored.` : 'No cycle.'}</p>
                  </div>
                  <div>
                    <h3>3. Maximum spanning tree (score {m.total_score}) vs spaCy</h3>
                    <table><thead><tr><th>MST</th><th>spaCy</th></tr></thead><tbody>{m.tree.map((a, i) => {
                      const sp = m.spacy.find((x) => x.dep === a.dep)
                      return <tr key={i}><td className="mono">{a.head} → {a.dep}</td><td className="mono">{sp ? `${sp.head} → ${sp.dep} (${sp.label})` : '–'}</td></tr>
                    })}</tbody></table>
                  </div>
                </div>
              )
            })()}
          </Technique>
        </div>

        <div className="grid grid-2">
          <div className="card unit-card">
            <h2>Unit IV <small>TF-IDF & information extraction</small></h2>
            <Technique name="TF-IDF top terms" what="Terms frequent in this alert but rare in the corpus get the highest weight (the same vectors cluster alerts into incidents).">
              <table><thead><tr><th>term</th><th className="num">weight</th><th style={{ width: '45%' }} /></tr></thead>
                <tbody>{res.unit4.tfidf_top_terms.map((t) => (
                  <tr key={t.term}><td className="mono">{t.term}</td><td className="num">{t.weight}</td>
                    <td><div style={{ height: 8, width: `${t.weight * 100}%`, background: '#3987e5', borderRadius: 4 }} /></td></tr>
                ))}</tbody></table>
              <p className="muted">Clustering text: <span className="mono">{res.unit4.feature_text}</span></p>
            </Technique>
          </div>
          <div className="card unit-card">
            <h2>Unit V <small>Semantic roles & applications</small></h2>
            <Technique name="Rule-based semantic role labelling" what="The triple is mapped to Agent / Action / Patient / Time / Location — these fill the summary template.">
              <table className="kv"><tbody>{Object.entries(res.unit5.srl).map(([k, v]) => <tr key={k}><th>{k}</th><td className="mono">{v || '–'}</td></tr>)}</tbody></table>
              <p className="muted">Time is “now” here because a pasted sentence has no alert timestamp.</p>
            </Technique>
          </div>
        </div>
      </>}

      <CorpusInsights analysisId={analysisId} />
      {!analysisId && !analyses.length && <div className="card subtle">Run an analysis (e.g. the sample data on the Dashboard) to see corpus-level results here.</div>}
      {busy && !res && <Loading text="Running the NLP units…" />}
    </>
  )
}
