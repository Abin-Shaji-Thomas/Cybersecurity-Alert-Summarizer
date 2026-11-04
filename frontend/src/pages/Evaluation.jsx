// Evaluation: metrics produced by `python -m nlp.evaluate` (data/eval/results.json).
import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, errorText } from '../api'
import { ChartTooltip, ErrorBox, Loading, StatCard } from '../components/Common'
import { CATEGORICAL } from '../theme'

const SYSTEM_COLOR = { template: CATEGORICAL[0], extractive: CATEGORICAL[1], abstractive: CATEGORICAL[2] }
const axis = { stroke: '#73839a', fontSize: 11 }

function RougeChart({ mean }) {
  const systems = Object.keys(mean)
  const data = ['rouge1', 'rouge2', 'rougeL'].map((m) => ({
    metric: m.replace('rouge', 'ROUGE-'), ...Object.fromEntries(systems.map((s) => [s, mean[s][m]])),
  }))
  return (
    <>
      <div className="legend">{systems.map((s) => <span key={s}><span className="dot" style={{ background: SYSTEM_COLOR[s] }} />{s}</span>)}</div>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={data} margin={{ top: 18, right: 8, left: -12, bottom: 0 }}>
          <CartesianGrid stroke="#263344" vertical={false} />
          <XAxis dataKey="metric" {...axis} />
          <YAxis {...axis} domain={[0, 'auto']} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
          {systems.map((s) => (
            <Bar key={s} dataKey={s} name={s} fill={SYSTEM_COLOR[s]} radius={[3, 3, 0, 0]}>
              <LabelList dataKey={s} position="top" fill="#a9b6c6" fontSize={10} formatter={(v) => v.toFixed(2)} />
            </Bar>
          ))}
        </BarChart>
      </ResponsiveContainer>
    </>
  )
}

function Check({ ok }) {
  return <span style={{ color: ok ? 'var(--ok)' : 'var(--danger)' }}>{ok ? '✓' : '✗'}</span>
}

export default function Evaluation() {
  const [r, setR] = useState(null)
  const [error, setError] = useState(null)
  const [item, setItem] = useState(0)

  const load = () => {
    setError(null)
    api.evaluation().then(setR).catch((e) => setError(errorText(e)))
  }
  useEffect(load, [])

  if (error) return <><h1>Evaluation</h1><ErrorBox error={error} onRetry={load} /></>
  if (!r) return <Loading text="Loading evaluation results…" />

  const sm = r.summarization
  const scen = Object.entries(r.scenarios)
  const matched = sm.items.filter((i) => i.matched)
  const ex = matched[item]

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Evaluation</h1>
          <div className="subtle">Run on the AIT-ADS scenarios {scen.map(([s]) => s).join(' and ')} · generated {r.generated_at} in {r.seconds} s</div>
        </div>
      </div>
      <div className="notice info">Gold files in <code>data/eval/</code> are <b>DRAFT – student to review</b>. Re-run with <code>python -m nlp.evaluate</code> after editing them.</div>

      <div className="stats">
        <StatCard label="ROUGE-1 (template)" value={sm.mean_f1.template?.rouge1.toFixed(3)} hint={`${sm.n_matched} reference summaries`} />
        <StatCard label="NER micro F1" value={r.ner.micro.f1.toFixed(3)} hint={`${r.ner.n_sentences} sentences`} />
        <StatCard label="Triple F1" value={r.triples.f1.toFixed(2)} hint={`${r.triples.n_gold} gold triples`} />
        <StatCard label="HMM / spaCy agreement" value={r.hmm_vs_spacy.agreement.toFixed(3)} hint={`${r.hmm_vs_spacy.n_tokens} tokens`} />
      </div>

      <div className="grid grid-2">
        <div className="card unit-card">
          <h2>Unit V <small>Summaries vs references (ROUGE F1)</small></h2>
          <p className="muted">Template filling vs TF-IDF extractive vs pretrained abstractive ({sm.abstractive_model || 'not run'}{sm.abstractive_seconds_per_summary ? `, ${sm.abstractive_seconds_per_summary} s per summary on CPU` : ''}).</p>
          <RougeChart mean={sm.mean_f1} />
          {sm.abstractive_error && <div className="notice error">Abstractive model failed: {sm.abstractive_error}</div>}
        </div>

        <div className="card unit-card">
          <h2>Unit V <small>One reference, three summaries</small></h2>
          <div className="row" style={{ marginBottom: 8 }}>
            <select value={item} onChange={(e) => setItem(Number(e.target.value))} aria-label="Choose incident">
              {matched.map((m, i) => <option key={i} value={i}>{m.scenario} · {m.incident_start.slice(5, 16)} · {m.title.slice(0, 50)}</option>)}
            </select>
          </div>
          <h3>Reference (hand-written)</h3>
          <p className="muted">{ex.reference}</p>
          {Object.entries(ex.outputs).map(([s, text]) => (
            <div key={s} style={{ marginBottom: 8 }}>
              <h3><span className="dot" style={{ background: SYSTEM_COLOR[s] }} /> {s} <span className="muted">R-1 {ex.scores[s]?.rouge1} · R-L {ex.scores[s]?.rougeL}</span></h3>
              <p className="muted" style={{ maxHeight: 90, overflowY: 'auto' }}>{text}</p>
            </div>
          ))}
        </div>

        <div className="card unit-card">
          <h2>Unit II <small>Named entity recognition</small></h2>
          <p className="muted">Exact match on (text, label). Micro P {r.ner.micro.precision} · R {r.ner.micro.recall} · F1 {r.ner.micro.f1}</p>
          <table>
            <thead><tr><th>Label</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th><th className="num">Gold</th></tr></thead>
            <tbody>{Object.entries(r.ner.per_label).map(([l, v]) => (
              <tr key={l}><td className="mono">{l}</td><td className="num">{v.precision}</td><td className="num">{v.recall}</td><td className="num"><b>{v.f1}</b></td><td className="num">{v.n_gold}</td></tr>
            ))}</tbody>
          </table>
          {r.ner.errors.length > 0 && <p className="muted" style={{ marginTop: 8 }}>Errors: {r.ner.errors.map((e) => `#${e.id} ${[...e.missed.map((m) => 'missed ' + m), ...e.spurious.map((s) => 'spurious ' + s)].join(', ')}`).join(' · ')}</p>}
          <h3 style={{ marginTop: 12 }}>HMM (own Viterbi) vs spaCy POS</h3>
          <p className="muted">Agreement {r.hmm_vs_spacy.agreement} on {r.hmm_vs_spacy.n_sentences} alert sentences. Most frequent disagreements:</p>
          <table><tbody>{r.hmm_vs_spacy.top_disagreements.map((d) => <tr key={d.pair}><td>{d.pair}</td><td className="num">{d.count}</td></tr>)}</tbody></table>
        </div>

        <div className="card unit-card">
          <h2>Unit III <small>Triple extraction (actor, action, target)</small></h2>
          <p className="muted">P {r.triples.precision} · R {r.triples.recall} · F1 {r.triples.f1} — field accuracy: {Object.entries(r.triples.field_accuracy).map(([k, v]) => `${k} ${v}`).join(', ')}</p>
          <div className="table-wrap" style={{ maxHeight: 340 }}>
            <table>
              <thead><tr><th>#</th><th>Gold</th><th>Predicted</th><th /></tr></thead>
              <tbody>{r.triples.rows.map((t) => (
                <tr key={t.id}><td>{t.id}</td><td className="mono">{t.gold.join(' · ')}</td><td className="mono">{t.pred.map((x) => x ?? '–').join(' · ')}</td><td><Check ok={t.correct} /></td></tr>
              ))}</tbody>
            </table>
          </div>
        </div>

        <div className="card unit-card">
          <h2>Unit I <small>Bigram LM perplexity</small></h2>
          <p className="muted">Held-out = 20 % of the unique masked sentences. Without smoothing an unseen bigram has probability 0.</p>
          <table>
            <thead><tr><th>Scenario</th><th className="num">Unsmoothed held-out</th><th className="num">Laplace held-out</th><th className="num">Laplace train</th><th className="num">Unseen-bigram test sents</th></tr></thead>
            <tbody>{scen.map(([s, v]) => (
              <tr key={s}><td>{s}</td><td className="num">{String(v.lm.perplexity_test_unsmoothed)}</td><td className="num"><b>{v.lm.perplexity_test_smoothed}</b></td><td className="num">{v.lm.perplexity_train_smoothed}</td><td className="num">{v.lm.test_sentences_with_zero_prob_unsmoothed} / {v.lm.n_test_sentences}</td></tr>
            ))}</tbody>
          </table>
        </div>

        <div className="card unit-card">
          <h2>Unit IV <small>Clusters and word vectors</small></h2>
          <p className="muted">Purity against attack-phase labels; the majority baseline is what one big cluster would score.</p>
          <table>
            <thead><tr><th>Scenario</th><th className="num">k</th><th className="num">Silhouette</th><th className="num">Purity (incidents)</th><th className="num">Baseline</th><th className="num">Word pairs</th></tr></thead>
            <tbody>{scen.map(([s, v]) => (
              <tr key={s}><td>{s}</td><td className="num">{v.clustering.k}</td><td className="num">{v.clustering.silhouette}</td><td className="num"><b>{v.clustering.purity_incidents}</b></td><td className="num">{v.clustering.purity_majority_baseline}</td><td className="num">{v.word_similarity_ppmi.pairwise_accuracy}</td></tr>
            ))}</tbody>
          </table>
          <p className="muted" style={{ marginTop: 8 }}>Word pairs = probability that a related pair (e.g. tls/ssl) has a higher PPMI cosine than an unrelated pair (e.g. sudo/tls). Mean cosine related vs unrelated: {scen.map(([s, v]) => `${s} ${v.word_similarity_ppmi.mean_cosine_related} vs ${v.word_similarity_ppmi.mean_cosine_unrelated}`).join('; ')}.</p>
        </div>
      </div>
    </>
  )
}
