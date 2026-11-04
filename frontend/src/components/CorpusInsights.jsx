// Corpus-level NLP outputs for one analysis (shown at the bottom of the NLP Lab).
import { useEffect, useState } from 'react'
import { CartesianGrid, LabelList, Line, LineChart, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from 'recharts'
import { api, errorText } from '../api'
import { ErrorBox, Loading } from './Common'
import { CATEGORICAL, clusterColor } from '../theme'

function PointTip({ active, payload, field }) {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return <div className="chart-tooltip">{p[field]}{p.count ? <div className="muted">{p.count} alerts · cluster {p.cluster}</div> : null}</div>
}

const axis = { stroke: '#73839a', fontSize: 11, tickFormatter: (v) => v.toFixed(1) }

export default function CorpusInsights({ analysisId }) {
  const [ins, setIns] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    setIns(null)
    setError(null)
    if (!analysisId) return
    api.insights(analysisId).then(setIns).catch((e) => setError(errorText(e)))
  }, [analysisId])

  if (!analysisId) return null
  if (error) return <ErrorBox error={error} />
  if (!ins) return <Loading text="Loading corpus results…" />

  const lm = ins.unit1.lm
  const u4 = ins.unit4
  const nClusters = Object.keys(u4.cluster_keywords).length
  // clusters beyond the 8 categorical colours are grouped as "other" (gray)
  const byCluster = Array.from({ length: Math.min(nClusters, 8) }, (_, c) => u4.alert_pca.filter((p) => p.cluster === c))
  const other = u4.alert_pca.filter((p) => p.cluster >= 8)
  const labelled = new Set(u4.word_pca.slice(0, 22).map((w) => w.word))

  return (
    <>
      <h1 style={{ marginTop: 28 }}>Corpus results <span className="muted">analysis #{ins.analysis.id} · {ins.analysis.n_alerts.toLocaleString()} alerts</span></h1>
      <p className="subtle">Computed over every alert sentence of the analysis when the pipeline ran.</p>

      <div className="grid grid-2">
        <div className="card unit-card">
          <h2>Unit I <small>Bigram LM: generalisation & smoothing</small></h2>
          <p className="muted">Trained on 80 % of the unique masked sentences, evaluated on the held-out 20 %. Without smoothing any unseen bigram has P = 0 → infinite perplexity.</p>
          <table>
            <thead><tr><th /><th className="num">Unsmoothed (MLE)</th><th className="num">Laplace (add-one)</th></tr></thead>
            <tbody>
              <tr><td>Train perplexity</td><td className="num">{lm.perplexity_train_unsmoothed}</td><td className="num">{lm.perplexity_train_smoothed}</td></tr>
              <tr><td>Held-out perplexity</td><td className="num">{String(lm.perplexity_test_unsmoothed)}</td><td className="num"><b>{lm.perplexity_test_smoothed}</b></td></tr>
            </tbody>
          </table>
          <p className="muted" style={{ marginTop: 8 }}>{lm.n_train_sentences} train / {lm.n_test_sentences} test sentences, vocabulary {lm.vocab_size}; {lm.test_sentences_with_zero_prob_unsmoothed} test sentences contain an unseen bigram.</p>
          <h3>Rarest alerts (highest perplexity → higher priority)</h3>
          <table><tbody>{ins.unit1.rarest_alerts.slice(0, 6).map((r) => <tr key={r.description}><td>{r.description}</td><td className="num">{r.rarity_score}</td></tr>)}</tbody></table>
        </div>

        <div className="card unit-card">
          <h2>Unit I <small>Alert types merged by edit distance</small></h2>
          <p className="muted">{ins.unit1.n_descriptions} distinct descriptions → {ins.unit1.n_alert_types} alert types (normalised, then merged when distance / length ≤ 0.2).</p>
          <div className="table-wrap" style={{ maxHeight: 360 }}>
            <table>
              <thead><tr><th>Alert type</th><th className="num">Alerts</th><th>Merged variants</th></tr></thead>
              <tbody>{ins.unit1.alert_types.map((t) => (
                <tr key={t.label}><td className="mono">{t.label}</td><td className="num">{t.count.toLocaleString()}</td>
                  <td className="muted">{t.members.length > 1 ? t.members.slice(1).join(' | ') : '–'}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="card unit-card">
          <h2>Unit III <small>Nearest neighbours (PPMI co-occurrence vectors)</small></h2>
          <div className="table-wrap" style={{ maxHeight: 340 }}>
            <table><tbody>{Object.entries(ins.unit3.neighbours_ppmi).map(([w, ns]) => (
              <tr key={w}><td className="mono">{w}</td><td>{ns.map((n) => <span key={n.word} className="chip">{n.word} {n.cosine}</span>)}</td></tr>
            ))}</tbody></table>
          </div>
        </div>
        <div className="card unit-card">
          <h2>Unit IV <small>Top PMI word pairs</small></h2>
          <p className="muted">PMI = log₂ P(x,y) / (P(x)P(y)) over unique sentences (pairs seen ≥ 3 times).</p>
          <div className="table-wrap" style={{ maxHeight: 300 }}>
            <table><thead><tr><th>w1</th><th>w2</th><th className="num">PMI</th><th className="num">count</th></tr></thead>
              <tbody>{u4.pmi_pairs.map((p, i) => <tr key={i}><td className="mono">{p.w1}</td><td className="mono">{p.w2}</td><td className="num">{p.pmi}</td><td className="num">{p.count}</td></tr>)}</tbody></table>
          </div>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="card unit-card">
          <h2>Unit IV <small>Word embeddings — 2-D PCA</small></h2>
          <p className="muted">PPMI word vectors projected with PCA; words used in similar contexts land close together. Hover for every word.</p>
          <div style={{ height: 340 }}>
            <ResponsiveContainer>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid stroke="#263344" />
                <XAxis type="number" dataKey="x" name="PC1" {...axis} />
                <YAxis type="number" dataKey="y" name="PC2" {...axis} />
                <ZAxis range={[60, 60]} />
                <Tooltip content={<PointTip field="word" />} />
                <Scatter data={u4.word_pca} fill={CATEGORICAL[0]} stroke="#121a24" strokeWidth={1}>
                  <LabelList dataKey="word" position="top" fontSize={10} fill="#a9b6c6"
                    content={(p) => labelled.has(p.value) ? <text x={p.x} y={p.y - 6} fontSize={10} fill="#a9b6c6" textAnchor="middle">{p.value}</text> : null} />
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card unit-card">
          <h2>Unit IV <small>Alert vectors by cluster — 2-D SVD</small></h2>
          <p className="muted">Unique TF-IDF alert patterns, coloured by KMeans cluster (k = {u4.k}, silhouette {u4.silhouette}).</p>
          <div style={{ height: 300 }}>
            <ResponsiveContainer>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid stroke="#263344" />
                <XAxis type="number" dataKey="x" {...axis} />
                <YAxis type="number" dataKey="y" {...axis} />
                <ZAxis range={[64, 64]} />
                <Tooltip content={<PointTip field="text" />} />
                {byCluster.map((pts, c) => <Scatter key={c} name={`cluster ${c}`} data={pts} fill={clusterColor(c)} stroke="#121a24" strokeWidth={1} />)}
                {other.length > 0 && <Scatter name="other" data={other} fill="#6b7280" stroke="#121a24" strokeWidth={1} />}
              </ScatterChart>
            </ResponsiveContainer>
          </div>
          <div className="legend">
            {Object.entries(u4.cluster_keywords).map(([c, kw]) => (
              <span key={c}><span className="dot" style={{ background: Number(c) < 8 ? clusterColor(Number(c)) : '#6b7280' }} />{c}: {kw.slice(0, 3).join(' ')}</span>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="card unit-card">
          <h2>Unit IV <small>Choosing k by silhouette</small></h2>
          <div style={{ height: 220 }}>
            <ResponsiveContainer>
              <LineChart data={u4.k_scores} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
                <CartesianGrid stroke="#263344" vertical={false} />
                <XAxis dataKey="k" stroke="#73839a" fontSize={11} />
                <YAxis stroke="#73839a" fontSize={11} domain={['auto', 'auto']} />
                <Tooltip content={({ active, payload }) => active && payload?.length ? <div className="chart-tooltip">k = {payload[0].payload.k}: silhouette {payload[0].value}</div> : null} />
                <Line dataKey="silhouette" stroke={CATEGORICAL[0]} strokeWidth={2} dot={{ r: 4, fill: CATEGORICAL[0], stroke: '#121a24', strokeWidth: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <p className="muted">Chosen k = {u4.k}. Purity vs attack-phase labels: clusters {u4.purity_clusters ?? 'n/a'}, incidents {u4.purity_incidents ?? 'n/a'}.</p>
        </div>
        <div className="card unit-card">
          <h2>Unit V <small>Temporal links between incidents (TimeBank-style)</small></h2>
          <div className="table-wrap" style={{ maxHeight: 260 }}>
            <table><tbody>{ins.unit5.temporal_links.map((l, i) => (
              <tr key={i}><td>{l.a}</td><td><span className="chip">{l.relation}</span></td><td>{l.b}</td></tr>
            ))}</tbody></table>
          </div>
          <p className="muted">Phases: {ins.phase_method}{ins.scenario ? ` (scenario ${ins.scenario})` : ''}.</p>
        </div>
      </div>
    </>
  )
}
