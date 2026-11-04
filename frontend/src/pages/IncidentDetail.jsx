// Incident detail: template summary (main), extractive vs AI summary, slots, SRL roles, alerts, PDF.
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, errorText } from '../api'
import { ErrorBox, Loading, SeverityBadge } from '../components/Common'
import { fmtTime, phaseGroup } from '../theme'

const SLOT_ORDER = ['what_happened', 'attacker', 'users', 'targets', 'time_window', 'phases', 'severity',
  'mitre_techniques', 'mitre_tactics', 'keywords', 'top_rare_alerts', 'recommended_action']

export default function IncidentDetail() {
  const { id } = useParams()
  const [inc, setInc] = useState(null)
  const [error, setError] = useState(null)
  const [ai, setAi] = useState({ busy: false, error: null })

  useEffect(() => {
    setInc(null)
    api.incident(id).then(setInc).catch((e) => setError(errorText(e)))
  }, [id])

  const generate = async () => {
    setAi({ busy: true, error: null })
    try {
      const r = await api.abstractive(id)
      setInc((x) => ({ ...x, summary_abstractive: r.summary_abstractive }))
      setAi({ busy: false, error: null })
    } catch (e) {
      setAi({ busy: false, error: errorText(e) })
    }
  }

  if (error) return <ErrorBox error={error} />
  if (!inc) return <Loading />
  const s = inc.slots

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted"><Link to={`/analysis/${inc.analysis_id}`}>Analysis #{inc.analysis_id}</Link> / incident #{inc.id}</div>
          <h1>{inc.title}</h1>
          <div className="row"><SeverityBadge severity={inc.severity} /><span className="subtle">{s.time_window} · {inc.n_alerts.toLocaleString()} alerts</span></div>
        </div>
        <a className="btn btn-primary" href={api.pdfUrl(inc.id)} download>⬇ Download PDF</a>
      </div>

      <div className="card">
        <h3>Summary — template filling (main)</h3>
        <p className="summary-main">{inc.summary_template}</p>
      </div>

      <div className="card action-box">
        <h3>Recommended action</h3>
        <p style={{ margin: 0 }}>{inc.recommended_action}</p>
      </div>

      <div className="grid grid-2">
        <div className="card">
          <h3>Extractive summary <span className="muted">(sentences closest to the TF-IDF centroid)</span></h3>
          <p className="mono" style={{ whiteSpace: 'pre-line' }}>{inc.summary_extractive}</p>
        </div>
        <div className="card">
          <h3>AI summary <span className="muted">(pretrained distilbart-cnn-6-6, CPU)</span></h3>
          {inc.summary_abstractive && <p>{inc.summary_abstractive}</p>}
          {!inc.summary_abstractive && !ai.busy && <p className="subtle">Not generated yet. The first run loads the model (~10–20 s).</p>}
          {ai.busy && <Loading text="Generating with the pretrained model…" />}
          <ErrorBox error={ai.error} />
          <button disabled={ai.busy} onClick={generate}>{inc.summary_abstractive ? '↻ Regenerate' : '✦ Generate AI summary'}</button>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="card">
          <h2>Filled template slots</h2>
          <table className="kv"><tbody>
            {SLOT_ORDER.map((k) => (
              <tr key={k}><th>{k.replace(/_/g, ' ')}</th>
                <td>{Array.isArray(s[k]) ? s[k].map((v) => <span key={v} className="chip">{v}</span>) : String(s[k] ?? '–')}</td></tr>
            ))}
          </tbody></table>
        </div>
        <div className="card">
          <h2>Semantic roles <span className="muted">(rule-based SRL, most unusual alerts)</span></h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Agent</th><th>Action</th><th>Patient</th><th>Location</th><th>Time</th></tr></thead>
              <tbody>
                {inc.srl.map((r) => (
                  <tr key={r.alert_id} title={r.sentence}>
                    <td className="mono">{r.roles.Agent}</td><td>{r.roles.Action}</td><td className="mono">{r.roles.Patient || '–'}</td>
                    <td className="mono">{r.roles.Location}</td><td className="mono">{r.roles.Time.slice(11, 19)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h3 style={{ marginTop: 14 }}>Entities</h3>
          <div>{inc.entities.slice(0, 30).map((e) => <span key={e.text + e.label} className="chip" title={`${e.count} mentions`}>{e.text} <b>{e.label}</b></span>)}</div>
          {inc.relations.length > 0 && <>
            <h3 style={{ marginTop: 14 }}>Relations</h3>
            <ul className="muted" style={{ margin: 0, paddingLeft: 18 }}>
              {inc.relations.slice(0, 8).map((r, i) => <li key={i}><span className="mono">{r.subject}</span> <b>{r.relation}</b> <span className="mono">{r.object}</span> ({r.count})</li>)}
            </ul>
          </>}
        </div>
      </div>

      <div className="card">
        <h2>Related alerts <span className="muted">({inc.n_alerts_shown} of {inc.n_alerts} shown, time order)</span></h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time (UTC)</th><th>Source</th><th>Description</th><th>Src IP</th><th>Host</th><th className="num">Port</th><th className="num">Level</th><th className="num">Rarity</th><th>Phase</th></tr></thead>
            <tbody>
              {inc.alerts.map((a) => (
                <tr key={a.id} title={a.sentence}>
                  <td className="mono">{fmtTime(a.timestamp)}</td><td>{a.source}</td><td>{a.description}{a.url && <div className="muted mono">{a.url.slice(0, 70)}</div>}</td>
                  <td className="mono">{a.src_ip || a.user || '–'}</td><td className="mono">{a.host}</td><td className="num">{a.dst_port ?? '–'}</td>
                  <td className="num">{a.level}</td><td className="num">{a.rarity_score?.toFixed(1)}</td>
                  <td><span className="row" style={{ gap: 6 }}><span className="dot" style={{ background: phaseGroup(a.phase).color }} />{a.phase}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
