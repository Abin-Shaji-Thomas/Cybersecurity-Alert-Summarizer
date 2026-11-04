// Incident cards sorted by severity, with a severity filter.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorText } from '../api'
import { ErrorBox, Loading, SeverityBadge } from './Common'
import { SEVERITY, fmtTime, fmtClock } from '../theme'

export default function IncidentsTab({ analysisId }) {
  const [incidents, setIncidents] = useState(null)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    api.incidents(analysisId).then(setIncidents).catch((e) => setError(errorText(e)))
  }, [analysisId])

  if (error) return <ErrorBox error={error} />
  if (!incidents) return <Loading />

  const counts = incidents.reduce((m, i) => ({ ...m, [i.severity]: (m[i.severity] || 0) + 1 }), {})
  const shown = filter === 'all' ? incidents : incidents.filter((i) => i.severity === filter)

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="muted">Show:</span>
        {['all', 'Critical', 'High', 'Medium', 'Low'].map((s) => (
          <button key={s} className={`btn-sm ${filter === s ? 'btn-primary' : ''}`} onClick={() => setFilter(s)}>
            {s === 'all' ? `All (${incidents.length})` : `${s} (${counts[s] || 0})`}
          </button>
        ))}
      </div>
      {shown.length === 0 && <p className="subtle">No incidents with this severity.</p>}
      <div className="grid grid-3">
        {shown.slice(0, 120).map((i) => (
          <Link key={i.id} to={`/incident/${i.id}`} className="card incident-card"
            style={{ borderLeftColor: SEVERITY[i.severity]?.color }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <SeverityBadge severity={i.severity} />
              <span className="muted">#{i.id} · {i.n_alerts.toLocaleString()} alerts</span>
            </div>
            <div className="title">{i.title}</div>
            <div className="muted">{fmtTime(i.start_time)} → {fmtClock(i.end_time)} UTC</div>
            <div style={{ margin: '6px 0' }}>{i.keywords?.split(', ').map((k) => <span key={k} className="chip">{k}</span>)}</div>
            <div className="clamp-2">{i.summary_template}</div>
          </Link>
        ))}
      </div>
      {shown.length > 120 && <p className="muted">Showing the 120 most severe of {shown.length} incidents.</p>}
    </>
  )
}
