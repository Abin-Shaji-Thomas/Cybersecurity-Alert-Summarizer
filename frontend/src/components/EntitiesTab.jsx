// Entity table (filter by NER label) + relation graph.
import { useEffect, useState } from 'react'
import { api, errorText } from '../api'
import { ErrorBox, Loading } from './Common'
import RelationGraph from './RelationGraph'

export default function EntitiesTab({ analysisId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [label, setLabel] = useState('')
  const [query, setQuery] = useState('')

  useEffect(() => {
    api.entities(analysisId).then(setData).catch((e) => setError(errorText(e)))
  }, [analysisId])

  if (error) return <ErrorBox error={error} />
  if (!data) return <Loading />

  const q = query.toLowerCase()
  const rows = data.entities.filter((e) => (!label || e.label === label) && (!q || e.text.toLowerCase().includes(q)))

  return (
    <div className="grid grid-2">
      <div className="card">
        <h2>Entities <span className="muted">(spaCy + security EntityRuler)</span></h2>
        <div className="row" style={{ marginBottom: 10 }}>
          <select value={label} onChange={(e) => setLabel(e.target.value)}>
            <option value="">All labels</option>
            {data.labels.map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <input type="text" placeholder="Search…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ flex: 1, width: 'auto' }} />
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Entity</th><th>Label</th><th className="num">Alerts</th></tr></thead>
            <tbody>
              {rows.slice(0, 300).map((e) => (
                <tr key={e.text + e.label}><td className="mono">{e.text}</td><td><span className="chip">{e.label}</span></td><td className="num">{e.n_alerts.toLocaleString()}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        {rows.length === 0 && <p className="subtle">No entities match.</p>}
      </div>

      <div className="card">
        <h2>Relations <span className="muted">(rule-based on NER + dependency triples)</span></h2>
        <RelationGraph relations={data.relations} />
        <div className="table-wrap" style={{ maxHeight: 260, marginTop: 10 }}>
          <table>
            <thead><tr><th>Subject</th><th>Relation</th><th>Object</th><th className="num">Alerts</th></tr></thead>
            <tbody>
              {data.relations.slice(0, 100).map((r, i) => (
                <tr key={i}><td className="mono">{r.subject}</td><td><span className="chip">{r.relation}</span></td><td className="mono">{r.object}</td><td className="num">{r.count}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
