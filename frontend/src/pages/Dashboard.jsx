// Dashboard: upload (drag & drop) or sample, poll processing status, stats, history.
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, errorText } from '../api'
import { ErrorBox, Loading, StatCard } from '../components/Common'
import { fmtTime } from '../theme'

export default function Dashboard() {
  const [analyses, setAnalyses] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [drag, setDrag] = useState(false)
  const fileInput = useRef(null)
  const navigate = useNavigate()

  const load = useCallback(() => {
    api.listAnalyses().then((a) => { setAnalyses(a); setError(null) }).catch((e) => setError(errorText(e)))
  }, [])

  useEffect(() => { load() }, [load])

  // Poll while any analysis is still processing
  const processing = analyses?.some((a) => a.status === 'processing')
  useEffect(() => {
    if (!processing) return
    const t = setInterval(load, 1500)
    return () => clearInterval(t)
  }, [processing, load])

  const start = async (fn) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
      load()
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(false)
    }
  }

  const onFiles = (files) => {
    const f = files?.[0]
    if (f) start(() => api.uploadFile(f))
  }

  const remove = (id) => start(() => api.deleteAnalysis(id))

  const latest = analyses?.find((a) => a.status === 'done')

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <div className="subtle">Upload Wazuh / Suricata alerts and get incident summaries.</div>
        </div>
      </div>

      <ErrorBox error={error} onRetry={load} />

      <div className="grid grid-2">
        <div className="card">
          <h2>New analysis</h2>
          <div
            className={`dropzone ${drag ? 'drag' : ''}`}
            onClick={() => fileInput.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); onFiles(e.dataTransfer.files) }}
            role="button" tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && fileInput.current?.click()}
          >
            <div className="big">Drop an alert file here or click to choose</div>
            <div className="muted">.json (array) or .jsonl (one alert per line), up to 150 MB</div>
            <input ref={fileInput} type="file" accept=".json,.jsonl,.ndjson" hidden
              onChange={(e) => { onFiles(e.target.files); e.target.value = '' }} />
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn-primary" disabled={busy} onClick={() => start(api.analyseSample)}>
              ▶ Use sample data
            </button>
            <span className="muted">1,515 real alerts from the AIT-ADS “russellmitchell” attack day</span>
          </div>
          {busy && <Loading text="Uploading…" />}
        </div>

        <div className="card">
          <h2>Latest analysis {latest && <span className="muted">#{latest.id} · {latest.filename}</span>}</h2>
          {!analyses && !error && <Loading />}
          {analyses && !latest && <p className="subtle">No finished analysis yet. Try the sample data.</p>}
          {latest && (
            <>
              <div className="stats">
                <StatCard label="Alerts" value={latest.n_alerts?.toLocaleString()} hint="after de-duplication" />
                <StatCard label="Alert types" value={latest.n_alert_types} hint="merged by edit distance" />
                <StatCard label="Incidents" value={latest.n_incidents} hint="TF-IDF clusters + time gaps" />
                <StatCard label="High / Critical" value={latest.n_high} hint="incidents" />
              </div>
              <Link className="btn btn-primary" to={`/analysis/${latest.id}`}>Open analysis →</Link>
            </>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Recent analyses</h2>
        {analyses && analyses.length === 0 && <p className="subtle">Nothing here yet.</p>}
        {analyses && analyses.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>#</th><th>File</th><th>Uploaded (UTC)</th><th>Status</th><th className="num">Alerts</th>
                  <th className="num">Incidents</th><th className="num">High+</th><th>Scenario</th><th /></tr>
              </thead>
              <tbody>
                {analyses.map((a) => (
                  <tr key={a.id}>
                    <td>{a.id}</td>
                    <td>{a.status === 'done' ? <Link to={`/analysis/${a.id}`}>{a.filename}</Link> : a.filename}</td>
                    <td>{fmtTime(a.uploaded_at)}</td>
                    <td>
                      {a.status === 'processing' && <span className="row" style={{ gap: 6 }}><span className="spinner" /> processing</span>}
                      {a.status === 'done' && <span className="badge" style={{ borderColor: 'var(--ok)' }}>✓ done</span>}
                      {a.status === 'failed' && <span className="badge" style={{ borderColor: 'var(--danger)' }} title={a.error}>✕ failed</span>}
                      {a.status === 'failed' && <div className="muted" style={{ maxWidth: 320 }}>{a.error}</div>}
                    </td>
                    <td className="num">{a.n_alerts?.toLocaleString() ?? '–'}</td>
                    <td className="num">{a.n_incidents ?? '–'}</td>
                    <td className="num">{a.n_high ?? '–'}</td>
                    <td>{a.scenario || '–'}</td>
                    <td className="row" style={{ justifyContent: 'flex-end' }}>
                      {a.status === 'done' && <button className="btn-sm" onClick={() => navigate(`/analysis/${a.id}`)}>Open</button>}
                      <button className="btn-sm btn-danger" disabled={busy || a.status === 'processing'} onClick={() => remove(a.id)}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
