// Small shared UI pieces: loading/error states, badges, stat cards, tabs, chart tooltip.
import { SEVERITY } from '../theme'

export function Loading({ text = 'Loading…' }) {
  return <div className="loading"><span className="spinner" /> {text}</div>
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null
  return (
    <div className="notice error row" role="alert">
      <span style={{ flex: 1 }}>{error}</span>
      {onRetry && <button className="btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function SeverityBadge({ severity }) {
  const s = SEVERITY[severity] || { color: '#6b7280', icon: '○' }
  return (
    <span className="badge" style={{ borderColor: s.color }}>
      <span style={{ color: s.color }} aria-hidden>{s.icon}</span>{severity || 'n/a'}
    </span>
  )
}

export function StatCard({ label, value, hint }) {
  return (
    <div className="stat">
      <div className="label">{label}</div>
      <div className="value">{value ?? '–'}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  )
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={active === t.key}
          className={active === t.key ? 'active' : ''} onClick={() => onChange(t.key)}>
          {t.label}
        </button>
      ))}
    </div>
  )
}

// Recharts custom tooltip: values in text colours, a colour dot carries series identity.
export function ChartTooltip({ active, payload, label, labelFormatter }) {
  if (!active || !payload?.length) return null
  const rows = payload.filter((p) => p.value)
  return (
    <div className="chart-tooltip">
      <div className="t">{labelFormatter ? labelFormatter(label) : label}</div>
      {rows.map((p) => (
        <div key={p.dataKey} className="row" style={{ gap: 6 }}>
          <span className="dot" style={{ background: p.color }} /> {p.name}: <b>{p.value}</b>
        </div>
      ))}
      {!rows.length && <div className="muted">no alerts</div>}
    </div>
  )
}
