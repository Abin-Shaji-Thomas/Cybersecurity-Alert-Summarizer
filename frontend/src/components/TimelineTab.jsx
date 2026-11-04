// Attack timeline: stacked bars of alerts per time bucket by phase group + ordered event list.
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, errorText } from '../api'
import { ChartTooltip, ErrorBox, Loading } from './Common'
import { PHASE_GROUPS, fmtClock, fmtTime, phaseGroup } from '../theme'

export default function TimelineTab({ analysisId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [minLevel, setMinLevel] = useState(0)
  const [hideNormal, setHideNormal] = useState(false)

  useEffect(() => {
    setData(null)
    api.timeline(analysisId, minLevel).then(setData).catch((e) => setError(errorText(e)))
  }, [analysisId, minLevel])

  // Sum the raw phases of each bucket into the 5 phase groups (+ Normal)
  const series = useMemo(() => {
    if (!data) return []
    return data.series.map((row) => {
      const out = { time: row.time }
      for (const p of data.phases) {
        const g = phaseGroup(p).key
        out[g] = (out[g] || 0) + (row[p] || 0)
      }
      return out
    })
  }, [data])

  if (error) return <ErrorBox error={error} />
  if (!data) return <Loading />

  const groups = PHASE_GROUPS.filter((g) => series.some((r) => r[g.key]) && !(hideNormal && g.key === 'Normal'))
  const events = hideNormal ? data.events.filter((e) => e.phase !== 'normal') : data.events
  const fmtTick = (t) => (data.bucket === '1h' ? t.slice(5, 13).replace('T', ' ') + 'h' : fmtClock(t).slice(0, 5))

  return (
    <>
      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2>Alerts over time <span className="muted">({data.bucket} buckets, coloured by attack phase)</span></h2>
          <label className="row muted"><input type="checkbox" checked={hideNormal} onChange={(e) => setHideNormal(e.target.checked)} /> hide normal</label>
        </div>
        <div style={{ width: '100%', height: 300 }}>
          <ResponsiveContainer>
            <BarChart data={series} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke="#263344" strokeDasharray="0" vertical={false} />
              <XAxis dataKey="time" tickFormatter={fmtTick} stroke="#73839a" fontSize={11} minTickGap={24} />
              <YAxis stroke="#73839a" fontSize={11} allowDecimals={false} />
              <Tooltip content={<ChartTooltip labelFormatter={(t) => `${fmtTime(t)} UTC`} />} cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
              <Legend wrapperStyle={{ fontSize: 12, color: '#a9b6c6' }} />
              {groups.map((g, i) => (
                <Bar key={g.key} dataKey={g.key} stackId="a" fill={g.color} stroke="#121a24" strokeWidth={1}
                  radius={i === groups.length - 1 ? [3, 3, 0, 0] : 0} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
        <p className="muted">Phases come from {`AIT-ADS labels.csv time windows when the data is from AIT-ADS, otherwise from MITRE tactics.`}</p>
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <h2>Ordered events <span className="muted">(consecutive identical alerts merged · {data.n_events.toLocaleString()} events)</span></h2>
          <label className="row muted">min level
            <select value={minLevel} onChange={(e) => setMinLevel(Number(e.target.value))}>
              {[0, 3, 5, 7, 10].map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
          </label>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Start (UTC)</th><th>End</th><th className="num">Count</th><th>Alert</th><th>Actor</th><th>Target</th><th className="num">Level</th><th>Phase</th><th>Incident</th></tr></thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i}>
                  <td className="mono">{fmtTime(e.start)}</td>
                  <td className="mono">{fmtClock(e.end)}</td>
                  <td className="num">{e.count}</td>
                  <td>{e.description}</td>
                  <td className="mono">{e.actor || '–'}</td>
                  <td className="mono">{e.target}</td>
                  <td className="num">{e.level}</td>
                  <td><span className="row" style={{ gap: 6 }}><span className="dot" style={{ background: phaseGroup(e.phase).color }} />{e.phase}</span></td>
                  <td><Link to={`/incident/${e.incident_id}`}>#{e.incident_id}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data.n_events > data.events.length && <p className="muted">Showing the first {data.events.length} events; raise the minimum level to focus.</p>}
      </div>
    </>
  )
}
