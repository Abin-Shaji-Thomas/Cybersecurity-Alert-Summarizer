// A simple two-column SVG graph: subjects (attackers/users) on the left, objects (hosts/ports/root) on the right.
// Edge colour = relation type (with legend); edge width grows with the number of supporting alerts.
import { useState } from 'react'

const REL_COLORS = { ATTACKED: '#d95926', SCANNED: '#3987e5', LOGGED_INTO: '#199e70', ESCALATED_TO: '#c98500' }

export default function RelationGraph({ relations, maxEdges = 24 }) {
  const [hover, setHover] = useState(null)
  const edges = relations.filter((r) => REL_COLORS[r.relation]).slice(0, maxEdges)
  if (!edges.length) return <p className="subtle">No attacker/host relations were extracted.</p>

  const left = [...new Set(edges.map((e) => e.subject))]
  const right = [...new Set(edges.map((e) => e.object))]
  const rowH = 26
  const height = Math.max(left.length, right.length) * rowH + 20
  const W = 560, xL = 150, xR = W - 150
  const yOf = (list, v) => 16 + list.indexOf(v) * rowH + ((Math.max(left.length, right.length) - list.length) * rowH) / 2
  const maxCount = Math.max(...edges.map((e) => e.count))

  return (
    <>
      <div className="legend">
        {Object.entries(REL_COLORS).filter(([k]) => edges.some((e) => e.relation === k)).map(([k, c]) => (
          <span key={k}><span className="dot" style={{ background: c }} />{k}</span>
        ))}
      </div>
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" role="img" aria-label="Relation graph">
        {edges.map((e, i) => {
          const y1 = yOf(left, e.subject), y2 = yOf(right, e.object)
          const active = hover === null || hover === i
          return (
            <g key={i} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <path d={`M${xL},${y1} C${(xL + xR) / 2},${y1} ${(xL + xR) / 2},${y2} ${xR},${y2}`}
                fill="none" stroke={REL_COLORS[e.relation]} strokeOpacity={active ? 0.9 : 0.15}
                strokeWidth={1.5 + 3 * Math.sqrt(e.count / maxCount)} />
              {/* wide invisible path = bigger hover target */}
              <path d={`M${xL},${y1} C${(xL + xR) / 2},${y1} ${(xL + xR) / 2},${y2} ${xR},${y2}`} fill="none" stroke="transparent" strokeWidth={10}>
                <title>{`${e.subject} ${e.relation} ${e.object} (${e.count} alerts)`}</title>
              </path>
            </g>
          )
        })}
        {left.map((n) => (
          <g key={'l' + n}>
            <circle cx={xL} cy={yOf(left, n)} r={5} fill="#e6edf3" stroke="#121a24" strokeWidth={2} />
            <text x={xL - 10} y={yOf(left, n) + 4} textAnchor="end" fontSize={11} fill="#e6edf3" fontFamily="Consolas, monospace">{n.slice(0, 22)}</text>
          </g>
        ))}
        {right.map((n) => (
          <g key={'r' + n}>
            <circle cx={xR} cy={yOf(right, n)} r={5} fill="#e6edf3" stroke="#121a24" strokeWidth={2} />
            <text x={xR + 10} y={yOf(right, n) + 4} fontSize={11} fill="#e6edf3" fontFamily="Consolas, monospace">{n.slice(0, 22)}</text>
          </g>
        ))}
      </svg>
      {hover !== null && <div className="muted">{edges[hover].subject} <b>{edges[hover].relation}</b> {edges[hover].object} — {edges[hover].count} alerts</div>}
    </>
  )
}
