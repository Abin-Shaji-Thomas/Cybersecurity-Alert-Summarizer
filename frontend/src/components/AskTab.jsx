// Chat UI for the QA module: answer + the supporting alerts found by TF-IDF retrieval.
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, errorText } from '../api'
import { fmtTime } from '../theme'

const SUGGESTIONS = [
  'Which hosts did 172.19.131.174 attack?',
  'Which IPs attacked us?',
  'When did the attack start?',
  'What MITRE techniques were seen?',
  'How many failed logins were there?',
  'Which users logged in?',
  'What is the most severe incident?',
  'What should I do next?',
]

export default function AskTab({ analysisId }) {
  const [messages, setMessages] = useState([])
  const [question, setQuestion] = useState('')
  const [busy, setBusy] = useState(false)
  const end = useRef(null)

  useEffect(() => { end.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) }, [messages])

  const ask = async (q) => {
    const text = (q ?? question).trim()
    if (!text || busy) return
    setQuestion('')
    setMessages((m) => [...m, { role: 'user', text }])
    setBusy(true)
    try {
      const r = await api.ask(analysisId, text)
      setMessages((m) => [...m, { role: 'bot', text: r.answer, intent: r.intent, support: r.supporting_alerts }])
    } catch (e) {
      setMessages((m) => [...m, { role: 'bot', text: `Error: ${errorText(e)}`, support: [] }])
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card">
      <h2>Ask about this analysis</h2>
      <div className="row" style={{ marginBottom: 12 }}>
        {SUGGESTIONS.map((s) => <button key={s} className="btn-sm" disabled={busy} onClick={() => ask(s)}>{s}</button>)}
      </div>
      <div className="chat">
        {messages.length === 0 && <p className="subtle">Ask a question in plain English. Answers come from rules over the extracted entities/relations; evidence comes from TF-IDF retrieval over the alert sentences.</p>}
        {messages.map((m, i) => (
          <div key={i} className={`msg ${m.role}`}>
            <div>{m.text}</div>
            {m.intent && <div className="muted" style={{ marginTop: 4 }}>intent: {m.intent}</div>}
            {m.support?.length > 0 && (
              <div className="support">
                <div className="muted">Supporting alerts:</div>
                <ul>
                  {m.support.map((a) => (
                    <li key={a.id}>{fmtTime(a.timestamp)} · {a.sentence} <Link to={`/incident/${a.incident_id}`}>#{a.incident_id}</Link></li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ))}
        {busy && <div className="msg bot"><span className="spinner" /> thinking…</div>}
        <div ref={end} />
      </div>
      <form className="row" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); ask() }}>
        <input type="text" value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="e.g. Which ports were targeted?" style={{ flex: 1, width: 'auto' }} maxLength={500} />
        <button className="btn-primary" disabled={busy || !question.trim()}>Ask</button>
      </form>
    </div>
  )
}
