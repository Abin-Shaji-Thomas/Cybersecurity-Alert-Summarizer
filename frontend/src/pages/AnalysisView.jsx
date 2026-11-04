// Analysis view: one uploaded file, with tabs for incidents, timeline, entities/relations and Q&A.
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, errorText } from '../api'
import { ErrorBox, Loading, StatCard, Tabs } from '../components/Common'
import IncidentsTab from '../components/IncidentsTab'
import TimelineTab from '../components/TimelineTab'
import EntitiesTab from '../components/EntitiesTab'
import AskTab from '../components/AskTab'

const TABS = [
  { key: 'incidents', label: 'Incidents' },
  { key: 'timeline', label: 'Timeline' },
  { key: 'entities', label: 'Entities & Relations' },
  { key: 'ask', label: 'Ask' },
]

export default function AnalysisView() {
  const { id } = useParams()
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('incidents')

  useEffect(() => {
    let timer
    const load = () =>
      api.getAnalysis(id)
        .then((a) => {
          setAnalysis(a)
          setError(null)
          if (a.status === 'processing') timer = setTimeout(load, 1500)  // poll until done
        })
        .catch((e) => setError(errorText(e)))
    load()
    return () => clearTimeout(timer)
  }, [id])

  if (error) return <ErrorBox error={error} />
  if (!analysis) return <Loading />

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted"><Link to="/">Dashboard</Link> / analysis #{analysis.id}</div>
          <h1>{analysis.filename}</h1>
          <div className="subtle">
            {analysis.scenario ? `AIT-ADS scenario “${analysis.scenario}” detected · ` : ''}uploaded {analysis.uploaded_at?.replace('T', ' ').slice(0, 19)} UTC
          </div>
        </div>
        <Link className="btn" to={`/lab?analysis=${analysis.id}`}>Open in NLP Lab</Link>
      </div>

      {analysis.status === 'processing' && <div className="notice info"><Loading text="Running the NLP pipeline… this page refreshes automatically." /></div>}
      {analysis.status === 'failed' && <ErrorBox error={`Analysis failed: ${analysis.error}`} />}

      {analysis.status === 'done' && (
        <>
          <div className="stats">
            <StatCard label="Alerts" value={analysis.n_alerts?.toLocaleString()} />
            <StatCard label="Alert types" value={analysis.n_alert_types} />
            <StatCard label="Incidents" value={analysis.n_incidents} />
            <StatCard label="High / Critical" value={analysis.n_high} />
            <StatCard label="Bigram perplexity" value={analysis.perplexity_smoothed}
              hint={`held-out, Laplace · unsmoothed: ${analysis.perplexity_unsmoothed}`} />
          </div>
          <Tabs tabs={TABS} active={tab} onChange={setTab} />
          {tab === 'incidents' && <IncidentsTab analysisId={id} />}
          {tab === 'timeline' && <TimelineTab analysisId={id} />}
          {tab === 'entities' && <EntitiesTab analysisId={id} />}
          {tab === 'ask' && <AskTab analysisId={id} />}
        </>
      )}
    </>
  )
}
