// Layout: sidebar navigation + routed pages.
import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import AnalysisView from './pages/AnalysisView'
import IncidentDetail from './pages/IncidentDetail'
import NlpLab from './pages/NlpLab'
import Evaluation from './pages/Evaluation'
import About from './pages/About'

const NAV = [
  { to: '/', label: 'Dashboard', icon: '▦' },
  { to: '/lab', label: 'NLP Lab', icon: '⚗' },
  { to: '/evaluation', label: 'Evaluation', icon: '✓' },
  { to: '/about', label: 'About', icon: 'ⓘ' },
]

export default function App() {
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <img src="/favicon.svg" width="28" height="28" alt="" />
          <div>Alert Summarizer<small>NLP for SOC analysts</small></div>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'}>
              <span className="icon" aria-hidden>{n.icon}</span>{n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">Runs locally · Data: AIT-ADS (CC BY 4.0)</div>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analysis/:id" element={<AnalysisView />} />
          <Route path="/incident/:id" element={<IncidentDetail />} />
          <Route path="/lab" element={<NlpLab />} />
          <Route path="/evaluation" element={<Evaluation />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<div className="card">Page not found. <NavLink to="/">Go to dashboard</NavLink></div>} />
        </Routes>
      </main>
    </div>
  )
}
