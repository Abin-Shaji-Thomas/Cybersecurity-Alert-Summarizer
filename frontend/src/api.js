// All calls to the FastAPI backend live here.
import axios from 'axios'

export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const http = axios.create({ baseURL: API_BASE, timeout: 180000 })

// Turn any axios error into a readable message (FastAPI puts it in `detail`).
export function errorText(err) {
  if (err?.response?.data?.detail) return String(err.response.data.detail)
  if (err?.code === 'ERR_NETWORK') return `Cannot reach the backend at ${API_BASE}. Is it running (start.bat)?`
  return err?.message || 'Unknown error'
}

const get = (url, params) => http.get(url, { params }).then((r) => r.data)
const post = (url, body) => http.post(url, body).then((r) => r.data)

export const api = {
  health: () => get('/api/health'),
  listAnalyses: () => get('/api/analyses'),
  getAnalysis: (id) => get(`/api/analyses/${id}`),
  deleteAnalysis: (id) => http.delete(`/api/analyses/${id}`).then((r) => r.data),
  uploadFile: (file) => {
    const form = new FormData()
    form.append('file', file)
    return http.post('/api/analyses', form).then((r) => r.data)
  },
  analyseSample: () => post('/api/analyses/sample'),
  incidents: (id) => get(`/api/analyses/${id}/incidents`),
  timeline: (id, minLevel = 0) => get(`/api/analyses/${id}/timeline`, { min_level: minLevel }),
  entities: (id) => get(`/api/analyses/${id}/entities`),
  insights: (id) => get(`/api/analyses/${id}/insights`),
  ask: (id, question) => post(`/api/analyses/${id}/ask`, { question }),
  qaHistory: (id) => get(`/api/analyses/${id}/qa`),
  incident: (id) => get(`/api/incidents/${id}`),
  abstractive: (id) => post(`/api/incidents/${id}/abstractive`),
  pdfUrl: (id) => `${API_BASE}/api/incidents/${id}/pdf`,
  lab: (text, analysisId, ckyText) =>
    post('/api/lab/process', { text, analysis_id: analysisId || null, cky_text: ckyText || null }),
  evaluation: () => get('/api/evaluation'),
}
