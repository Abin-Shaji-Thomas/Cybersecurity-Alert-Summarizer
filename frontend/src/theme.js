// Chart colours (dark mode steps of a validated categorical palette) and helpers.

// Attack phases are folded into 5 groups so the chart never needs more than 5 hues + gray.
export const PHASE_GROUPS = [
  { key: 'Recon', color: '#3987e5', phases: ['network_scans', 'service_scans', 'reconnaissance'] },
  { key: 'Web scanning', color: '#d95926', phases: ['wpscan', 'dirb'] },
  { key: 'Exploitation', color: '#199e70', phases: ['webshell', 'cracking', 'reverse_shell', 'initial_access', 'credential_access', 'lateral_movement'] },
  { key: 'Privilege escalation', color: '#c98500', phases: ['privilege_escalation'] },
  { key: 'Exfiltration', color: '#d55181', phases: ['service_stop', 'dnsteal', 'exfiltration'] },
  { key: 'Normal', color: '#6b7280', phases: ['normal'] },
]

export function phaseGroup(phase) {
  return PHASE_GROUPS.find((g) => g.phases.includes(phase)) || PHASE_GROUPS[PHASE_GROUPS.length - 1]
}

// Status colours are reserved for severity and always shown with a text label.
export const SEVERITY = {
  Low: { color: '#0ca30c', icon: '●' },
  Medium: { color: '#fab219', icon: '▲' },
  High: { color: '#ec835a', icon: '◆' },
  Critical: { color: '#d03b3b', icon: '■' },
}

// Categorical colours for clusters (fixed order; clusters past 8 fold to gray "other").
export const CATEGORICAL = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767']
export const clusterColor = (c) => CATEGORICAL[c] || '#6b7280'

export const fmtTime = (iso) => (iso ? iso.replace('T', ' ').slice(0, 19) : '')
export const fmtClock = (iso) => (iso ? iso.slice(11, 19) : '')
