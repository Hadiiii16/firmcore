import type { JobStatus } from '../types'

// ── StatusBadge ───────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<JobStatus, string> = {
  pending:        'bg-surface-600 text-gray-400',
  extracting:     'bg-blue-900/60 text-blue-300 animate-pulse',
  sbom_generating:'bg-cyan-900/60 text-cyan-300 animate-pulse',
  scanning:       'bg-purple-900/60 text-purple-300 animate-pulse',
  vex_analyzing:  'bg-amber-900/60 text-amber-300 animate-pulse',
  completed:      'bg-green-900/60 text-accent-green',
  failed:         'bg-red-900/60 text-red-400',
}

const STATUS_LABELS: Record<JobStatus, string> = {
  pending:        'PENDING',
  extracting:     'EXTRACTING',
  sbom_generating:'SBOM GEN',
  scanning:       'SCANNING',
  vex_analyzing:  'VEX AI',
  completed:      'DONE',
  failed:         'FAILED',
}

export function StatusBadge({ status }: { status: JobStatus }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold tracking-wider ${STATUS_STYLES[status]}`}
    >
      {STATUS_LABELS[status]}
    </span>
  )
}

// ── SeverityBadge ─────────────────────────────────────────────────────────────

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN'

const SEV_STYLES: Record<Severity, string> = {
  CRITICAL:   'bg-red-900/70 text-red-300 border border-red-700/50',
  HIGH:       'bg-orange-900/70 text-orange-300 border border-orange-700/50',
  MEDIUM:     'bg-yellow-900/70 text-yellow-300 border border-yellow-700/50',
  LOW:        'bg-blue-900/70 text-blue-300 border border-blue-700/50',
  NEGLIGIBLE: 'bg-surface-600 text-gray-400',
  UNKNOWN:    'bg-surface-600 text-gray-500',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold ${SEV_STYLES[severity]}`}
    >
      {severity}
    </span>
  )
}

// ── VexBadge ──────────────────────────────────────────────────────────────────

const VEX_STYLES: Record<string, string> = {
  not_affected:        'bg-green-900/60 text-accent-green border border-green-700/40',
  // affected + low:  orange (not-red, signalling reduced urgency)
  affected_low:        'bg-orange-900/60 text-orange-300 border border-orange-700/40',
  affected:            'bg-red-900/60 text-red-300 border border-red-700/40',
  fixed:               'bg-blue-900/60 text-blue-300 border border-blue-700/40',
  under_investigation: 'bg-amber-900/60 text-amber-300 border border-amber-700/40',
}

const VEX_LABELS: Record<string, string> = {
  not_affected:        'NOT AFFECTED',
  affected_low:        'AFFECTED · LOW',
  affected:            'AFFECTED',
  fixed:               'FIXED',
  under_investigation: 'INVESTIGATING',
}

export function VexBadge({
  status,
  tier,
}: {
  status: string | null
  tier?: 'low' | 'standard' | null
}) {
  if (!status) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono text-gray-500 bg-surface-600">
        NO VEX
      </span>
    )
  }
  // Affected + low-tier gets its own styling so users immediately see the
  // reduced urgency without having to open the analysis detail.
  const key = status === 'affected' && tier === 'low' ? 'affected_low' : status
  const style = VEX_STYLES[key] ?? 'bg-surface-600 text-gray-400'
  const label = VEX_LABELS[key] ?? status.toUpperCase()
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold ${style}`}
      title={
        key === 'affected_low'
          ? '컴파일 완화로 exploit 난이도가 높아 패치 우선순위를 낮출 수 있음'
          : undefined
      }
    >
      {label}
    </span>
  )
}
