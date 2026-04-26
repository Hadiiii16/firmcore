import type { JobStatus } from '../types'

// ── StatusBadge ───────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<JobStatus, string> = {
  pending:        'bg-surface-600 text-gray-400',
  extracting:     'bg-blue-900/60 text-blue-300 animate-pulse',
  sbom_generating:'bg-cyan-900/60 text-cyan-300 animate-pulse',
  scanning:       'bg-purple-900/60 text-purple-300 animate-pulse',
  // 진행 중 VEX 는 "LIVE" 뱃지로 강조 — 녹색 + 깜빡이는 점으로 단순
  // ``VEX AI`` 라벨보다 "실시간 분석 중" 이라는 상태를 명확히 전달.
  vex_analyzing:  'bg-emerald-900/60 text-emerald-300 border border-emerald-600/50',
  completed:      'bg-green-900/60 text-accent-green',
  failed:         'bg-red-900/60 text-red-400',
}

const STATUS_LABELS: Record<JobStatus, string> = {
  pending:        'PENDING',
  extracting:     'EXTRACTING',
  sbom_generating:'SBOM GEN',
  scanning:       'SCANNING',
  vex_analyzing:  'LIVE VEX',
  completed:      'DONE',
  failed:         'FAILED',
}

export function StatusBadge({ status }: { status: JobStatus }) {
  const isLive = status === 'vex_analyzing'
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono font-semibold tracking-wider ${STATUS_STYLES[status]}`}
    >
      {isLive && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
        </span>
      )}
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

// ── ModelBadge ───────────────────────────────────────────────────────────────
// "이 CVE 판정을 어느 CLI/모델이 냈는지" 를 시각적으로 구분.  Pro 쿼터
// 소진 시 Auto 체인(Pro → Codex → Flash) 중 어느 단계가 실제로 응답했는지
// 한눈에 보이게 한다.
//   - gemini-*-pro*   → PRO   (보라) : 최고 품질, Gemini Pro
//   - gpt-*, o3*, codex-*, chatgpt-* → CODEX (에메랄드) : OpenAI Codex 폴백
//   - gemini-*-flash* → FLASH (청)  : 쿼터 절약, Gemini Flash
//   - 그 외 / 미지정   → AUTO  (회색)

function _modelKind(m: string): 'pro' | 'codex' | 'flash' | 'auto' {
  const s = m.toLowerCase()
  if (s.startsWith('gpt-') || s.startsWith('o3') || s.startsWith('codex-') || s.startsWith('chatgpt-')) return 'codex'
  if (s.includes('flash')) return 'flash'
  if (s.includes('pro')) return 'pro'
  return 'auto'
}

export function ModelBadge({ model }: { model: string | null | undefined }) {
  if (!model) return null
  const kind = _modelKind(model)
  const label = kind === 'pro' ? 'PRO' : kind === 'flash' ? 'FLASH' : kind === 'codex' ? 'CODEX' : 'AUTO'
  const cls =
    kind === 'pro'   ? 'bg-purple-900/50 text-purple-300 border border-purple-700/40'
    : kind === 'codex' ? 'bg-emerald-900/50 text-emerald-300 border border-emerald-700/40'
    : kind === 'flash' ? 'bg-cyan-900/40 text-cyan-300 border border-cyan-700/40'
    : 'bg-surface-700 text-gray-400 border border-surface-500'
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold tracking-wider ${cls}`}
      title={`분석에 사용된 모델: ${model}`}
    >
      {label}
    </span>
  )
}
