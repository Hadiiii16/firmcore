import { useState, type MouseEvent } from 'react'
import { RefreshCw, Bot, ChevronDown, ChevronRight, FastForward } from 'lucide-react'
import { SeverityBadge, VexBadge } from '../../components/Badge'
import type { CveResult, JobStatus } from '../../types'

interface VexAnalysisTabProps {
  cves: CveResult[]
  onRetryVexSingle: (cveId: string) => Promise<void>
  onResumeVexFrom: (cveId: string) => Promise<void>
  retryingCve: string | null
  resumingFromCve: string | null
  jobStatus: JobStatus | null
}

// Order within the table: urgent first, then deprioritised, then resolved.
// Affected w/ exploitability_tier === 'low' sorts *after* standard-affected
// since its patch priority is lower.
const VEX_ORDER = ['affected', 'affected_low', 'under_investigation', 'not_affected', 'fixed']

function vexOrder(cve: CveResult) {
  const key =
    cve.vex_status === 'affected' && cve.exploitability_tier === 'low'
      ? 'affected_low'
      : (cve.vex_status ?? '')
  const idx = VEX_ORDER.indexOf(key)
  return idx === -1 ? VEX_ORDER.length : idx
}

export function VexAnalysisTab({
  cves,
  onRetryVexSingle,
  onResumeVexFrom,
  retryingCve,
  resumingFromCve,
  jobStatus,
}: VexAnalysisTabProps) {
  const canRetry = jobStatus === 'completed' || jobStatus === 'failed' || jobStatus === 'vex_analyzing'
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const toggle = (cveId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(cveId)) next.delete(cveId)
      else next.add(cveId)
      return next
    })
  }

  const withVex = cves
    .filter((c) => c.vex_status && c.vex_status !== 'unknown')
    .sort((a, b) => vexOrder(a) - vexOrder(b))

  const noVex = cves.filter((c) => !c.vex_status || c.vex_status === 'unknown')

  if (cves.length === 0) {
    return (
      <div className="text-center py-16 text-gray-600 font-mono text-sm">
        No vulnerability data available.
      </div>
    )
  }

  function RetryButton({ cveId }: { cveId: string }) {
    const isThis = retryingCve === cveId
    const isBusy = retryingCve !== null || resumingFromCve !== null
    return (
      <button
        onClick={(e) => { e.stopPropagation(); void onRetryVexSingle(cveId) }}
        disabled={isBusy || !canRetry}
        title={canRetry ? `${cveId} VEX 분석 재실행` : '분석 완료 후 사용 가능'}
        className="flex items-center gap-1 px-2 py-1 rounded text-xs font-mono bg-surface-800 text-gray-500 border border-surface-600 hover:bg-cyan-900/40 hover:text-accent-cyan hover:border-cyan-700/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
      >
        <RefreshCw size={11} className={isThis ? 'animate-spin' : ''} />
        {isThis ? 'Analyzing…' : 'Re-analyze'}
      </button>
    )
  }

  function ResumeFromButton({ cveId }: { cveId: string }) {
    const isThis = resumingFromCve === cveId
    const isBusy = retryingCve !== null || resumingFromCve !== null
    const handleClick = (e: MouseEvent) => {
      e.stopPropagation()
      const ok = window.confirm(
        `${cveId} 부터 이어서 분석합니다.\n` +
        `${cveId} 와 그 이후 모든 CVE 의 기존 결과는 삭제되고 다시 분석됩니다.\n` +
        `이전 CVE 의 결과는 그대로 유지됩니다.\n\n계속하시겠습니까?`
      )
      if (ok) void onResumeVexFrom(cveId)
    }
    return (
      <button
        onClick={handleClick}
        disabled={isBusy || !canRetry}
        title={canRetry ? `${cveId} 부터 이어서 VEX 분석 (이후 CVE 모두 재분석)` : '분석 완료 후 사용 가능'}
        className="flex items-center gap-1 px-2 py-1 rounded text-xs font-mono bg-surface-800 text-gray-500 border border-surface-600 hover:bg-emerald-900/40 hover:text-emerald-300 hover:border-emerald-700/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
      >
        <FastForward size={11} className={isThis ? 'animate-pulse' : ''} />
        {isThis ? 'Resuming…' : 'Resume from here'}
      </button>
    )
  }

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="flex items-center justify-between gap-2 text-sm text-gray-400">
        <div className="flex items-center gap-2">
          <Bot size={15} className="text-accent-amber" />
          <span className="font-mono">
            {withVex.length} VEX statements generated · {noVex.length} without analysis
          </span>
        </div>
        {withVex.length > 0 && (
          <button
            onClick={() =>
              setExpanded((prev) =>
                prev.size === withVex.length ? new Set() : new Set(withVex.map((c) => c.cve_id)),
              )
            }
            className="text-xs font-mono text-gray-500 hover:text-accent-cyan transition-colors"
          >
            {expanded.size === withVex.length ? 'Collapse all' : 'Expand all'}
          </button>
        )}
      </div>

      {/* VEX rows — collapsed by default, click header to expand */}
      <div className="border border-surface-700 rounded-xl overflow-hidden divide-y divide-surface-800">
        {withVex.map((cve) => {
          const isOpen = expanded.has(cve.cve_id)
          return (
            <div key={cve.cve_id}>
              <button
                onClick={() => toggle(cve.cve_id)}
                className="w-full flex items-center gap-3 px-5 py-2.5 bg-surface-800/40 hover:bg-surface-800/70 transition-colors text-left"
              >
                {isOpen
                  ? <ChevronDown size={14} className="text-gray-500 shrink-0" />
                  : <ChevronRight size={14} className="text-gray-500 shrink-0" />}
                <SeverityBadge severity={cve.severity} />
                <span className="font-mono text-sm text-accent-cyan font-semibold">{cve.cve_id}</span>
                <span className="text-gray-500 text-xs font-mono truncate">
                  {cve.package_name} {cve.package_version}
                </span>
                <div className="ml-auto flex items-center gap-2 shrink-0">
                  <VexBadge status={cve.vex_status} tier={cve.exploitability_tier} />
                  <RetryButton cveId={cve.cve_id} />
                  <ResumeFromButton cveId={cve.cve_id} />
                </div>
              </button>

              {isOpen && (
                <div className="px-5 py-4 space-y-3 bg-surface-900">
                  {cve.description && (
                    <p className="text-sm text-gray-400">{cve.description}</p>
                  )}

                  {cve.vex_justification && (
                    <div className="bg-surface-950 rounded-lg px-4 py-3 border border-surface-700">
                      <p className="text-xs font-mono text-gray-500 mb-1 tracking-wider">JUSTIFICATION</p>
                      <p className="text-sm text-gray-300 font-mono">{cve.vex_justification}</p>
                    </div>
                  )}

                  {cve.vex_detail && (
                    <div className="bg-surface-950 rounded-lg px-4 py-3 border border-surface-700">
                      <p className="text-xs font-mono text-gray-500 mb-1 tracking-wider">ANALYSIS DETAIL</p>
                      <p className="text-sm text-gray-400 leading-relaxed whitespace-pre-wrap">{cve.vex_detail}</p>
                    </div>
                  )}

                  {cve.fix_version && (
                    <p className="text-xs font-mono text-gray-500">
                      Fixed in: <span className="text-accent-green">{cve.fix_version}</span>
                    </p>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* No VEX section */}
      {noVex.length > 0 && (
        <div className="border border-surface-700 rounded-xl overflow-hidden">
          <div className="px-5 py-3 bg-surface-800/40 border-b border-surface-700">
            <p className="text-xs font-mono text-gray-500 tracking-wider">
              NOT ANALYZED BY VEX AI ({noVex.length})
            </p>
          </div>
          <ul className="divide-y divide-surface-800">
            {noVex.map((cve) => (
              <li key={cve.cve_id} className="flex items-center gap-3 px-5 py-2.5">
                <SeverityBadge severity={cve.severity} />
                <span className="font-mono text-sm text-gray-400">{cve.cve_id}</span>
                <span className="text-xs text-gray-600 font-mono flex-1">{cve.package_name}</span>
                <RetryButton cveId={cve.cve_id} />
                <ResumeFromButton cveId={cve.cve_id} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
