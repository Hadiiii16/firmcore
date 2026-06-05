import { useMemo, useState, type MouseEvent } from 'react'
import { RefreshCw, Bot, ChevronDown, ChevronRight, FastForward, Zap, Gem } from 'lucide-react'
import { SeverityBadge, VexBadge, ModelBadge, EvidenceBadge } from '../../components/Badge'
import type { CveResult, JobStatus } from '../../types'

interface VexAnalysisTabProps {
  cves: CveResult[]
  // ``model`` 옵션으로 Gemini 모델 명시 선택 (Pro/Flash).  미지정 시
  // 기본 정책(Pro → Flash 자동 폴백) 으로 백엔드에서 처리.
  onRetryVexSingle: (cveId: string, model?: string) => Promise<void>
  onResumeVexFrom: (cveId: string) => Promise<void>
  retryingCve: string | null
  resumingFromCve: string | null
  jobStatus: JobStatus | null
}

// 기본 정렬은 severity — 백엔드 ``_select_cves_for_vex`` 와 동일해야
// Resume from here 인덱스가 일치한다.  사용자가 sort dropdown 으로
// vex / cve 를 선택하면 그때만 다른 기준 사용.
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']
// GEMINI.md v5.0 위험도 정렬:
// affected_b (가장 시급) → affected_c → affected_d → investigating → not_affected → fixed
const VEX_ORDER = [
  'affected_a',          // exploit 시연 (사실상 발행 X)
  'affected_b',          // 일반 affected, 패치 시급
  'affected_c',          // 도달 가능, 완화 충족
  'affected_d',          // 잠재 위험, 노출 증거 부재
  'affected',            // grade 없는 affected (legacy / 누락)
  'under_investigation',
  'not_affected',
  'fixed',
]

type SortKey = 'severity' | 'vex' | 'cve'
type VexFilter =
  | 'all'
  | 'affected_b'
  | 'affected_c'
  | 'affected_d'
  | 'not_affected'
  | 'under_investigation'
  | 'fixed'
  | 'unknown'

function vexKey(c: CveResult): string {
  if (c.vex_status === 'affected') {
    const g = (c.analysis_grade || '').toUpperCase()
    if (g === 'A' || g === 'B' || g === 'C' || g === 'D') return `affected_${g.toLowerCase()}`
    return 'affected'
  }
  return c.vex_status ?? ''
}

function sortCves(list: CveResult[], key: SortKey): CveResult[] {
  return [...list].sort((a, b) => {
    if (key === 'vex') {
      const va = VEX_ORDER.indexOf(vexKey(a))
      const vb = VEX_ORDER.indexOf(vexKey(b))
      const ai = va === -1 ? VEX_ORDER.length : va
      const bi = vb === -1 ? VEX_ORDER.length : vb
      if (ai !== bi) return ai - bi
      return SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    }
    if (key === 'cve') {
      return a.cve_id.localeCompare(b.cve_id)
    }
    return SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  })
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
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [vexFilter, setVexFilter] = useState<VexFilter>('all')

  const toggle = (cveId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(cveId)) next.delete(cveId)
      else next.add(cveId)
      return next
    })
  }

  // VEX 상태별 카운트 (한 번만 계산).  affected 는 GRADE 별로 세분화.
  const stats = useMemo(() => {
    const s = {
      total: cves.length,
      affected_b: 0,         // 일반 affected
      affected_c: 0,         // 완화 충족
      affected_d: 0,         // 잠재 위험
      affected_a: 0,         // 사실상 0
      affected_other: 0,     // grade 없는 legacy affected
      not_affected: 0,
      under_investigation: 0,
      fixed: 0,
      unknown: 0,            // 분석 미실행
    }
    for (const c of cves) {
      if (!c.vex_status || c.vex_status === 'unknown') { s.unknown++; continue }
      if (c.vex_status === 'affected') {
        const g = (c.analysis_grade || '').toUpperCase()
        if (g === 'A') s.affected_a++
        else if (g === 'B') s.affected_b++
        else if (g === 'C') s.affected_c++
        else if (g === 'D') s.affected_d++
        else s.affected_other++
      } else if (c.vex_status === 'not_affected') s.not_affected++
      else if (c.vex_status === 'under_investigation') s.under_investigation++
      else if (c.vex_status === 'fixed') s.fixed++
    }
    return s
  }, [cves])

  const analyzed = stats.total - stats.unknown
  const coverage = stats.total > 0 ? Math.round((analyzed / stats.total) * 100) : 0

  const matchesFilter = (c: CveResult): boolean => {
    if (vexFilter === 'all') return true
    if (vexFilter === 'unknown') {
      return !c.vex_status || c.vex_status === 'unknown'
    }
    // affected_b pill 은 GRADE B 외에 grade 가 없는 affected (legacy/누락)
    // 와 사실상 발행 안 되는 GRADE A 도 함께 묶어 표시한다.
    if (vexFilter === 'affected_b') {
      if (c.vex_status !== 'affected') return false
      const g = (c.analysis_grade || '').toUpperCase()
      return g === '' || g === 'A' || g === 'B'
    }
    if (vexFilter === 'affected_c' || vexFilter === 'affected_d') {
      return vexKey(c) === vexFilter
    }
    return c.vex_status === vexFilter
  }

  const withVex = sortCves(
    cves.filter((c) => c.vex_status && c.vex_status !== 'unknown' && matchesFilter(c)),
    sortKey,
  )
  const noVex = sortCves(
    cves.filter((c) => (!c.vex_status || c.vex_status === 'unknown') && (vexFilter === 'all' || vexFilter === 'unknown')),
    sortKey,
  )

  if (cves.length === 0) {
    return (
      <div className="text-center py-16 text-gray-600 font-mono text-sm">
        No vulnerability data available.
      </div>
    )
  }

  // 필터 pill 정의.  affected 는 GRADE 별로 세분화된 3개 pill.  legacy
  // affected (grade=null) 는 affected_b 카운트에 합쳐져 표시되지 않으므로
  // 사용자에겐 D/C/B 만 노출 (분석 미완료 + 신규 잡 정상 흐름).
  const filterPills: Array<{ key: VexFilter; label: string; count: number; active: string; inactive: string }> = [
    { key: 'all',                 label: 'ALL',          count: stats.total,                active: 'bg-surface-700 text-gray-100 border-surface-500',  inactive: 'bg-surface-800/60 text-gray-400 border-surface-700 hover:bg-surface-700/60' },
    { key: 'affected_b',          label: 'AFF·B',        count: stats.affected_b + stats.affected_other + stats.affected_a, active: 'bg-red-900/60 text-red-200 border-red-700',         inactive: 'bg-red-900/15 text-red-400 border-red-900/40 hover:bg-red-900/30' },
    { key: 'affected_c',          label: 'AFF·C',        count: stats.affected_c,           active: 'bg-orange-900/60 text-orange-200 border-orange-700', inactive: 'bg-orange-900/15 text-orange-400 border-orange-900/40 hover:bg-orange-900/30' },
    { key: 'affected_d',          label: 'AFF·D',        count: stats.affected_d,           active: 'bg-yellow-900/60 text-yellow-200 border-yellow-700', inactive: 'bg-yellow-900/15 text-yellow-400 border-yellow-900/40 hover:bg-yellow-900/30' },
    { key: 'not_affected',        label: 'NOT AFFECTED', count: stats.not_affected,         active: 'bg-green-900/60 text-green-200 border-green-700',   inactive: 'bg-green-900/15 text-accent-green border-green-900/40 hover:bg-green-900/30' },
    { key: 'under_investigation', label: 'INVESTIGATING', count: stats.under_investigation, active: 'bg-amber-900/60 text-amber-200 border-amber-700',   inactive: 'bg-amber-900/15 text-amber-400 border-amber-900/40 hover:bg-amber-900/30' },
    { key: 'fixed',               label: 'FIXED',        count: stats.fixed,                active: 'bg-blue-900/60 text-blue-200 border-blue-700',      inactive: 'bg-blue-900/15 text-blue-400 border-blue-900/40 hover:bg-blue-900/30' },
    { key: 'unknown',             label: 'UNANALYZED',   count: stats.unknown,              active: 'bg-surface-700 text-gray-100 border-surface-500',   inactive: 'bg-surface-800/60 text-gray-500 border-surface-700 hover:bg-surface-700/60' },
  ]

  // Re-analyze 는 Pro / Codex / Flash 3가지 엔진·모델 선택 가능한 분리 버튼.
  // - Pro 버튼   : Gemini 3 Pro.  품질 우선, 쿼터 많이 씀.  Flash 로 분석된
  //                CVE 를 Pro 로 업그레이드할 때 주로 사용.
  // - Codex 버튼 : OpenAI gpt-5-codex.  Gemini Pro 쿼터가 나갔거나 Codex
  //                구독 쿼터를 활용하고 싶을 때.  read-only 샌드박스로 동작.
  // - Flash 버튼 : Gemini 3 Flash.  빠르고 쿼터 절약.  간단한 판정을 빠르게
  //                재확인할 때.
  // 모델 문자열의 prefix(gemini-*/gpt-*) 로 백엔드가 자동 엔진 라우팅.
  function RetryButtonGroup({ cveId }: { cveId: string }) {
    const isThis = retryingCve === cveId
    const isBusy = retryingCve !== null || resumingFromCve !== null
    const baseCls =
      'flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono bg-surface-800 text-gray-500 border disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0'
    return (
      <div className="flex items-center gap-1 shrink-0">
        <button
          onClick={(e) => { e.stopPropagation(); void onRetryVexSingle(cveId, 'gemini-3-pro-preview') }}
          disabled={isBusy || !canRetry}
          title={canRetry ? `${cveId} 를 Gemini Pro 로 재분석 (품질 우선, 쿼터 많이 씀)` : '분석 완료 후 사용 가능'}
          className={`${baseCls} border-surface-600 hover:bg-purple-900/40 hover:text-purple-300 hover:border-purple-700/50`}
        >
          <Gem size={11} className={isThis ? 'animate-pulse' : ''} />
          {isThis ? '…' : 'Pro'}
        </button>
        <button
          onClick={(e) => { e.stopPropagation(); void onRetryVexSingle(cveId, 'codex-default') }}
          disabled={isBusy || !canRetry}
          title={canRetry ? `${cveId} 를 OpenAI Codex 로 재분석 (CLI 기본 모델 자동 선택)` : '분석 완료 후 사용 가능'}
          className={`${baseCls} border-surface-600 hover:bg-emerald-900/40 hover:text-emerald-300 hover:border-emerald-700/50`}
        >
          <Bot size={11} className={isThis ? 'animate-pulse' : ''} />
          {isThis ? '…' : 'Codex'}
        </button>
        <button
          onClick={(e) => { e.stopPropagation(); void onRetryVexSingle(cveId, 'gemini-3-flash-preview') }}
          disabled={isBusy || !canRetry}
          title={canRetry ? `${cveId} 를 Gemini Flash 로 재분석 (빠름, 쿼터 절약)` : '분석 완료 후 사용 가능'}
          className={`${baseCls} border-surface-600 hover:bg-cyan-900/40 hover:text-cyan-300 hover:border-cyan-700/50`}
        >
          <Zap size={11} className={isThis ? 'animate-pulse' : ''} />
          {isThis ? '…' : 'Flash'}
        </button>
      </div>
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
    <div className="space-y-5">
      {/* ─── VEX Summary 헤더 ─── */}
      <div className="flex items-center gap-3 text-sm text-gray-400">
        <Bot size={15} className="text-accent-amber shrink-0" />
        <span className="font-mono text-gray-300">
          VEX analysis coverage
        </span>
        <span className="font-mono text-accent-cyan font-semibold">
          {analyzed} / {stats.total}
        </span>
        <span className="font-mono text-gray-600">({coverage}%)</span>
        {withVex.length > 0 && (
          <button
            onClick={() =>
              setExpanded((prev) =>
                prev.size === withVex.length ? new Set() : new Set(withVex.map((c) => c.cve_id)),
              )
            }
            className="ml-auto text-xs font-mono text-gray-500 hover:text-accent-cyan transition-colors"
          >
            {expanded.size === withVex.length ? 'Collapse all' : 'Expand all'}
          </button>
        )}
      </div>

      {/* ─── Filter pills: VEX 상태별 카운트 + 토글 ─── */}
      <div className="flex items-center gap-2 flex-wrap">
        {filterPills.map(({ key, label, count, active, inactive }) => (
          <button
            key={key}
            onClick={() => setVexFilter(key)}
            disabled={count === 0 && key !== 'all'}
            className={`px-3 py-1 rounded-full text-xs font-mono border transition-colors whitespace-nowrap
              ${vexFilter === key ? active : inactive}
              ${count === 0 && key !== 'all' ? 'opacity-40 cursor-not-allowed' : ''}`}
          >
            {label} <span className="ml-1 font-bold">{count}</span>
          </button>
        ))}
        {/* Sort dropdown */}
        <div className="ml-auto flex items-center gap-2">
          <label className="text-xs font-mono text-gray-500">Sort</label>
          <select
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            className="px-2 py-1 rounded text-xs font-mono bg-surface-800 text-gray-300 border border-surface-600 focus:outline-none focus:border-accent-cyan"
          >
            <option value="severity">Severity</option>
            <option value="vex">VEX status</option>
            <option value="cve">CVE ID</option>
          </select>
        </div>
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
                  <ModelBadge model={cve.analysis_model} />
                  <VexBadge status={cve.vex_status} grade={cve.analysis_grade} />
                  <RetryButtonGroup cveId={cve.cve_id} />
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
                <RetryButtonGroup cveId={cve.cve_id} />
                <ResumeFromButton cveId={cve.cve_id} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
