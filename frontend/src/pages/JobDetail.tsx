import { useState, type ReactNode } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Clock, Package, ShieldAlert, Bot, Terminal, RefreshCw,
  CircleStop, Hourglass, FastForward,
} from 'lucide-react'
import { useJobDetail } from '../hooks/useJobDetail'
import { PipelineStepper } from '../components/PipelineStepper'
import { LogViewer } from '../components/LogViewer'
import { StatusBadge } from '../components/Badge'
import { SbomTab } from './JobDetail/SbomTab'
import { VulnerabilitiesTab } from './JobDetail/VulnerabilitiesTab'
import { VexAnalysisTab } from './JobDetail/VexAnalysisTab'

type Tab = 'log' | 'sbom' | 'vulnerabilities' | 'vex'

interface TabConfig {
  id: Tab
  label: string
  icon: ReactNode
  count?: number | null
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '—'
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  return `${Math.floor(seconds / 60)}m ${(seconds % 60).toFixed(0)}s`
}

export function JobDetail() {
  const { jobId } = useParams<{ jobId: string }>()
  const navigate = useNavigate()
  // 분석 결과 중심의 탭 순서: SBOM → Vulnerabilities → VEX Analysis.
  // Pipeline Log 는 개발/디버깅 시에만 관심이 있으므로 마지막에 배치하고,
  // 페이지 진입 시 기본 탭도 VEX Analysis (= 최종 산출물).
  const [activeTab, setActiveTab] = useState<Tab>('vex')

  const { result, logs, status, currentStage, stageProgress, errorMessage, streaming, retrying, resuming, cancelling, retryingCve, resumingFromCve, retryVex, resumeVex, resumeVexFrom, retryVexSingle, cancelVex, resumeFromSbom } =
    useJobDetail(jobId!)

  const tabs: TabConfig[] = [
    {
      id: 'sbom',
      label: 'SBOM',
      icon: <Package size={14} />,
      count: result?.sbom_components.length ?? null,
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      icon: <ShieldAlert size={14} />,
      count: result?.cve_results.length ?? null,
    },
    {
      id: 'vex',
      label: 'VEX Analysis',
      icon: <Bot size={14} />,
      count: result?.cve_results.filter((c) => c.vex_status).length ?? null,
    },
    {
      id: 'log',
      label: 'Pipeline Log',
      icon: <Terminal size={14} />,
      count: logs.length,
    },
  ]

  return (
    <div className="min-h-screen bg-surface-950">
      {/* Nav */}
      <nav className="border-b border-surface-700 bg-surface-900/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-[1680px] mx-auto px-4 h-20 flex items-center gap-3">
          <img
            src="/binxray_logo2.png"
            alt="binXray"
            className="h-16 w-auto select-none cursor-pointer"
            onClick={() => navigate('/')}
          />
          <span className="text-gray-700">/</span>
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-1.5 text-gray-500 hover:text-gray-300 transition-colors text-sm"
          >
            <ArrowLeft size={14} />
            <span className="font-mono">Dashboard</span>
          </button>
          <span className="text-gray-700">/</span>
          <span className="font-mono text-xs text-gray-500 truncate max-w-xs">{jobId}</span>
        </div>
      </nav>

      <div className="max-w-[1680px] mx-auto px-4 py-8 space-y-6">
        {/* Header */}
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-5 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 mb-1">
                {status && <StatusBadge status={status} />}
                {streaming && (
                  <span className="text-xs font-mono text-accent-cyan animate-pulse">
                    ● LIVE
                  </span>
                )}
              </div>
              <h1 className="font-mono text-lg text-gray-200 truncate">
                {result?.filename ?? jobId}
              </h1>
              {(result?.product_name || result?.product_version) && (
                <p className="text-sm text-gray-500 font-mono mt-0.5">
                  {[result.product_name, result.product_version].filter(Boolean).join(' ')}
                </p>
              )}
            </div>

            {/* Stage timings */}
            {result?.stage_timings && result.stage_timings.length > 0 && (
              <div className="flex items-center gap-4 text-xs font-mono shrink-0">
                {result.stage_timings.map((st) => (
                  <div key={st.stage} className="text-center">
                    <p className="text-gray-600 tracking-wider">{st.stage.replace('_', ' ').toUpperCase().slice(0, 6)}</p>
                    <p className="text-gray-400 mt-0.5">
                      <Clock size={10} className="inline mr-0.5 -mt-0.5" />
                      {formatDuration(st.elapsed_seconds)}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Pipeline stepper */}
          <PipelineStepper
            status={status}
            currentStage={currentStage}
            stageProgress={stageProgress}
          />

          {/* Error message + Retry/Resume VEX buttons.  재분석 중
              (status === 'vex_analyzing') 일 때는 이전 실패/취소 배너가
              stale 로 남아있을 수 있으므로 강제로 숨긴다 — hooks 단의
              동기화가 누락되더라도 UI 가 혼란스럽지 않게. */}
          {errorMessage && status !== 'vex_analyzing' && (() => {
            const isRateLimit = errorMessage.includes('[RATE_LIMIT]')
            // Strip the [RATE_LIMIT] marker and try to pull the affected
            // model + reset hint out for a cleaner, more informative display.
            const cleaned = errorMessage.replace(/\[RATE_LIMIT\]\s*/, '').trim()
            const modelMatch = cleaned.match(/^(\S+)\s+쿼터/)
            const resetMatch = cleaned.match(/Access resets at ([^)]+?)\)/i)
            // Outer guard already narrowed status to !== 'vex_analyzing',
            // so only 'failed' / 'completed' remain as actionable states here.
            const canAct = status === 'failed' || status === 'completed'

            if (isRateLimit) {
              return (
                <div className="flex items-start gap-3 bg-amber-900/20 border border-amber-700/50 rounded-lg px-4 py-3">
                  <Hourglass size={18} className="text-amber-300 shrink-0 mt-0.5" />
                  <div className="flex-1 space-y-1">
                    <p className="text-sm font-mono text-amber-200 font-semibold">
                      Gemini 일일 쿼터 소진으로 분석 일시 중단
                    </p>
                    <p className="text-xs font-mono text-amber-300/80">
                      {modelMatch && <>모델 <span className="text-amber-200">{modelMatch[1]}</span> · </>}
                      {resetMatch
                        ? <>쿼터 리셋 시각 <span className="text-amber-200">{resetMatch[1].trim()}</span></>
                        : '쿼터가 회복되면 Resume VEX 로 이어서 분석하세요.'}
                    </p>
                    <p className="text-xs font-mono text-gray-500 pt-1">
                      이미 완료된 CVE 는 건너뛰고 남은 CVE 만 다시 분석합니다.
                    </p>
                  </div>
                  {canAct && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => void resumeVex()}
                        disabled={resuming}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-emerald-900/40 text-emerald-300 border border-emerald-700/50 hover:bg-emerald-900/70 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        <RefreshCw size={12} className={resuming ? 'animate-spin' : ''} />
                        {resuming ? 'Resuming…' : 'Resume VEX'}
                      </button>
                      <button
                        onClick={() => {
                          if (window.confirm('기존 VEX 분석 결과를 모두 삭제하고 처음부터 다시 분석합니다. 계속하시겠습니까?')) {
                            void retryVex()
                          }
                        }}
                        disabled={retrying}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-surface-800 text-gray-400 border border-surface-600 hover:bg-cyan-900/40 hover:text-accent-cyan hover:border-cyan-700/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
                        {retrying ? 'Starting…' : 'Retry VEX'}
                      </button>
                    </div>
                  )}
                </div>
              )
            }

            // SBOM 후처리 단계에서 깨졌고 EMBA 산출물(sbom.raw.json) 이 있으면
            // EMBA 부터 다시 돌리지 않고 fix_cpe → enrich → grype → VEX 만
            // 이어 진행할 수 있도록 "Resume from SBOM" 버튼을 함께 노출.
            const canResumeFromSbom = canAct && Boolean(result?.resume_from_sbom_available)
            return (
              <div className="flex items-start gap-3 bg-red-900/20 border border-red-800/40 rounded-lg px-4 py-2">
                <p className="text-sm text-red-400 font-mono flex-1">✗ {cleaned}</p>
                {canAct && (
                  <div className="flex items-center gap-2 shrink-0">
                    {canResumeFromSbom && (
                      <button
                        onClick={() => {
                          if (window.confirm(
                            'EMBA 가 만든 sbom.raw.json 부터 fix_cpe → enrich → grype → VEX 를 다시 진행합니다.\n' +
                            '(EMBA 추출/SBOM 생성 단계는 재실행하지 않음)\n\n계속하시겠습니까?'
                          )) {
                            void resumeFromSbom()
                          }
                        }}
                        disabled={resuming || retrying}
                        title="EMBA 가 만든 sbom.raw.json 부터 후속 단계만 다시 실행 (EMBA 단계 skip)"
                        className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-emerald-900/40 text-emerald-300 border border-emerald-700/50 hover:bg-emerald-900/70 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        <FastForward size={12} className={resuming ? 'animate-pulse' : ''} />
                        {resuming ? 'Resuming…' : 'Resume from SBOM'}
                      </button>
                    )}
                    <button
                      onClick={() => {
                        if (window.confirm('기존 VEX 분석 결과를 모두 삭제하고 처음부터 다시 분석합니다. 계속하시겠습니까?')) {
                          void retryVex()
                        }
                      }}
                      disabled={retrying}
                      className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-cyan-900/40 text-accent-cyan border border-cyan-700/50 hover:bg-cyan-900/70 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
                      {retrying ? 'Starting…' : 'Retry VEX'}
                    </button>
                  </div>
                )}
              </div>
            )
          })()}
          {/* Retry VEX button when completed (no error) */}
          {!errorMessage && (status === 'completed' || status === 'failed' || status === 'vex_analyzing') && (
            <div className="flex justify-end gap-2">
              {status === 'vex_analyzing' && (
                <button
                  onClick={() => void cancelVex()}
                  disabled={cancelling}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-red-950/40 text-red-300 border border-red-800/50 hover:bg-red-900/60 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <CircleStop size={12} />
                  {cancelling ? 'Stopping...' : 'Stop VEX'}
                </button>
              )}
              <button
                onClick={() => {
                  if (window.confirm('기존 VEX 분석 결과를 모두 삭제하고 처음부터 다시 분석합니다. 계속하시겠습니까?')) {
                    void retryVex()
                  }
                }}
                disabled={retrying}
                title="모든 CVE 의 VEX 결과를 삭제하고 다시 분석"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono bg-surface-800 text-gray-400 border border-surface-600 hover:bg-cyan-900/40 hover:text-accent-cyan hover:border-cyan-700/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
                {retrying ? 'Starting…' : 'Re-run VEX Analysis'}
              </button>
            </div>
          )}
        </div>

        {/* CVE summary bar (when results available) */}
        {result && result.cve_results.length > 0 && (() => {
          const counts: Record<string, number> = {}
          for (const c of result.cve_results) counts[c.severity] = (counts[c.severity] ?? 0) + 1
          const items = [
            { key: 'CRITICAL', color: 'text-red-300 bg-red-900/50' },
            { key: 'HIGH',     color: 'text-orange-300 bg-orange-900/50' },
            { key: 'MEDIUM',   color: 'text-yellow-300 bg-yellow-900/50' },
            { key: 'LOW',      color: 'text-blue-300 bg-blue-900/50' },
          ].filter(({ key }) => counts[key])
          return (
            <div className="flex items-center gap-3 px-5 py-3 bg-surface-900 border border-surface-700 rounded-xl">
              <ShieldAlert size={15} className="text-accent-purple shrink-0" />
              <span className="text-xs font-mono text-gray-500">CVE SUMMARY</span>
              <div className="flex items-center gap-2 ml-2">
                {items.map(({ key, color }) => (
                  <span key={key} className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${color}`}>
                    {counts[key]} {key}
                  </span>
                ))}
              </div>
              <span className="ml-auto text-xs font-mono text-gray-600">
                {result.cve_results.length} total
              </span>
            </div>
          )
        })()}

        {/* Tabs */}
        <div className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
          {/* Tab bar */}
          <div className="flex border-b border-surface-700 overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  flex items-center gap-2 px-5 py-3 text-sm font-mono whitespace-nowrap
                  border-b-2 transition-colors
                  ${activeTab === tab.id
                    ? 'border-accent-cyan text-accent-cyan bg-cyan-900/10'
                    : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-surface-600'
                  }
                `}
              >
                {tab.icon}
                {tab.label}
                {tab.count !== null && tab.count !== undefined && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-xs ${
                      activeTab === tab.id
                        ? 'bg-cyan-900/50 text-cyan-300'
                        : 'bg-surface-700 text-gray-500'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="p-5">
            {activeTab === 'log' && (
              <LogViewer logs={logs} autoScroll={streaming} maxHeight="500px" />
            )}
            {activeTab === 'sbom' && (
              <SbomTab components={result?.sbom_components ?? []} />
            )}
            {activeTab === 'vulnerabilities' && (
              <VulnerabilitiesTab cves={result?.cve_results ?? []} />
            )}
            {activeTab === 'vex' && (
              <VexAnalysisTab
                cves={result?.cve_results ?? []}
                onRetryVexSingle={retryVexSingle}
                onResumeVexFrom={resumeVexFrom}
                retryingCve={retryingCve}
                resumingFromCve={resumingFromCve}
                jobStatus={status}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
