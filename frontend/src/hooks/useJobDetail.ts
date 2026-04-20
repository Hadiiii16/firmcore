import { useState, useEffect, useRef, useCallback } from 'react'
import { cancelVex, createJobStream, getJobResult, resumeVex, resumeVexFrom, retryVex, retryVexSingle } from '../api/client'
import type { CveResult, JobResult, JobStatus } from '../types'

// 백엔드 SSE 실제 포맷
// {"type": "stage_start",    "stage": "extracting", "job_id": "..."}
// {"type": "stage_progress", "stage": "extracting", "progress": 3, "log": "...", "job_id": "..."}
// {"type": "stage_complete", "stage": "extracting", "elapsed": 12.3, "job_id": "..."}
// {"type": "stage_error",    "stage": "extracting", "error": "...", "job_id": "..."}
// {"type": "job_complete",   "job_id": "..."}
// {"type": "keepalive"}
interface RawEvent {
  type: string
  stage?: string
  status?: string
  log?: string
  error?: string
  progress?: number
  elapsed?: number
  job_id?: string
  [key: string]: unknown
}

export interface LogLine {
  id: number
  stage: string
  text: string
}

interface UseJobDetailState {
  result: JobResult | null
  logs: LogLine[]
  status: JobStatus | null
  currentStage: string | null
  stageProgress: number
  errorMessage: string | null
  streaming: boolean
  retrying: boolean
  resuming: boolean
  cancelling: boolean
  retryingCve: string | null   // 개별 CVE 재분석 중인 CVE ID
  resumingFromCve: string | null  // 지정된 CVE 부터 이어서 분석 중인 시작 CVE ID
}

export function useJobDetail(jobId: string) {
  const [state, setState] = useState<UseJobDetailState>({
    result: null,
    logs: [],
    status: null,
    currentStage: null,
    stageProgress: 0,
    errorMessage: null,
    streaming: true,
    retrying: false,
    resuming: false,
    cancelling: false,
    retryingCve: null,
    resumingFromCve: null,
  })

  // reconnect trigger: increment to force SSE reconnect
  const [reconnectKey, setReconnectKey] = useState(0)
  // retry 시 SSE가 기존 이벤트를 재전송하지 않도록 after_id 추적
  const afterIdRef = useRef<number>(0)

  const esRef = useRef<EventSource | null>(null)
  const logIdRef = useRef(0)

  const addLog = useCallback((stage: string, text: string) => {
    const id = ++logIdRef.current
    setState((s) => ({ ...s, logs: [...s.logs, { id, stage, text }] }))
  }, [])

  const loadResult = useCallback(async () => {
    try {
      const data = await getJobResult(jobId)
      setState((s) => ({
        ...s,
        result: data,
        // errorMessage 는 SSE 이벤트로 설정되기도 하지만 새로고침·재연결
        // 시점에는 DB 기준(result.error_message)만이 유일한 truth.
        // null/undefined 면 유지, 있으면 덮어쓴다.
        errorMessage: data.error_message ?? s.errorMessage,
        // 완료/실패 상태면 스트리밍 종료, 분석 중이면 유지
        ...(data.status === 'completed' || data.status === 'failed'
          ? { streaming: false }
          : {}),
      }))
    } catch {
      // 결과가 아직 준비되지 않은 경우 무시
    }
  }, [jobId])

  const handleRetryVex = useCallback(async () => {
    setState((s) => ({ ...s, retrying: true }))
    try {
      await retryVex(jobId)
      // 재연결 시 로그 초기화 — afterIdRef는 유지하여 기존 이벤트 재전송 방지
      setState((s) => ({
        ...s,
        retrying: false,
        streaming: true,
        status: 'vex_analyzing' as JobStatus,
        errorMessage: null,
        currentStage: 'vex_analyzing',
        stageProgress: 0,
        logs: [],
      }))
      setReconnectKey((k) => k + 1)
    } catch (err) {
      setState((s) => ({
        ...s,
        retrying: false,
        errorMessage: (err as Error).message,
      }))
    }
  }, [jobId])

  const handleResumeVex = useCallback(async () => {
    setState((s) => ({ ...s, resuming: true }))
    try {
      await resumeVex(jobId)
      setState((s) => ({
        ...s,
        resuming: false,
        streaming: true,
        status: 'vex_analyzing' as JobStatus,
        errorMessage: null,
        currentStage: 'vex_analyzing',
        stageProgress: 0,
        logs: [],
      }))
      setReconnectKey((k) => k + 1)
    } catch (err) {
      setState((s) => ({
        ...s,
        resuming: false,
        errorMessage: (err as Error).message,
      }))
    }
  }, [jobId])

  const handleResumeVexFrom = useCallback(async (cveId: string) => {
    setState((s) => ({ ...s, resumingFromCve: cveId }))
    try {
      await resumeVexFrom(jobId, cveId)
      setState((s) => ({
        ...s,
        resumingFromCve: null,
        streaming: true,
        status: 'vex_analyzing' as JobStatus,
        errorMessage: null,
        currentStage: 'vex_analyzing',
        stageProgress: 0,
        logs: [],
      }))
      setReconnectKey((k) => k + 1)
    } catch (err) {
      setState((s) => ({
        ...s,
        resumingFromCve: null,
        errorMessage: (err as Error).message,
      }))
    }
  }, [jobId])

  const handleRetryVexSingle = useCallback(async (cveId: string) => {
    setState((s) => ({ ...s, retryingCve: cveId }))
    try {
      await retryVexSingle(jobId, cveId)
      setState((s) => ({
        ...s,
        retryingCve: null,
        streaming: true,
        status: 'vex_analyzing' as JobStatus,
        errorMessage: null,
        currentStage: 'vex_analyzing',
        stageProgress: 0,
        logs: [],
      }))
      setReconnectKey((k) => k + 1)
    } catch (err) {
      setState((s) => ({
        ...s,
        retryingCve: null,
        errorMessage: (err as Error).message,
      }))
    }
  }, [jobId])

  const handleCancelVex = useCallback(async () => {
    setState((s) => ({ ...s, cancelling: true }))
    try {
      await cancelVex(jobId)
      setState((s) => ({
        ...s,
        cancelling: false,
        streaming: false,
        status: 'failed',
        errorMessage: 'VEX 분석이 사용자 요청으로 취소되었습니다.',
      }))
      addLog('vex_analyzing', '■ VEX 분석 취소 요청 완료')
      setReconnectKey((k) => k + 1)
    } catch (err) {
      setState((s) => ({
        ...s,
        cancelling: false,
        errorMessage: (err as Error).message,
      }))
    }
  }, [addLog, jobId])

  // 페이지 로드 시 기존 결과 즉시 로드 (이미 완료된 job이면 VEX 탭 바로 표시)
  useEffect(() => {
    void loadResult()
  }, [loadResult])

  useEffect(() => {
    const es = createJobStream(jobId, afterIdRef.current)
    esRef.current = es

    es.onmessage = (e: MessageEvent) => {
      let ev: RawEvent
      try {
        ev = JSON.parse(e.data as string) as RawEvent
      } catch {
        return
      }
      // DB 이벤트 ID 추적 (재연결 시 중복 방지)
      if (typeof ev._db_id === 'number') {
        afterIdRef.current = ev._db_id
      }

      const { type, stage = 'info', log, error, progress, elapsed } = ev

      switch (type) {
        case 'stage_start':
          setState((s) => ({
            ...s,
            currentStage: stage,
            status: (stage as JobStatus) ?? s.status,
            stageProgress: 0,
          }))
          addLog(stage, `▶ ${stage} 시작`)
          break

        case 'stage_progress':
          if (log) addLog(stage, log)
          if (typeof progress === 'number') {
            setState((s) => ({ ...s, stageProgress: progress, currentStage: stage }))
          }
          break

        case 'stage_complete':
          setState((s) => ({ ...s, stageProgress: 100 }))
          addLog(stage, `✓ ${stage} 완료${typeof elapsed === 'number' ? ` (${elapsed.toFixed(1)}s)` : ''}`)
          break

        case 'stage_error':
        case 'error': {
          // 백엔드 _fail_job 은 ``{"type": "error", "message": ...}`` 로
          // emit 하지만 구 코드는 ``stage_error + error`` 필드를 기대했다.
          // 두 케이스를 한 번에 처리하고 message/error 둘 다 읽는다.
          const msg = (ev.message as string | undefined) ?? error ?? '알 수 없는 오류'
          setState((s) => ({
            ...s,
            status: 'failed',
            errorMessage: msg,
            streaming: false,
          }))
          addLog('error', `✗ ${msg}`)
          es.close()
          break
        }

        case 'job_complete':
          {
          const nextStatus = ev.status === 'failed' ? 'failed' : 'completed'
          setState((s) => ({
            ...s,
            status: nextStatus,
            stageProgress: 100,
            streaming: false,
          }))
          addLog('system', nextStatus === 'failed' ? '✗ 분석 종료' : '✓ 분석 완료')
          es.close()
          loadResult()
          break
          }

        case 'job_failed':
          setState((s) => ({
            ...s,
            status: 'failed',
            errorMessage: error ?? '파이프라인 실패',
            streaming: false,
          }))
          addLog('error', `✗ ${error ?? '파이프라인 실패'}`)
          es.close()
          break

        case 'cve_start':
          addLog('vex_analyzing', `▶ [${ev.index}/${ev.total}] ${ev.cve_id} 분석 시작`)
          break

        case 'gemini_response': {
          const preview = (ev.content as string ?? '').slice(0, 200).replace(/\n/g, ' ')
          addLog('vex_analyzing', `🤖 Turn ${ev.turn}: ${preview}…`)
          break
        }

        case 'executing_command':
          addLog('vex_analyzing', `$ ${ev.command}`)
          break

        case 'command_result': {
          const out = ((ev.result as string) ?? '').slice(0, 200).replace(/\n/g, ' ')
          if (ev.blocked) {
            addLog('vex_analyzing', `⛔ 차단: ${ev.command}`)
          } else {
            addLog('vex_analyzing', `  rc=${ev.returncode} ${out}`)
          }
          break
        }

        case 'vex_complete': {
          const cveId = ev.cve_id as string ?? ''
          const status = ev.status as string ?? ''
          const icon = status === 'not_affected' ? '✓' : status === 'affected' ? '✗' : '?'
          addLog('vex_analyzing', `${icon} ${cveId} → ${status}`)
          break
        }

        case 'vex_json_not_found':
          addLog('vex_analyzing', `⚠ ${ev.cve_id} OpenVEX JSON 추출 실패 → under_investigation (fallback)`)
          break

        case 'cve_done': {
          addLog('vex_analyzing', `✓ ${ev.cve_id} 완료: ${ev.status}`)
          // Merge the single-CVE payload carried on the event for fast
          // partial updates.  If result is still null (page just loaded /
          // refreshed and the initial fetch hasn't returned yet) the patch
          // would be lost — fall back to a fresh /result fetch in that
          // case so the UI eventually catches up.
          const patch = ev.cve_result as CveResult | undefined
          let needFullLoad = !patch
          if (patch) {
            setState((s) => {
              if (!s.result) {
                needFullLoad = true
                return s
              }
              const cves = s.result.cve_results
              const idx = cves.findIndex((c) => c.cve_id === patch.cve_id)
              const nextCves = idx >= 0
                ? cves.map((c, i) => (i === idx ? { ...c, ...patch } : c))
                : [...cves, patch]
              const counts = { not_affected_count: 0, affected_count: 0, under_investigation_count: 0 }
              for (const c of nextCves) {
                if (c.vex_status === 'not_affected') counts.not_affected_count++
                else if (c.vex_status === 'affected') counts.affected_count++
                else if (c.vex_status === 'under_investigation') counts.under_investigation_count++
              }
              return {
                ...s,
                result: { ...s.result, cve_results: nextCves, ...counts },
              }
            })
          }
          if (needFullLoad) void loadResult()
          break
        }

        case 'batch_complete':
          addLog('vex_analyzing', `✓ VEX 배치 분석 완료 (${(ev.total as number) ?? 0}개 CVE)`)
          void loadResult()
          break

        case 'batch_cancelled':
          setState((s) => ({
            ...s,
            status: 'failed',
            streaming: false,
            errorMessage: (ev.message as string) ?? 'VEX 분석이 취소되었습니다.',
          }))
          addLog('vex_analyzing', `■ ${(ev.message as string) ?? 'VEX 분석이 취소되었습니다.'}`)
          break

        case 'keepalive':
          break

        default:
          // 알 수 없는 이벤트: log 필드가 있으면 표시
          if (log) addLog(stage, log)
      }
    }

    es.onerror = () => {
      setState((s) => {
        if (s.status === 'completed' || s.status === 'failed') return s
        return { ...s, streaming: false }
      })
    }

    return () => {
      es.close()
    }
  // reconnectKey 변경 시 SSE 재연결
  }, [jobId, addLog, loadResult, reconnectKey])

  return {
    ...state,
    retryVex: handleRetryVex,
    resumeVex: handleResumeVex,
    resumeVexFrom: handleResumeVexFrom,
    retryVexSingle: handleRetryVexSingle,
    cancelVex: handleCancelVex,
  }
}
