import { useState, useEffect, useRef, useCallback } from 'react'
import { createJobStream, getJobResult, retryVex } from '../api/client'
import type { JobResult, JobStatus } from '../types'

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
  })

  // reconnect trigger: increment to force SSE reconnect
  const [reconnectKey, setReconnectKey] = useState(0)

  const esRef = useRef<EventSource | null>(null)
  const logIdRef = useRef(0)

  const addLog = useCallback((stage: string, text: string) => {
    const id = ++logIdRef.current
    setState((s) => ({ ...s, logs: [...s.logs, { id, stage, text }] }))
  }, [])

  const loadResult = useCallback(async () => {
    try {
      const result = await getJobResult(jobId)
      setState((s) => ({ ...s, result, streaming: false }))
    } catch {
      // 결과가 아직 준비되지 않은 경우 무시
    }
  }, [jobId])

  const handleRetryVex = useCallback(async () => {
    setState((s) => ({ ...s, retrying: true }))
    try {
      await retryVex(jobId)
      // SSE 재연결 — 기존 이벤트 히스토리는 유지하고 새 이벤트 추가
      setState((s) => ({
        ...s,
        retrying: false,
        streaming: true,
        status: 'vex_analyzing' as JobStatus,
        errorMessage: null,
        currentStage: 'vex_analyzing',
        stageProgress: 0,
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

  useEffect(() => {
    const es = createJobStream(jobId)
    esRef.current = es

    es.onmessage = (e: MessageEvent) => {
      let ev: RawEvent
      try {
        ev = JSON.parse(e.data as string) as RawEvent
      } catch {
        return
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
          setState((s) => ({
            ...s,
            status: 'failed',
            errorMessage: error ?? '알 수 없는 오류',
            streaming: false,
          }))
          addLog('error', `✗ ${error ?? '알 수 없는 오류'}`)
          es.close()
          break

        case 'job_complete':
          setState((s) => ({
            ...s,
            status: 'completed',
            stageProgress: 100,
            streaming: false,
          }))
          addLog('system', '✓ 분석 완료')
          es.close()
          loadResult()
          break

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

        case 'max_turns_reached':
          addLog('vex_analyzing', `⚠ ${ev.cve_id} 최대 턴 도달 → under_investigation`)
          break

        case 'cve_done':
          addLog('vex_analyzing', `✓ ${ev.cve_id} 완료: ${ev.status}`)
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

  return { ...state, retryVex: handleRetryVex }
}
