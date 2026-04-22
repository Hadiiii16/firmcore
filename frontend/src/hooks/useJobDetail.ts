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

  // ``loadResult`` 는 여러 경로에서 호출된다 (페이지 로드, cve_done 폴백,
  // 60초 fail-safe, Resume/Retry 직후).  SSE 재연결 시점에 backend 가
  // ``after_id=0`` 부터 히스토리를 몰아서 쏟으면 cve_done 이 수십 개
  // 연속으로 도착해 각각 ``s.result === null`` 분기에서 ``loadResult`` 를
  // 건드려 async fetch 가 병렬로 쌓인다 (초당 10+개).
  //
  // in-flight guard + 완료 후 잠깐의 coalesce 창을 두어 중복 호출을
  // 한 건으로 압축한다.
  const loadingRef = useRef(false)
  const loadResult = useCallback(async () => {
    if (loadingRef.current) return
    loadingRef.current = true
    try {
      const data = await getJobResult(jobId)
      setState((s) => {
        const newStatus = (data.status ?? s.status) as JobStatus | null
        // errorMessage 처리 규칙:
        //   1. DB 가 error_message 를 **명시적으로** 들고 있다 → 그 값으로 덮어쓰기
        //   2. DB error_message 가 null + status 가 completed / vex_analyzing
        //      → "문제 없음" 의미이므로 state 의 stale 에러 배너를 **비운다**
        //   3. 그 외 (DB null + state failed 에 stale 에러) → state 유지
        //      (SSE 로 들어왔던 최신 에러 메시지는 존중)
        let nextError: string | null = s.errorMessage
        if (data.error_message) {
          nextError = data.error_message
        } else if (newStatus === 'completed' || newStatus === 'vex_analyzing') {
          nextError = null
        }
        return {
          ...s,
          result: data,
          status: newStatus,
          errorMessage: nextError,
          streaming: !(newStatus === 'completed' || newStatus === 'failed'),
        }
      })
    } catch {
      // 결과가 아직 준비되지 않은 경우 무시
    } finally {
      loadingRef.current = false
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

  const handleRetryVexSingle = useCallback(async (cveId: string, model?: string) => {
    setState((s) => ({ ...s, retryingCve: cveId }))
    try {
      await retryVexSingle(jobId, cveId, model)
      // 개별 재분석은 **로그를 비우지 않고** 기존 기록에 구분자 + 시작
      // 표시만 덧붙인다.  handleRetryVex (전체 재분석) 은 의미상 "처음
      // 부터" 이므로 clear 하지만, 단일 CVE 재분석은 기존 로그 맥락
      // 위에 덧붙는 게 자연스럽다.
      const modelLabel = model
        ? (model.includes('pro') ? 'Pro' : model.includes('flash') ? 'Flash' : model)
        : 'default'
      setState((s) => ({
        ...s,
        retryingCve: null,
        streaming: true,
        status: 'vex_analyzing' as JobStatus,
        errorMessage: null,
        currentStage: 'vex_analyzing',
        stageProgress: 0,
        logs: [
          ...s.logs,
          {
            id: ++logIdRef.current,
            stage: 'system',
            text: `────── ${cveId} 개별 재분석 시작 (${modelLabel}) ──────`,
          },
        ],
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

  // 이벤트 기반 업데이트:
  //   1. 페이지 로드 시 loadResult() 한 번 (위 useEffect)
  //   2. SSE ``cve_done`` 이벤트마다 loadResult() 호출 (아래 switch 분기)
  //   3. Resume/Retry 버튼 핸들러가 직접 setState + SSE 재연결
  //
  // 주기적 폴링 없음 — SSE 가 끊긴 경우를 대비해 60초 fail-safe 만 유지.
  // 분석 진행 중일 때 60초 동안 cve_done 이 한 건도 안 오면 분명 어딘가
  // 끊긴 상황이므로 한 번 강제 동기화.  completed 상태면 완전 정지.
  useEffect(() => {
    if (state.status === 'completed') return
    const id = setInterval(() => { void loadResult() }, 60000)
    return () => clearInterval(id)
  }, [state.status, loadResult])

  // SSE 는 ``job_failed`` / ``job_complete`` 를 수신하면 es.close() 로
  // 닫힌다.  그 후 retry/resume 으로 DB 가 다시 vex_analyzing 으로 바뀌고
  // polling 이 그것을 감지하면(esRef.current?.readyState === CLOSED),
  // SSE 를 재연결해 실시간 로그 스트림을 복구한다.
  useEffect(() => {
    if (state.status !== 'vex_analyzing') return
    const es = esRef.current
    if (es && es.readyState !== EventSource.CLOSED) return
    setReconnectKey((k) => k + 1)
  }, [state.status])

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
          // 새 stage 가 시작되면 이전 실패/취소 메시지는 의미를 잃는다.
          // SSE 재연결 시 과거 ``batch_cancelled`` / ``error`` 이벤트가
          // 먼저 도착해 errorMessage 를 채운 뒤 ``stage_start`` 로 넘어
          // 오는 경우가 있으므로, 여기서 강제로 비워 stale 배너가 남는
          // 것을 막는다.
          setState((s) => ({
            ...s,
            currentStage: stage,
            status: (stage as JobStatus) ?? s.status,
            stageProgress: 0,
            errorMessage: null,
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
          //
          // 주의: ``es.close()`` 를 호출하지 않는다.  SSE 재전송 시 과거
          // ``error`` 이벤트가 재수신될 수 있는데 여기서 close 하면
          // 이후 복구 이벤트 (Resume 성공의 job_complete 등) 를 못 받아
          // 프론트엔드가 stale 실패 상태에 갇힌다.  SSE 자체는 백엔드
          // ``_sse_generator`` 가 job 완료 시 자연스럽게 닫는다.
          const msg = (ev.message as string | undefined) ?? error ?? '알 수 없는 오류'
          setState((s) => ({
            ...s,
            status: 'failed',
            errorMessage: msg,
            streaming: false,
          }))
          addLog('error', `✗ ${msg}`)
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
            // 정상 완료 시엔 이전 stale 에러 배너(예: 재전송된
            // ``batch_cancelled`` 로 인한 "취소됨" 메시지) 를 비운다.
            // 실패 완료는 기존 errorMessage 유지.
            errorMessage: nextStatus === 'completed' ? null : s.errorMessage,
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
          // ``cve_result`` payload 에 이미 디스크 기준 최신 상태(
          // vex_status / vex_justification / vex_detail / exploitability_tier)
          // 가 들어 있으므로 patch 적용만으로 UI 가 정합하다.  추가
          // fetch 는 불필요 (네트워크 낭비).  단 result 가 아직 null
          // (페이지 로드 직후) 이면 patch 를 붙일 곳이 없으니 한 번만
          // fetch.
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

        case 'batch_cancelled': {
          // SSE 재연결 시 과거 cancel 이벤트가 재전송되는 경우가 있다.
          // 이미 분석이 진행 중(vex_analyzing) 이거나 그 뒤로 완료/
          // 실패했다면 stale 이벤트로 간주하고 무시한다.  cancel 이
          // "지금 막 일어났다" 를 나타내는 유일한 정상 경로는 폴링/
          // 실시간 스트림에서 status 가 ``failed`` 로 방금 전환되는
          // 순간인데, 그 경우엔 handleCancelVex 가 이미 errorMessage
          // 를 직접 설정한다.
          let skipStale = false
          setState((s) => {
            if (
              s.status === 'vex_analyzing' ||
              s.status === 'completed' ||
              // 이미 non-cancel 메시지로 실패 처리되어 있다면 덮어쓰지 않음
              (s.status === 'failed' && s.errorMessage &&
                !s.errorMessage.includes('취소'))
            ) {
              skipStale = true
              return s
            }
            return {
              ...s,
              status: 'failed' as JobStatus,
              streaming: false,
              errorMessage: (ev.message as string) ?? 'VEX 분석이 취소되었습니다.',
            }
          })
          if (!skipStale) {
            addLog('vex_analyzing', `■ ${(ev.message as string) ?? 'VEX 분석이 취소되었습니다.'}`)
          }
          break
        }

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
