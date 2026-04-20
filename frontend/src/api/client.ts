import type {
  DashboardSummary,
  JobCreateResponse,
  JobListResponse,
  JobResult,
} from '../types'

const BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init)
  if (!res.ok) {
    // 에러 바디가 비어 있거나 JSON 이 아닐 수 있으므로 둘 다 방어.
    let detail: string | undefined
    try {
      const body = await res.json()
      detail = (body as { detail?: string }).detail
    } catch { /* swallow */ }
    throw new Error(detail ?? `HTTP ${res.status}`)
  }
  // 204 No Content 응답은 바디가 없음 — res.json() 을 호출하면 Safari 가
  // "The string did not match the expected pattern." 를 throw 하므로 분기.
  if (res.status === 204) return undefined as unknown as T
  const text = await res.text()
  if (!text) return undefined as unknown as T
  return JSON.parse(text) as T
}

// ── Upload ────────────────────────────────────────────────────────────────────

export async function uploadFirmware(
  file: File,
  productName: string,
  productVersion: string,
  onProgress?: (pct: number) => void,
): Promise<JobCreateResponse> {
  return new Promise((resolve, reject) => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('product_name', productName)
    fd.append('product_version', productVersion)

    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${BASE}/upload`)

    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100))
      }
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText) as JobCreateResponse)
      } else {
        try {
          const body = JSON.parse(xhr.responseText) as { detail?: string }
          reject(new Error(body.detail ?? `HTTP ${xhr.status}`))
        } catch {
          reject(new Error(`HTTP ${xhr.status}`))
        }
      }
    }
    xhr.onerror = () => reject(new Error('Network error'))
    xhr.send(fd)
  })
}

// ── Jobs ──────────────────────────────────────────────────────────────────────

export function getJobs(limit = 20, offset = 0): Promise<JobListResponse> {
  return request<JobListResponse>(`/jobs?limit=${limit}&offset=${offset}`)
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export function getDashboardSummary(): Promise<DashboardSummary> {
  return request<DashboardSummary>('/dashboard/summary')
}

export function getJobResult(jobId: string): Promise<JobResult> {
  return request<JobResult>(`/jobs/${jobId}/result`)
}

export function deleteJob(jobId: string, force = false): Promise<void> {
  const qs = force ? '?force=true' : ''
  return request<void>(`/jobs/${jobId}${qs}`, { method: 'DELETE' })
}

export function retryVex(jobId: string): Promise<{ job_id: string; status: string }> {
  return request(`/jobs/${jobId}/retry-vex`, { method: 'POST' })
}

export function resumeVex(jobId: string): Promise<{ job_id: string; status: string; mode: string }> {
  return request(`/jobs/${jobId}/resume-vex`, { method: 'POST' })
}

export function resumeVexFrom(
  jobId: string,
  cveId: string,
): Promise<{ job_id: string; cve_id: string; status: string; mode: string }> {
  return request(`/jobs/${jobId}/resume-vex/${encodeURIComponent(cveId)}`, { method: 'POST' })
}

export function cancelVex(
  jobId: string,
): Promise<{ job_id: string; status: string; terminated_processes: number }> {
  return request(`/jobs/${jobId}/cancel-vex`, { method: 'POST' })
}

export function retryVexSingle(
  jobId: string,
  cveId: string,
): Promise<{ job_id: string; cve_id: string; status: string }> {
  return request(`/jobs/${jobId}/retry-vex/${encodeURIComponent(cveId)}`, { method: 'POST' })
}

// ── SSE Stream ────────────────────────────────────────────────────────────────

export function createJobStream(jobId: string, afterId = 0): EventSource {
  const url = afterId > 0
    ? `${BASE}/jobs/${jobId}/stream?after_id=${afterId}`
    : `${BASE}/jobs/${jobId}/stream`
  return new EventSource(url)
}
