import type {
  JobCreateResponse,
  JobListResponse,
  JobResult,
} from '../types'

const BASE = '/api'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init)
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error((body as { detail?: string }).detail ?? `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
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

export function getJobResult(jobId: string): Promise<JobResult> {
  return request<JobResult>(`/jobs/${jobId}/result`)
}

export function deleteJob(jobId: string): Promise<void> {
  return request<void>(`/jobs/${jobId}`, { method: 'DELETE' })
}

export function retryVex(jobId: string): Promise<{ job_id: string; status: string }> {
  return request(`/jobs/${jobId}/retry-vex`, { method: 'POST' })
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
