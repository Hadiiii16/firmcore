// ── Job Status ────────────────────────────────────────────────────────────────

export type JobStatus =
  | 'pending'
  | 'extracting'
  | 'sbom_generating'
  | 'scanning'
  | 'vex_analyzing'
  | 'completed'
  | 'failed'

// ── Job Summary (list view) ───────────────────────────────────────────────────

export interface JobSummary {
  id: string           // 백엔드 필드명
  filename: string
  product_name: string | null
  product_version: string | null
  status: JobStatus
  current_stage: string | null
  stage_progress: number
  total_cves: number
  critical_cves: number
  high_cves: number
  affected_count: number
  not_affected_count: number
  under_investigation_count: number
  created_at: string
  updated_at: string
  completed_at: string | null
  error_message: string | null
}

export interface JobListResponse {
  items: JobSummary[]
  total: number
  limit: number
  offset: number
}

// ── Job Create ────────────────────────────────────────────────────────────────

export interface JobCreateResponse {
  job_id: string
  status: JobStatus
  filename: string
  created_at: string
}

// ── SSE Events ────────────────────────────────────────────────────────────────

export interface SseEvent {
  id: number
  type: string
  data: Record<string, unknown>
  created_at: string
}

// ── Pipeline Result ───────────────────────────────────────────────────────────

export interface SbomComponent {
  bom_ref: string
  name: string
  version: string
  type: string
  purl: string | null
}

export interface CveResult {
  cve_id: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN'
  package_name: string
  package_version: string
  fixed_version: string | null
  description: string
  vex_status: string | null
  vex_justification: string | null
  vex_detail: string | null
}

export interface StageTiming {
  stage: string
  started_at: string
  elapsed_seconds: number | null
  status: string
}

export interface JobResult {
  job_id: string
  status: JobStatus
  filename: string
  product_name: string | null
  product_version: string | null
  sbom_components: SbomComponent[]
  cve_results: CveResult[]
  stage_timings: StageTiming[]
  created_at: string
  completed_at: string | null
  error_message: string | null
}
