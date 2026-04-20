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
  id: string
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
  name: string
  version: string
  type: string
  purl: string | null
  licenses: string[]
  cve_count: number
  max_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | null
}

export interface CveResult {
  cve_id: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN'
  package_name: string
  package_version: string
  fix_version: string | null   // 백엔드 필드명: fix_version
  urls: string[]
  description: string
  // grype 스코어링 메트릭 (값이 없을 수 있음)
  cvss_base_score: number | null
  cvss_vector: string | null
  epss_score: number | null
  epss_percentile: number | null
  risk_score: number | null
  cwes: string[]
  vex_status: string | null
  vex_justification: string | null
  vex_detail: string | null
}

// ── Dashboard aggregation ────────────────────────────────────────────────────

export interface FirmwareRef {
  job_id: string
  filename: string
  product_name: string
  product_version: string
  cve_count: number              // package drill-down: CVE count in this firmware
  vex_status: string | null      // CVE drill-down: per-firmware VEX verdict
}

export interface TopPackage {
  package_name: string
  package_version: string
  firmware_count: number
  cve_count: number
  affected_count: number
  max_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | null
  firmwares: FirmwareRef[]
}

export interface TopCve {
  cve_id: string
  severity: string
  firmware_count: number
  affected_firmware_count: number
  package_name: string
  max_cvss: number | null
  max_epss: number | null
  max_risk: number | null
  firmwares: FirmwareRef[]
}

export interface DashboardSummary {
  total_firmwares: number
  unique_components: number
  unique_cves: number
  critical_cves: number
  high_cves: number
  medium_cves: number
  low_cves: number
  affected_count: number
  not_affected_count: number
  under_investigation_count: number
  unanalyzed_count: number
  pending_vex: number
  affected_with_fix: number
  total_jobs: number
  active_jobs: number
  completed_jobs: number
  failed_jobs: number
  top_packages: TopPackage[]
  top_cves: TopCve[]
}

export interface StageTiming {
  stage: string
  started_at: string
  completed_at: string | null
  elapsed_seconds: number | null
}

export interface JobResult {
  id: string               // 백엔드 필드명: id
  filename: string
  status: JobStatus
  product_name: string | null
  product_version: string | null

  // SBOM
  component_count: number
  sbom_components: SbomComponent[]

  // CVE 집계
  total_cves: number
  critical_cves: number
  high_cves: number
  medium_cves: number
  low_cves: number

  // VEX 집계
  not_affected_count: number
  affected_count: number
  under_investigation_count: number

  // 상세 결과
  cve_results: CveResult[]
  vex_document: Record<string, unknown> | null

  stage_timings: StageTiming[]
  created_at: string
  completed_at: string | null
  error_message: string | null
}
