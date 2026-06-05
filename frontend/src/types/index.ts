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
  severity_counts: Partial<Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN', number>>
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
  // GEMINI.md v5.0 — affected 의 위험 등급.
  //   'B' — 일반 affected (도달 가능 + 완화 부족) → 패치 시급
  //   'C' — 도달 가능하지만 컴파일 완화로 exploit 난이도 상승
  //   'D' — 코드 + 실행 경로 존재하나 공격 표면 노출 증거 없음 (잠재 위험)
  //   'A' — exploit 시연 (GEMINI.md 가 발행 금지하지만 잘못 들어올 수 있어 보존)
  //   null — status !== 'affected'
  analysis_grade: 'A' | 'B' | 'C' | 'D' | null
  // GEMINI.md v5.0 — 정적 분석 신뢰도 (모든 status 에 적용).
  //   HIGH   — 직접 증거로 판정
  //   MEDIUM — 합리적 추론, 일부 가정 포함
  //   LOW    — 강한 가정 또는 stripped/NVRAM 의존
  //   null   — evidence 태그 누락 (구버전 분석본)
  analysis_evidence: 'HIGH' | 'MEDIUM' | 'LOW' | null
  // 실제 분석을 수행한 모델명 (Gemini Pro/Flash 또는 Codex).  Pro 쿼터
  // 소진 시 Codex / Flash 로 자동 폴백되는 케이스가 있어 배치 기본 모델과
  // 다를 수 있다.  null = 모델 추적 전 데이터 또는 mock.
  analysis_model: string | null
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

  // EMBA 가 만든 sbom.raw.json 이 디스크에 있으면 true.  fix_cpe/enrich/grype/
  // VEX 단계에서 잡이 깨졌을 때 "Resume from SBOM" 버튼을 활성화할지 결정.
  resume_from_sbom_available?: boolean
}
