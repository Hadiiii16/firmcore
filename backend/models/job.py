"""
models/job.py — Job 관련 Pydantic 스키마 (API 요청/응답 모델)

DB CRUD 함수는 backend/db.py에 위치합니다.
이 파일은 FastAPI 엔드포인트의 요청/응답 스키마만 정의합니다.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    PENDING = "pending"
    EXTRACTING = "extracting"
    SBOM_GENERATING = "sbom_generating"
    SCANNING = "scanning"
    VEX_ANALYZING = "vex_analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# API 응답 모델
# ---------------------------------------------------------------------------


class JobCreateResponse(BaseModel):
    """POST /api/upload 응답."""

    job_id: str
    status: JobStatus
    filename: str
    created_at: str


class StageTiming(BaseModel):
    stage: str
    started_at: str
    completed_at: Optional[str] = None
    elapsed_seconds: Optional[float] = None


class JobSummary(BaseModel):
    """GET /api/jobs 목록 항목."""

    id: str
    filename: str
    status: JobStatus
    current_stage: Optional[str] = None
    stage_progress: int = 0
    product_name: str = ""
    product_version: str = ""
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    affected_count: int = 0
    not_affected_count: int = 0
    under_investigation_count: int = 0
    error_message: Optional[str] = None
    created_at: str
    updated_at: str
    completed_at: Optional[str] = None


class JobListResponse(BaseModel):
    """GET /api/jobs 응답."""

    items: list[JobSummary]
    total: int
    limit: int
    offset: int


class CveResult(BaseModel):
    """CVE 스캔 결과 + VEX 판정 병합 모델."""

    cve_id: str
    package_name: str
    package_version: str
    severity: str
    description: str
    fix_version: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    # grype 의 추가 스코어링 메트릭 — 보안 담당자가 우선순위 결정에
    # 활용할 수 있도록 함께 노출함.  grype 출력에 없는 경우 None.
    cvss_base_score: Optional[float] = None    # 0.0 ~ 10.0
    cvss_vector: Optional[str] = None          # "CVSS:3.1/AV:N/..."
    epss_score: Optional[float] = None         # 0.0 ~ 1.0 (exploit 가능성)
    epss_percentile: Optional[float] = None    # 0.0 ~ 1.0 (전체 CVE 대비 분포)
    risk_score: Optional[float] = None         # grype 가 합성한 통합 리스크
    cwes: list[str] = Field(default_factory=list)  # ["CWE-119", ...]
    # VEX 판정 (not_affected | affected | fixed | under_investigation | unknown)
    vex_status: str = "unknown"
    vex_justification: Optional[str] = None
    vex_detail: Optional[str] = None
    # GEMINI.md v5.0 — ``affected`` 의 실전 위험도 등급.
    #   "B"  — 일반 affected (도달 가능 + 완화 부족) → 패치 시급
    #   "C"  — 도달 가능하지만 컴파일 완화로 exploit 난이도 상승
    #   "D"  — 코드 + 실행 경로 존재하나 공격 표면 노출 증거 없음 (잠재 위험)
    #   None — status != "affected"
    analysis_grade: Optional[str] = None
    # GEMINI.md v5.0 — 정적 분석 신뢰도.  HIGH / MEDIUM / LOW.
    # 모든 status 에 적용 가능.  LOW 면 수동 추가 검증 권장.
    analysis_evidence: Optional[str] = None
    # 이 CVE 판정을 실제로 낸 분석 모델명.  Pro 쿼터 소진 시 Codex/Flash 로
    # 자동 폴백된 케이스가 있어 배치 기본 모델과 다를 수 있다.
    # 프론트엔드는 이 값을 뱃지(``PRO`` / ``CODEX`` / ``FLASH``) 로 표시하고,
    # Flash/Codex 로 분석된 CVE 를 Pro 로 재분석하도록 Re-analyze 버튼을
    # 활성화한다.  ``null`` = 모델 추적 전 데이터 또는 mock.
    analysis_model: Optional[str] = None


class SbomComponent(BaseModel):
    """SBOM 컴포넌트 요약."""

    name: str
    version: str
    type: str = ""
    purl: Optional[str] = None
    licenses: list[str] = Field(default_factory=list)
    # Cross-reference with scan.json: how many CVEs hit this component
    # and what's the worst severity.  Lets the SBOM tab double as a
    # "which packages need attention?" view without opening the CVE tab.
    cve_count: int = 0
    max_severity: Optional[str] = None  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    # 심각도 등급별 CVE 개수 — 키: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN, 0 인 등급은 생략
    severity_counts: dict[str, int] = Field(default_factory=dict)


class JobResult(BaseModel):
    """GET /api/jobs/{job_id}/result 응답."""

    id: str
    filename: str
    status: JobStatus
    product_name: str
    product_version: str

    # 컴포넌트
    component_count: int = 0
    sbom_components: list[SbomComponent] = Field(default_factory=list)

    # CVE 집계
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    medium_cves: int = 0
    low_cves: int = 0

    # VEX 집계
    not_affected_count: int = 0
    affected_count: int = 0
    under_investigation_count: int = 0

    # 상세 CVE 목록 (VEX 판정 포함)
    cve_results: list[CveResult] = Field(default_factory=list)

    # 통합 OpenVEX 문서
    vex_document: Optional[dict] = None

    # 단계별 소요시간
    stage_timings: list[StageTiming] = Field(default_factory=list)

    error_message: Optional[str] = None

    # Resume-from-SBOM 가능 여부 — EMBA 가 만든 sbom.raw.json 이 존재하는 경우.
    # 잡이 fix_cpe / enrich_sbom / scanning / vex_analyzing 단계에서 실패했을
    # 때 SBOM 부터 이어 진행 가능한지 프론트엔드가 판단하는 데 사용.
    resume_from_sbom_available: bool = False
    created_at: str
    completed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Dashboard aggregation models (GET /api/dashboard/summary)
# ---------------------------------------------------------------------------


class FirmwareRef(BaseModel):
    """대시보드 drill-down 용 펌웨어 참조.

    Top Packages / Top CVEs 의 각 행을 펼쳤을 때 "어느 펌웨어에서
    나온 것인지" 를 사용자가 바로 확인하고 해당 job 으로 이동할 수
    있도록 최소 식별자 세트를 담는다.
    """

    job_id: str                          # /jobs/{job_id} 링크 생성용
    filename: str
    product_name: str = ""
    product_version: str = ""
    # 컨텍스트-의존 필드 — package drill-down 에서는 해당 펌웨어에서
    # 이 패키지에 걸린 CVE 개수, CVE drill-down 에서는 해당 펌웨어의
    # VEX 판정.  관계없는 쪽은 None 또는 0 으로 둔다.
    cve_count: int = 0
    vex_status: Optional[str] = None     # affected | not_affected | under_investigation | unanalyzed


class TopPackage(BaseModel):
    """패키지별 fleet-wide 노출 요약."""

    package_name: str
    package_version: str
    firmware_count: int        # 이 (name, version) 이 탐지된 펌웨어 수
    cve_count: int             # 이 패키지에 대한 고유 CVE 수
    affected_count: int        # VEX 판정이 ``affected`` 인 CVE 개수
    max_severity: Optional[str] = None  # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    firmwares: list[FirmwareRef] = Field(default_factory=list)


class TopCve(BaseModel):
    """CVE 별 fleet-wide 영향 요약."""

    cve_id: str
    severity: str
    firmware_count: int
    affected_firmware_count: int
    package_name: str
    max_cvss: Optional[float] = None
    max_epss: Optional[float] = None
    max_risk: Optional[float] = None
    firmwares: list[FirmwareRef] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    """GET /api/dashboard/summary 응답."""

    # ── Fleet overview ─────────────────────────────────────────────
    total_firmwares: int           # 완료된 분석 수 (status = completed)
    unique_components: int         # fleet 전체 (name, version) 고유 컴포넌트
    unique_cves: int               # fleet 전체 고유 CVE

    # ── 심각도 rollup (유니크 CVE × 펌웨어 매칭 기준) ───────────────
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int

    # ── VEX rollup ────────────────────────────────────────────────
    affected_count: int
    not_affected_count: int
    under_investigation_count: int
    unanalyzed_count: int          # VEX 판정 자체가 없는 CVE

    # ── Actions needed ────────────────────────────────────────────
    pending_vex: int               # under_investigation + unanalyzed
    affected_with_fix: int         # affected + fix_version 존재 → 업그레이드 가능

    # ── Job pipeline status ───────────────────────────────────────
    total_jobs: int
    active_jobs: int
    completed_jobs: int
    failed_jobs: int

    # ── Top exposures ────────────────────────────────────────────
    top_packages: list[TopPackage] = Field(default_factory=list)
    top_cves: list[TopCve] = Field(default_factory=list)
