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
    # VEX 판정 (not_affected | affected | under_investigation | unknown)
    vex_status: str = "unknown"
    vex_justification: Optional[str] = None
    vex_detail: Optional[str] = None


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
