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
