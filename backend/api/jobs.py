"""
jobs.py — Job 관련 API 엔드포인트

GET /api/jobs                  — 전체 Job 목록 (페이징)
GET /api/jobs/{job_id}/stream  — SSE 실시간 스트리밍
GET /api/jobs/{job_id}/result  — 완료된 Job 전체 결과
DELETE /api/jobs/{job_id}      — Job 삭제

SSE 설계 (중복 없음 보장):
  - event_bus 로 알림 큐 등록 (실시간 웨이크업 신호)
  - DB job_events 테이블이 단일 진실 공급원 (single source of truth)
  - last_event_id 추적으로 중복 전송 불가
  - 재연결 시 기존 이벤트 자동 리플레이
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from pathlib import Path
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from db import (
    db_add_event,
    db_get_events,
    db_get_job,
    db_get_stage_timings,
    db_list_jobs,
    db_update_job,
    get_db,
    now_iso,
)
from event_bus import broadcast, subscribe, unsubscribe
from models.job import (
    CveResult,
    JobListResponse,
    JobResult,
    JobStatus,
    JobSummary,
    SbomComponent,
    StageTiming,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# GET /api/jobs — Job 목록
# ---------------------------------------------------------------------------


@router.get("", response_model=JobListResponse)
async def list_jobs(
    limit: int = Query(20, ge=1, le=100, description="페이지당 항목 수"),
    offset: int = Query(0, ge=0, description="건너뛸 항목 수"),
) -> JobListResponse:
    """전체 Job 목록을 최신순으로 반환합니다."""
    async with get_db() as db:
        rows, total = await db_list_jobs(db, limit=limit, offset=offset)

    items = []
    for r in rows:
        # jobs 테이블의 affected_count 등은 runner 의 incremental 카운터
        # 기반이라 Resume/Retry 를 반복하면 stale 해진다.  ``combined_vex
        # .json`` 또는 ``vex/*_vex.json`` 파일을 살펴 실시간 재집계.
        aff = r.get("affected_count", 0) or 0
        na = r.get("not_affected_count", 0) or 0
        ui = r.get("under_investigation_count", 0) or 0
        sdir = r.get("storage_dir")
        if sdir:
            live = _count_vex_statuses(Path(sdir))
            if live is not None:
                aff, na, ui = live

        items.append(JobSummary(
            id=r["id"],
            filename=r["filename"],
            status=JobStatus(r["status"]),
            current_stage=r.get("current_stage"),
            stage_progress=r.get("stage_progress", 0),
            product_name=r.get("product_name", ""),
            product_version=r.get("product_version", ""),
            total_cves=r.get("total_cves", 0),
            critical_cves=r.get("critical_cves", 0),
            high_cves=r.get("high_cves", 0),
            affected_count=aff,
            not_affected_count=na,
            under_investigation_count=ui,
            error_message=r.get("error_message"),
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            completed_at=r.get("completed_at"),
        ))
    return JobListResponse(items=items, total=total, limit=limit, offset=offset)


def _count_vex_statuses(storage_dir: Path) -> Optional[tuple[int, int, int]]:
    """Return (affected, not_affected, under_investigation) from on-disk VEX.

    Priority: combined_vex.json (배치 완료 후), 없으면 vex/*_vex.json 모음.
    둘 다 없으면 None → 호출부가 DB 캐시로 폴백하도록 함.
    """
    combined = storage_dir / "combined_vex.json"
    if combined.exists():
        try:
            doc = json.loads(combined.read_text(encoding="utf-8"))
            aff = na = ui = 0
            for stmt in doc.get("statements", []):
                st = stmt.get("status")
                if st == "affected":
                    aff += 1
                elif st == "not_affected":
                    na += 1
                elif st == "under_investigation":
                    ui += 1
            return (aff, na, ui)
        except Exception:
            pass

    vex_dir = storage_dir / "vex"
    if not vex_dir.exists():
        return None
    aff = na = ui = 0
    for f in vex_dir.glob("*_vex.json"):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
            for stmt in doc.get("statements", []):
                st = stmt.get("status")
                if st == "affected":
                    aff += 1
                elif st == "not_affected":
                    na += 1
                elif st == "under_investigation":
                    ui += 1
        except Exception:
            continue
    return (aff, na, ui)


# ---------------------------------------------------------------------------
# GET /api/jobs/{job_id}/stream — SSE 실시간 스트리밍
# ---------------------------------------------------------------------------


@router.get("/{job_id}/stream")
async def stream_job(
    job_id: str,
    request: Request,
    after_id: int = Query(0, ge=0, description="이 ID 이후 이벤트만 전송 (재연결 시 중복 방지)"),
) -> StreamingResponse:
    """
    SSE(Server-Sent Events)로 Job 진행 상황을 실시간 스트리밍합니다.

    after_id=N 을 지정하면 DB event ID N 이후 이벤트만 전송합니다.
    초기 로드는 after_id=0(기본값), retry 재연결은 마지막 수신 ID를 전달합니다.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    return StreamingResponse(
        _sse_generator(job_id, request, start_after_id=after_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


async def _sse_generator(
    job_id: str,
    request: Request,
    start_after_id: int = 0,
) -> AsyncGenerator[str, None]:
    """
    SSE 이벤트 스트림 제너레이터.

    전략:
    1. event_bus에 알림 큐 등록 (이벤트 발생 시 즉시 깨어남)
    2. DB에서 start_after_id 이후 이벤트 전송 (재연결 시 중복 방지)
    3. 이미 완료된 Job이면 스트림 종료
    4. 알림 큐 대기 (최대 10초) → 깨어나면 DB 폴링으로 신규 이벤트 전송
    5. job_complete 수신 시 스트림 종료
    각 이벤트에 _db_id 필드를 삽입하여 클라이언트가 마지막 수신 ID를 추적할 수 있게 함
    """
    notify_q = subscribe(job_id)
    last_event_id: int = start_after_id

    try:
        # ── 기존 이벤트 전송 (히스토리 또는 누락분) ──────────────────────
        async with get_db() as db:
            history = await db_get_events(db, job_id, after_id=start_after_id)
            job = await db_get_job(db, job_id)

        for ev in history:
            last_event_id = ev["id"]
            # _db_id 필드 삽입 — 클라이언트가 재연결 시 after_id로 사용
            try:
                payload = json.loads(ev["data"])
                payload["_db_id"] = ev["id"]
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            except (json.JSONDecodeError, KeyError):
                yield f"data: {ev['data']}\n\n"

        # ── 이미 완료된 Job이면 스트림 종료 ─────────────────────────────
        if job and job["status"] in ("completed", "failed"):
            logger.debug("[SSE] 이미 완료된 Job, 스트림 종료: job=%s", job_id)
            return

        # ── 실시간 이벤트 스트리밍 ────────────────────────────────────────
        while True:
            # 클라이언트 연결 해제 감지
            if await request.is_disconnected():
                logger.debug("[SSE] 클라이언트 연결 해제: job=%s", job_id)
                break

            # 알림 큐 대기 (10초 타임아웃)
            try:
                await asyncio.wait_for(notify_q.get(), timeout=10.0)
            except asyncio.TimeoutError:
                # keepalive 코멘트 전송 (연결 유지)
                yield ": keepalive\n\n"
                continue

            # 알림 수신 → 남은 큐 비우기 (중복 깨우기 방지)
            while not notify_q.empty():
                try:
                    notify_q.get_nowait()
                except asyncio.QueueEmpty:
                    break

            # DB에서 신규 이벤트 조회 (last_event_id 이후)
            async with get_db() as db:
                new_events = await db_get_events(db, job_id, after_id=last_event_id)

            is_done = False
            for ev in new_events:
                last_event_id = ev["id"]
                try:
                    payload = json.loads(ev["data"])
                    payload["_db_id"] = ev["id"]
                    data_str = json.dumps(payload, ensure_ascii=False)
                    if payload.get("type") in ("job_complete", "error"):
                        is_done = True
                except (json.JSONDecodeError, KeyError):
                    data_str = ev["data"]
                yield f"data: {data_str}\n\n"

            if is_done:
                break

    except asyncio.CancelledError:
        logger.debug("[SSE] 스트림 취소됨: job=%s", job_id)
    except Exception:
        logger.exception("[SSE] 스트림 오류: job=%s", job_id)
    finally:
        unsubscribe(job_id, notify_q)


# ---------------------------------------------------------------------------
# GET /api/jobs/{job_id}/result — 완료된 Job 전체 결과
# ---------------------------------------------------------------------------


@router.get("/{job_id}/result", response_model=JobResult)
async def get_job_result(job_id: str) -> JobResult:
    """
    완료된 Job의 전체 결과를 반환합니다.

    SBOM 컴포넌트 목록, CVE 목록(VEX 상태 포함), 통합 VEX 문서,
    단계별 소요시간이 포함됩니다.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")
        stage_timings_raw = await db_get_stage_timings(db, job_id)

    # 분석 진행 중이면 부분 결과만 반환
    stage_timings = [
        StageTiming(
            stage=t["stage"],
            started_at=t["started_at"],
            completed_at=t.get("completed_at"),
            elapsed_seconds=t.get("elapsed_seconds"),
        )
        for t in stage_timings_raw
    ]

    storage_dir = Path(job["storage_dir"]) if job.get("storage_dir") else None

    # ── CVE 스캔 결과 파싱 (SBOM 크로스 참조를 위해 먼저 로드) ──────────
    raw_vulns = _load_scan_results(storage_dir, job.get("scan_result_path"))

    # ── SBOM 컴포넌트 파싱 (CVE count / max severity 포함) ─────────────
    sbom_components = _load_sbom_components(
        storage_dir, job.get("sbom_path"), scan_results=raw_vulns,
    )

    # ── VEX 상태 매핑 ────────────────────────────────────────────────────
    vex_document, vex_map = _load_vex(storage_dir, job.get("combined_vex_path"))

    # ── CVE + VEX 병합 ───────────────────────────────────────────────────
    cve_results = [
        CveResult(
            cve_id=v["cve_id"],
            package_name=v["package_name"],
            package_version=v["package_version"],
            severity=v["severity"],
            description=v["description"],
            fix_version=v.get("fix_version"),
            urls=v.get("urls", []),
            cvss_base_score=v.get("cvss_base_score"),
            cvss_vector=v.get("cvss_vector"),
            epss_score=v.get("epss_score"),
            epss_percentile=v.get("epss_percentile"),
            risk_score=v.get("risk_score"),
            cwes=v.get("cwes", []),
            vex_status=vex_map.get(v["cve_id"], {}).get("status", "unknown"),
            vex_justification=vex_map.get(v["cve_id"], {}).get("justification"),
            vex_detail=vex_map.get(v["cve_id"], {}).get("vex_detail"),
            analysis_grade=vex_map.get(v["cve_id"], {}).get("analysis_grade"),
            analysis_evidence=vex_map.get(v["cve_id"], {}).get("analysis_evidence"),
            analysis_model=vex_map.get(v["cve_id"], {}).get("analysis_model"),
        )
        for v in raw_vulns
    ]

    # VEX 집계는 ``jobs`` 테이블의 캐시 컬럼이 아니라 **현 시점 cve_results**
    # 에서 실시간 재계산한다.  Resume/Retry 를 여러 번 돌리면 runner 의
    # incremental 카운터가 0 부터 다시 시작해 stale 해지는 케이스가 있어
    # ``combined_vex`` / on-disk 결과와 뱃지가 어긋나던 문제를 막는다.
    live_affected = sum(1 for c in cve_results if c.vex_status == "affected")
    live_not_affected = sum(1 for c in cve_results if c.vex_status == "not_affected")
    live_investigating = sum(1 for c in cve_results if c.vex_status == "under_investigation")

    # Resume-from-SBOM 가능 조건: sbom.raw.json 존재.  EMBA 가 만들어둔 raw SBOM
    # 이 디스크에 있으면 fix_cpe / enrich / grype / VEX 만 재실행할 수 있다.
    resume_from_sbom = bool(storage_dir and (storage_dir / "sbom.raw.json").exists())

    return JobResult(
        id=job["id"],
        filename=job["filename"],
        status=JobStatus(job["status"]),
        product_name=job.get("product_name", ""),
        product_version=job.get("product_version", ""),
        component_count=job.get("component_count", len(sbom_components)),
        sbom_components=sbom_components,
        total_cves=job.get("total_cves", len(cve_results)),
        critical_cves=job.get("critical_cves", 0),
        high_cves=job.get("high_cves", 0),
        medium_cves=job.get("medium_cves", 0),
        low_cves=job.get("low_cves", 0),
        not_affected_count=live_not_affected,
        affected_count=live_affected,
        under_investigation_count=live_investigating,
        cve_results=cve_results,
        vex_document=vex_document,
        stage_timings=stage_timings,
        error_message=job.get("error_message"),
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
        resume_from_sbom_available=resume_from_sbom,
    )


# ---------------------------------------------------------------------------
# POST /api/jobs/{job_id}/resume-from-sbom — EMBA 후처리부터 이어서
# ---------------------------------------------------------------------------


@router.post("/{job_id}/resume-from-sbom", status_code=202)
async def resume_from_sbom(job_id: str, background_tasks: BackgroundTasks) -> dict:
    """``storage/<job>/sbom.raw.json`` 부터 fix_cpe → enrich_sbom → grype → VEX
    까지 이어서 실행한다.

    EMBA 추출/SBOM 생성 단계 (가장 무거운 20~60분 단계) 가 이미 끝나 sbom.raw.json
    이 있을 때, fix_cpe 등 후속 단계에서 실패한 잡을 처음부터 다시 돌리지 않고
    살리기 위한 엔드포인트.

    조건:
    - 잡 상태가 ``failed`` 이거나 ``sbom_generating`` 단계에서 멈춤
    - ``storage/<job>/sbom.raw.json`` 존재
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    storage_dir = Path(job["storage_dir"]) if job.get("storage_dir") else None
    if not storage_dir:
        raise HTTPException(status_code=422, detail="storage_dir 없음")
    sbom_raw = storage_dir / "sbom.raw.json"
    if not sbom_raw.exists():
        raise HTTPException(
            status_code=422,
            detail=f"sbom.raw.json 이 없습니다 ({sbom_raw}). EMBA 단계가 완료되지 않은 잡입니다 — "
                   f"처음부터 다시 업로드해야 합니다.",
        )

    # 후처리·이후 단계의 stale 산출물 폐기 (재실행 시 중복 / 일관성 문제 방지)
    for stale in (
        storage_dir / "sbom.fix.json",
        storage_dir / "sbom.cdx.json",
        storage_dir / "sbom.cdx.audit.json",
        storage_dir / "cpe_mapper.log",
        storage_dir / "scan.json",
        storage_dir / "combined_vex.json",
    ):
        if stale.exists():
            stale.unlink(missing_ok=True)
    vex_dir = storage_dir / "vex"
    if vex_dir.exists():
        shutil.rmtree(vex_dir, ignore_errors=True)

    async with get_db() as db:
        await db_update_job(
            db, job_id,
            status="sbom_generating",
            current_stage="sbom_generating",
            stage_progress=0,
            sbom_path=None,
            scan_result_path=None,
            combined_vex_path=None,
            component_count=0,
            not_affected_count=0,
            affected_count=0,
            under_investigation_count=0,
            error_message=None,
            completed_at=None,
        )

    import os
    from pipeline.runner import run_from_existing_sbom
    from pipeline.mock import run_mock_pipeline

    MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"
    if MOCK:
        background_tasks.add_task(run_mock_pipeline, job_id)
    else:
        background_tasks.add_task(run_from_existing_sbom, job_id)

    return {"job_id": job_id, "status": "sbom_generating", "mode": "resume-from-sbom"}


# ---------------------------------------------------------------------------
# POST /api/jobs/{job_id}/retry-vex — VEX 분석 재실행
# ---------------------------------------------------------------------------


@router.post("/{job_id}/retry-vex", status_code=202)
async def retry_vex(job_id: str, background_tasks: BackgroundTasks) -> dict:
    """
    기존 VEX 결과를 모두 삭제하고 모든 CVE 에 대해 VEX 분석을 처음부터 다시 실행합니다.

    삭제 대상: storage/{job}/vex/ 디렉토리 전체, combined_vex.json.
    Gemini 응답 원문/보고서/JSON 도 함께 폐기되며 첫 CVE 부터 다시 분석됩니다.
    특정 CVE 만 재실행하려면 /retry-vex/{cve_id} 를 사용하세요.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    if job["status"] not in ("completed", "failed", "vex_analyzing"):
        raise HTTPException(
            status_code=409,
            detail=f"VEX 재분석은 scanning 이후 상태에서만 가능합니다 (현재: {job['status']})",
        )

    storage_dir = Path(job["storage_dir"]) if job.get("storage_dir") else None
    if not storage_dir or not (storage_dir / "scan.json").exists():
        raise HTTPException(
            status_code=422,
            detail="scan.json이 없습니다. 스캔 단계부터 다시 실행해야 합니다.",
        )

    # ── 기존 VEX 결과 폐기 ─────────────────────────────────────────────
    vex_dir = storage_dir / "vex"
    if vex_dir.exists():
        shutil.rmtree(vex_dir, ignore_errors=True)
        logger.info("[retry-vex] 기존 vex/ 디렉토리 삭제: %s", vex_dir)
    combined = storage_dir / "combined_vex.json"
    if combined.exists():
        combined.unlink(missing_ok=True)

    # 집계 필드도 초기화해 프론트엔드가 깜빡이지 않게 한다
    async with get_db() as db:
        await db_update_job(
            db, job_id,
            status="vex_analyzing",
            current_stage="vex_analyzing",
            stage_progress=0,
            not_affected_count=0,
            affected_count=0,
            under_investigation_count=0,
            combined_vex_path=None,
            error_message=None,
            completed_at=None,
        )

    import os
    from pipeline.runner import run_vex_only
    from pipeline.mock import run_mock_pipeline

    MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"
    if MOCK:
        background_tasks.add_task(run_mock_pipeline, job_id)
    else:
        background_tasks.add_task(run_vex_only, job_id)

    return {"job_id": job_id, "status": "vex_analyzing", "mode": "fresh"}


@router.post("/{job_id}/resume-vex", status_code=202)
async def resume_vex(job_id: str, background_tasks: BackgroundTasks) -> dict:
    """
    중단된 VEX 분석을 이어서 실행합니다 (rate-limit 복구 후 재개 등).
    이미 완료된 CVE(vex/{cve_id}_vex.json 존재)는 건너뛰고
    미완료 CVE 부터 다시 분석합니다.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    if job["status"] not in ("completed", "failed", "vex_analyzing"):
        raise HTTPException(
            status_code=409,
            detail=f"VEX 이어서 분석은 scanning 이후 상태에서만 가능합니다 (현재: {job['status']})",
        )

    storage_dir = Path(job["storage_dir"]) if job.get("storage_dir") else None
    if not storage_dir or not (storage_dir / "scan.json").exists():
        raise HTTPException(
            status_code=422,
            detail="scan.json이 없습니다. 스캔 단계부터 다시 실행해야 합니다.",
        )

    async with get_db() as db:
        await db_update_job(
            db, job_id,
            status="vex_analyzing",
            current_stage="vex_analyzing",
            stage_progress=0,
            error_message=None,
            completed_at=None,
        )

    import os
    from pipeline.runner import run_vex_resume
    from pipeline.mock import run_mock_pipeline

    MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"
    if MOCK:
        background_tasks.add_task(run_mock_pipeline, job_id)
    else:
        background_tasks.add_task(run_vex_resume, job_id)

    return {"job_id": job_id, "status": "vex_analyzing", "mode": "resume"}


@router.post("/{job_id}/resume-vex/{cve_id}", status_code=202)
async def resume_vex_from(
    job_id: str, cve_id: str, background_tasks: BackgroundTasks,
) -> dict:
    """
    지정된 CVE 부터 VEX 분석을 이어서 실행합니다.

    스캔 정렬 기준으로 ``cve_id`` 와 그 이후 모든 CVE 의 기존 산출물
    (``vex/{CVE-ID}_*``) 을 삭제한 뒤 그 CVE 부터 다시 분석합니다.
    이전(상위) CVE 의 결과는 유지됩니다.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    if job["status"] not in ("completed", "failed", "vex_analyzing"):
        raise HTTPException(
            status_code=409,
            detail=f"VEX 이어서 분석은 scanning 이후 상태에서만 가능합니다 (현재: {job['status']})",
        )

    storage_dir = Path(job["storage_dir"]) if job.get("storage_dir") else None
    if not storage_dir or not (storage_dir / "scan.json").exists():
        raise HTTPException(
            status_code=422,
            detail="scan.json이 없습니다. 스캔 단계부터 다시 실행해야 합니다.",
        )

    if not job.get("rootfs_path"):
        raise HTTPException(
            status_code=422,
            detail="rootfs_path가 없습니다. 추출 단계부터 다시 실행해야 합니다.",
        )

    import os
    from pipeline.runner import run_vex_resume_from
    from pipeline.mock import run_mock_pipeline

    MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"
    if MOCK:
        background_tasks.add_task(run_mock_pipeline, job_id)
    else:
        background_tasks.add_task(run_vex_resume_from, job_id, cve_id)

    return {
        "job_id": job_id,
        "cve_id": cve_id,
        "status": "vex_analyzing",
        "mode": "resume_from",
    }


@router.post("/{job_id}/cancel-vex", status_code=202)
async def cancel_vex(job_id: str) -> dict:
    """
    진행 중인 VEX 분석을 취소합니다.
    현재 실행 중인 Gemini CLI 프로세스 그룹을 종료하고 배치 루프가 다음 CVE로
    넘어가지 않도록 취소 마커를 남깁니다.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    storage_dir = Path(job["storage_dir"]) if job.get("storage_dir") else None
    if not storage_dir:
        raise HTTPException(status_code=422, detail="storage_dir이 없습니다.")

    storage_dir.mkdir(parents=True, exist_ok=True)
    (storage_dir / ".cancel_vex").write_text(now_iso(), encoding="utf-8")

    from pipeline.vex import terminate_active_gemini_processes

    terminated = await terminate_active_gemini_processes("cancel-vex API")

    event = {
        "type": "batch_cancelled",
        "stage": "vex_analyzing",
        "message": "VEX 분석 취소 요청을 처리했습니다.",
        "terminated_processes": terminated,
        "job_id": job_id,
    }
    async with get_db() as db:
        await db_update_job(
            db,
            job_id,
            status="failed",
            current_stage="vex_analyzing",
            error_message="VEX 분석이 사용자 요청으로 취소되었습니다.",
            completed_at=now_iso(),
        )
        await db_add_event(db, job_id, event)
    broadcast(job_id, event)

    return {
        "job_id": job_id,
        "status": "cancelled",
        "terminated_processes": terminated,
    }


@router.post("/{job_id}/retry-vex/{cve_id}", status_code=202)
async def retry_vex_single(
    job_id: str,
    cve_id: str,
    background_tasks: BackgroundTasks,
    model: Optional[str] = Query(
        None,
        description=(
            "분석에 사용할 Gemini 모델.  ``gemini-3-pro-preview`` / "
            "``gemini-3-flash-preview`` 등 실제 모델명 지정 시 **해당 모델 "
            "고정** (폴백 없음).  생략 시 기본 정책 (Pro → Flash 자동 폴백)."
        ),
    ),
) -> dict:
    """
    특정 CVE에 대해서만 VEX 분석을 (재)실행합니다.
    완료 후 combined_vex.json을 전체 재빌드합니다.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

    if job["status"] not in ("completed", "failed", "vex_analyzing"):
        raise HTTPException(
            status_code=409,
            detail=f"VEX 분석은 scanning 이후 상태에서만 가능합니다 (현재: {job['status']})",
        )

    if not job.get("rootfs_path"):
        raise HTTPException(
            status_code=422,
            detail="rootfs_path가 없습니다. 추출 단계부터 다시 실행해야 합니다.",
        )

    import os
    from pipeline.runner import run_vex_single
    from pipeline.mock import run_mock_pipeline

    MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"
    if MOCK:
        background_tasks.add_task(run_mock_pipeline, job_id)
    else:
        background_tasks.add_task(run_vex_single, job_id, cve_id, model)

    return {
        "job_id": job_id,
        "cve_id": cve_id,
        "status": "vex_analyzing",
        "model": model,
    }


# ---------------------------------------------------------------------------
# DELETE /api/jobs/{job_id} — Job 삭제
# ---------------------------------------------------------------------------


@router.delete("/{job_id}", status_code=204, response_class=Response)
async def delete_job(job_id: str, force: bool = False) -> Response:
    """Job과 관련 파일을 삭제합니다.

    기본 동작은 ``completed/failed/pending`` 상태만 허용하지만,
    서버 재시작 등으로 실제로는 죽었는데 DB 상태만 ``vex_analyzing``
    같은 non-terminal 로 남아 있는 고아 Job 이 생길 수 있습니다.
    이런 경우 ``?force=true`` 로 강제 삭제가 가능합니다 — active
    Gemini 프로세스가 있다면 먼저 그 프로세스 그룹을 종료한 뒤 정리.
    """
    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job을 찾을 수 없습니다: {job_id}")

        if job["status"] not in ("completed", "failed", "pending") and not force:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"진행 중인 Job 은 삭제할 수 없습니다 (status: {job['status']}). "
                    "서버 재시작 등으로 멈춘 경우 ?force=true 로 강제 삭제하세요."
                ),
            )

        # force 경로: 혹시라도 이 프로세스에 active Gemini 가 남아있다면
        # 종료한 뒤 DB/파일을 삭제합니다.
        if force and job["status"] not in ("completed", "failed", "pending"):
            try:
                from pipeline.vex import terminate_active_gemini_processes
                await terminate_active_gemini_processes(f"force-delete {job_id}")
            except Exception:
                logger.warning("[Delete] force 종료 중 오류 (계속 진행): %s", job_id)

        # DB 레코드 삭제
        await db.execute("DELETE FROM job_events WHERE job_id = ?", (job_id,))
        await db.execute("DELETE FROM stage_timings WHERE job_id = ?", (job_id,))
        await db.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        await db.commit()

    # 저장 파일 삭제
    if job.get("storage_dir"):
        storage_path = Path(job["storage_dir"])
        if storage_path.exists():
            shutil.rmtree(storage_path, ignore_errors=True)

    logger.info("Job 삭제 완료: job=%s", job_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Result 파싱 헬퍼
# ---------------------------------------------------------------------------


_SEVERITY_RANK = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "": 0,
}


def _load_sbom_components(
    storage_dir: Optional[Path],
    sbom_path_str: Optional[str],
    scan_results: Optional[list[dict]] = None,
) -> list[SbomComponent]:
    """CycloneDX JSON 에서 컴포넌트 목록을 파싱합니다.

    - syft/sbom_claude_scripts 가 같은 패키지를 rootfs 의 여러 복제 경로
      (예: squashfs-root 와 그 내부 중첩 추출) 에서 찾아 (name, version)
      쌍이 중복된 컴포넌트 목록을 방출합니다.  여기서 한 번 dedup.
    - ``scan_results`` 가 주어지면 각 컴포넌트의 CVE 개수와 최고 심각도
      를 채워 SBOM 탭에서 "어떤 패키지가 위험한가?" 를 한눈에 확인할
      수 있게 합니다.
    """
    path = _resolve_path(storage_dir, sbom_path_str, "sbom.cdx.json")
    if not path or not path.exists():
        return []

    # bom-ref 가 우선, (name, version) 은 fallback.  grype 는 SBOM 의 bom-ref
    # 를 artifact.id 로 그대로 보존하므로 EMBA 의 group/name 합본 같은 표기
    # 차이와 무관하게 정확한 매칭이 가능하다.
    # 값: (total_count, max_rank, max_label, severity_counts_dict)
    by_ref: dict[str, tuple[int, int, str, dict[str, int]]] = {}
    by_name: dict[tuple[str, str], tuple[int, int, str, dict[str, int]]] = {}
    for m in scan_results or []:
        sev = (m.get("severity") or "UNKNOWN").upper()
        rank = _SEVERITY_RANK.get(sev, 0)
        ref = m.get("bom_ref", "") or ""
        name_key = (m.get("package_name", ""), m.get("package_version", ""))
        for bucket, k in ((by_ref, ref), (by_name, name_key)):
            if not k:
                continue
            prev_count, prev_rank, prev_label, prev_counts = bucket.get(
                k, (0, -1, "", {})
            )
            counts = dict(prev_counts)
            counts[sev] = counts.get(sev, 0) + 1
            bucket[k] = (
                prev_count + 1,
                max(prev_rank, rank),
                sev if rank > prev_rank else prev_label,
                counts,
            )

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("SBOM 파싱 실패: %s", path)
        return []

    seen: set[tuple[str, str]] = set()
    results: list[SbomComponent] = []
    for c in data.get("components", []):
        name = c.get("name", "")
        version = c.get("version", "")
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        ref = c.get("bom-ref", "") or ""
        cve_count, _, max_label, sev_counts = (
            by_ref.get(ref) or by_name.get(key, (0, -1, None, {}))
        )
        results.append(
            SbomComponent(
                name=name,
                version=version,
                type=c.get("type", ""),
                purl=c.get("purl"),
                licenses=[
                    lic.get("expression", lic.get("id", ""))
                    for lic in c.get("licenses", [])
                    if isinstance(lic, dict)
                ],
                cve_count=cve_count,
                max_severity=max_label or None,
                severity_counts=sev_counts,
            )
        )
    return results


def _load_scan_results(
    storage_dir: Optional[Path],
    scan_path_str: Optional[str],
) -> list[dict]:
    """grype JSON에서 취약점 목록을 파싱합니다."""
    path = _resolve_path(storage_dir, scan_path_str, "scan.json")
    if not path or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # syft가 같은 패키지를 rootfs 내 여러 경로(예: squashfs-root 와 그 복사본)
        # 에서 발견하면 grype 가 동일 (cve, 패키지, 버전) 조합을 각각의 위치마다
        # 매치로 중복 방출합니다. 프론트엔드 / VEX 분석은 CVE 단위로 동작하므로
        # 여기서 한 번 dedup 하는 게 가장 간단합니다.
        seen: set[tuple[str, str, str]] = set()
        results = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            # EMBA SBOM 은 component 의 group 필드에 vendor 를, name 에 product 만
            # 두는데 grype 는 SBOM 을 읽으면서 artifact.name 을
            # "<group>/<name>" 으로 합쳐 방출한다 (예: "OpenWRT/alsa-lib").
            # 표시·매칭 일관성을 위해 슬래시 뒤만 남겨 product name 으로 정규화.
            raw_name = artifact.get("name", "") or ""
            display_name = raw_name.rsplit("/", 1)[-1] if "/" in raw_name else raw_name
            bom_ref = artifact.get("id", "") or ""
            key = (
                vuln.get("id", "UNKNOWN"),
                display_name,
                artifact.get("version", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            fix_versions = vuln.get("fix", {}).get("versions", [])
            # CVSS — 여러 벤더 제출본 중 Primary (NVD) 를 우선으로, 없으면
            # 첫 항목 사용.
            cvss_list = vuln.get("cvss", []) or []
            primary_cvss = next(
                (c for c in cvss_list if c.get("type") == "Primary"),
                cvss_list[0] if cvss_list else {},
            )
            cvss_metrics = (primary_cvss.get("metrics") or {})
            # EPSS — grype 는 최신 단일 항목만 배열로 넣어둠.
            epss_list = vuln.get("epss", []) or []
            epss_entry = epss_list[0] if epss_list else {}
            # CWE 는 grype 가 "CWE-119" 형태의 문자열 리스트로 방출.
            cwes_raw = vuln.get("cwes", []) or []
            cwes = [c for c in cwes_raw if isinstance(c, str)]
            results.append({
                "cve_id": key[0],
                "package_name": key[1],
                "package_version": key[2],
                "bom_ref": bom_ref,
                "severity": vuln.get("severity", "UNKNOWN").upper(),
                "description": vuln.get("description", ""),
                "fix_version": fix_versions[0] if fix_versions else None,
                "urls": vuln.get("urls", []),
                "cvss_base_score": cvss_metrics.get("baseScore"),
                "cvss_vector": primary_cvss.get("vector"),
                "epss_score": epss_entry.get("epss"),
                "epss_percentile": epss_entry.get("percentile"),
                "risk_score": vuln.get("risk"),
                "cwes": cwes,
            })
        return results
    except Exception:
        logger.warning("scan.json 파싱 실패: %s", path)
        return []


_VEX_GRADE_RE = re.compile(r"\[GRADE\s*:\s*([A-D])\]", re.IGNORECASE)
_VEX_EVIDENCE_RE = re.compile(r"\[EVIDENCE\s*:\s*(HIGH|MEDIUM|LOW)\]", re.IGNORECASE)


def _vuln_id_from_stmt(stmt: dict) -> str:
    """OpenVEX statement 의 ``vulnerability`` 에서 CVE ID 추출 (str/dict 호환).

    OpenVEX 0.2.0 은 vulnerability 가 string("CVE-...") 또는 dict({"@id":..,
    "name":..}) 두 표기를 모두 허용한다. v5.0 모델 출력은 string 형이라
    기존 ``stmt.get("vulnerability", {}).get("name")`` 코드는 str 에서 .get
    호출하다 ``'str' object has no attribute 'get'`` 으로 터졌다.
    """
    v = stmt.get("vulnerability")
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, dict):
        name = v.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        vid = v.get("@id")
        if isinstance(vid, str) and "/" in vid:
            return vid.rsplit("/", 1)[-1]
    return ""


def _vex_grade_from_stmt(stmt: dict) -> Optional[str]:
    """Resolve GRADE (B/C/D) from an OpenVEX statement.

    Only meaningful when status == "affected".  Order:
    1. Explicit ``x_firmcore_grade`` field (set by v5.0+ runs).
    2. ``[GRADE: …]`` prefix in ``impact_statement``.
    3. ``None`` otherwise.
    """
    if stmt.get("status") != "affected":
        return None
    raw = stmt.get("x_firmcore_grade")
    if isinstance(raw, str) and raw.upper() in ("A", "B", "C", "D"):
        return raw.upper()
    m = _VEX_GRADE_RE.search(stmt.get("impact_statement") or "")
    return m.group(1).upper() if m else None


def _vex_evidence_from_stmt(stmt: dict) -> Optional[str]:
    """Resolve evidence confidence (HIGH/MEDIUM/LOW) from a statement."""
    raw = stmt.get("x_firmcore_evidence")
    if isinstance(raw, str) and raw.upper() in ("HIGH", "MEDIUM", "LOW"):
        return raw.upper()
    m = _VEX_EVIDENCE_RE.search(stmt.get("impact_statement") or "")
    return m.group(1).upper() if m else None


def _stmt_to_map_entry(
    stmt: dict,
    vex_dir: Optional[Path],
    cve_name: str,
) -> dict:
    """단일 OpenVEX statement → vex_map 항목 dict 변환 (공용 헬퍼)."""
    report_text: Optional[str] = None
    if vex_dir is not None:
        report_file = vex_dir / f"{cve_name}_report.md"
        if report_file.exists():
            try:
                report_text = report_file.read_text(encoding="utf-8")
            except Exception:
                pass
    return {
        "status": stmt.get("status", "unknown"),
        "justification": stmt.get("justification"),
        "vex_detail": report_text or stmt.get("x_firmcore_report") or stmt.get("impact_statement"),
        "analysis_grade": _vex_grade_from_stmt(stmt),
        "analysis_evidence": _vex_evidence_from_stmt(stmt),
        "analysis_model": stmt.get("x_firmcore_analysis_model"),
    }


def _load_vex(
    storage_dir: Optional[Path],
    vex_path_str: Optional[str],
) -> tuple[Optional[dict], dict[str, dict]]:
    """VEX 상태 매핑을 로드합니다.

    두 소스를 **mtime-aware merge** 합니다 — 분석 진행 중에는 개별
    ``vex/{CVE}_vex.json`` 만 새로 갱신되고 ``combined_vex.json`` 은 batch
    또는 단일 CVE 종료 후에만 재빌드되므로, combined 만 신뢰하면 화면이
    "있다가 없다가" 처럼 옛/새 상태를 오갈 수 있다.

    규칙:
      1. combined_vex.json 이 있으면 우선 그 statements 를 vex_map 에 채움.
      2. vex/*_vex.json 중 mtime 이 combined 보다 **새것** 인 파일은 그 항목을
         덮어쓰기 (분석 중에 막 떨어진 새 결과 반영).
      3. combined 가 아예 없으면 모든 개별 파일을 그대로 vex_map 에 채움.

    Returns
    -------
    (vex_document, {cve_id: {"status": ..., "vex_detail": ..., "analysis_grade": ..., ...}})
    """
    vex_map: dict[str, dict] = {}
    vex_doc: Optional[dict] = None
    combined_mtime: float = 0.0
    vex_dir: Optional[Path] = None
    if storage_dir is not None:
        vex_dir_candidate = storage_dir / "vex"
        if vex_dir_candidate.exists():
            vex_dir = vex_dir_candidate

    # 1) combined_vex.json 우선 로드
    combined_path = _resolve_path(storage_dir, vex_path_str, "combined_vex.json")
    if combined_path and combined_path.exists():
        try:
            vex_doc = json.loads(combined_path.read_text(encoding="utf-8"))
            combined_mtime = combined_path.stat().st_mtime
            for stmt in vex_doc.get("statements", []):
                cve_name = _vuln_id_from_stmt(stmt)
                if cve_name:
                    vex_map[cve_name] = _stmt_to_map_entry(stmt, vex_dir, cve_name)
        except Exception:
            logger.warning("combined_vex.json 파싱 실패: %s", combined_path)
            vex_doc = None
            combined_mtime = 0.0

    # 2) 개별 vex/*_vex.json 중 combined 보다 새것은 덮어쓰기
    #    (combined 가 없을 때는 combined_mtime=0 이라 모든 파일이 새것 취급)
    if vex_dir is not None:
        for vex_file in sorted(vex_dir.glob("*_vex.json")):
            try:
                file_mtime = vex_file.stat().st_mtime
                if file_mtime <= combined_mtime:
                    # 이미 combined 에 반영된 stale 파일 — 스킵
                    continue
                doc = json.loads(vex_file.read_text(encoding="utf-8"))
                for stmt in doc.get("statements", []):
                    cve_name = _vuln_id_from_stmt(stmt)
                    if not cve_name:
                        continue
                    vex_map[cve_name] = _stmt_to_map_entry(stmt, vex_dir, cve_name)
            except Exception:
                continue

    return vex_doc, vex_map


def _resolve_path(
    storage_dir: Optional[Path],
    explicit_path: Optional[str],
    default_filename: str,
) -> Optional[Path]:
    """
    DB에 저장된 경로 또는 storage_dir 기반 기본 경로를 반환합니다.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            return p
    if storage_dir:
        fallback = storage_dir / default_filename
        if fallback.exists():
            return fallback
    return None
