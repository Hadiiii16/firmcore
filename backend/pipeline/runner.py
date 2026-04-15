"""
runner.py — 파이프라인 오케스트레이터

각 단계(추출 → SBOM → 스캔 → VEX)를 순서대로 실행하며
DB 상태를 업데이트하고 SSE 이벤트를 브로드캐스트합니다.

모든 단계는 독립적인 aiosqlite 연결을 사용합니다.
실패 시 즉시 job status = failed 로 전환하고 이후 단계를 건너뜁니다.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from db import (
    STORAGE_DIR,
    db_add_event,
    db_end_stage,
    db_get_job,
    db_start_stage,
    db_update_job,
    get_db,
    now_iso,
)
from event_bus import broadcast
from pipeline.extractor import ExtractResult, extract_firmware
from pipeline.sbom import SbomResult, generate_sbom_multi
from pipeline.scanner import ScanResult, Vulnerability, scan_sbom
from pipeline.vex import VexResult, analyze_cve_batch

logger = logging.getLogger(__name__)

# VEX 분석 대상 CVE 최대 수 (Critical/High 우선)
MAX_VEX_CVES = int(os.environ.get("MAX_VEX_CVES", "20"))

# scanner._parse_vulnerabilities 재사용
from pipeline.scanner import _parse_vulnerabilities as _parse_scan_vulns

# severity 우선순위
_SEV_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                 "NEGLIGIBLE": 4, "UNKNOWN": 5}


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


async def run_vex_only(job_id: str) -> None:
    """
    이미 스캔이 완료된 Job에서 VEX 분석만 재실행합니다.
    scan.json이 존재해야 합니다.
    """
    logger.info("[Runner] VEX 재분석 시작: job=%s", job_id)

    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            logger.error("[Runner] Job 없음: %s", job_id)
            return

    storage_dir = Path(job["storage_dir"])
    rootfs_path_str = job.get("rootfs_path")
    if not rootfs_path_str:
        logger.error("[Runner] rootfs_path 없음: %s", job_id)
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message="rootfs_path가 저장되지 않아 VEX 재분석 불가",
                                completed_at=now_iso())
        return

    rootfs_path = Path(rootfs_path_str)
    product_info = {
        "name": job["product_name"] or "firmware",
        "version": job["product_version"] or "unknown",
    }

    # scan.json 로드
    scan_json = storage_dir / "scan.json"
    if not scan_json.exists():
        logger.error("[Runner] scan.json 없음: %s", job_id)
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message="scan.json이 없어 VEX 재분석 불가",
                                completed_at=now_iso())
        return

    try:
        import json as _json
        data = _json.loads(scan_json.read_text(encoding="utf-8"))
        vulnerabilities = _parse_scan_vulns(data)
    except Exception as exc:
        logger.error("[Runner] scan.json 파싱 실패: %s", exc)
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message=f"scan.json 파싱 실패: {exc}",
                                completed_at=now_iso())
        return

    # VEX 재분석 전 job 상태 초기화 (오류 메시지 삭제)
    async with get_db() as db:
        await db_update_job(db, job_id,
                            status="vex_analyzing",
                            error_message=None,
                            completed_at=None)

    from pipeline.scanner import ScanResult
    scan_result = ScanResult(
        vulnerabilities=vulnerabilities,
        counts_by_severity={},
        total_count=len(vulnerabilities),
        log=[],
        success=True,
    )

    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir)


async def run_pipeline(job_id: str) -> None:
    """
    펌웨어 분석 파이프라인을 실행합니다.
    FastAPI BackgroundTasks에서 호출됩니다.

    단계: extracting → sbom_generating → scanning → vex_analyzing → completed
    """
    logger.info("[Runner] 파이프라인 시작: job=%s", job_id)

    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            logger.error("[Runner] Job 없음: %s", job_id)
            return

    firmware_path = Path(job["firmware_path"])
    storage_dir = Path(job["storage_dir"])
    product_info = {
        "name": job["product_name"] or "firmware",
        "version": job["product_version"] or "unknown",
    }

    # ── Stage 1: 추출 ────────────────────────────────────────────────────
    extract_result = await _stage_extract(job_id, firmware_path, storage_dir)
    if extract_result is None:
        return  # _fail_job already called
    rootfs_path, rootfs_candidates = extract_result

    # ── Stage 2: SBOM 생성 ────────────────────────────────────────────────
    sbom_path = await _stage_sbom(job_id, rootfs_candidates, storage_dir)
    if sbom_path is None:
        return

    # ── Stage 3: CVE 스캔 ────────────────────────────────────────────────
    scan_result = await _stage_scan(job_id, sbom_path, storage_dir)
    if scan_result is None:
        return

    # ── Stage 4: VEX 분석 ────────────────────────────────────────────────
    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir)


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------


async def _stage_extract(
    job_id: str,
    firmware_path: Path,
    storage_dir: Path,
) -> Optional[tuple[Path, list[Path]]]:
    """추출 성공 시 (대표 rootfs, 모든 후보 목록) 반환."""
    stage = "extracting"
    t0 = time.monotonic()

    await _start_stage(job_id, stage)

    extract_dir = storage_dir / "extracted"
    log_count = 0
    rootfs: Optional[Path] = None
    candidates: list[Path] = []

    try:
        async for item in extract_firmware(firmware_path, extract_dir, job_id):
            if isinstance(item, str):
                log_count += 1
                progress = min(90, log_count * 3)
                await _emit_progress(job_id, stage, progress, item)

            elif isinstance(item, ExtractResult):
                if not item.success:
                    await _fail_job(job_id, stage, item.error or "binwalk 추출 실패")
                    return None
                rootfs = item.rootfs_path
                candidates = item.rootfs_candidates

    except Exception as exc:
        await _fail_job(job_id, stage, f"추출 단계 예외: {exc}")
        return None

    if rootfs is None:
        await _fail_job(job_id, stage, "rootfs를 탐지하지 못했습니다. 펌웨어 구조를 확인하세요.")
        return None

    elapsed = time.monotonic() - t0
    await _end_stage(job_id, stage, elapsed, rootfs_path=str(rootfs))
    return rootfs, candidates or [rootfs]


async def _stage_sbom(
    job_id: str,
    rootfs_candidates: list[Path],
    storage_dir: Path,
) -> Optional[Path]:
    stage = "sbom_generating"
    t0 = time.monotonic()

    await _start_stage(job_id, stage)

    log_count = 0
    sbom_path: Optional[Path] = None
    component_count = 0

    try:
        async for item in generate_sbom_multi(rootfs_candidates, storage_dir, job_id):
            if isinstance(item, str):
                log_count += 1
                progress = min(90, log_count * 5)
                await _emit_progress(job_id, stage, progress, item)

            elif isinstance(item, SbomResult):
                if not item.success:
                    await _fail_job(job_id, stage, item.error or "SBOM 생성 실패")
                    return None
                sbom_path = item.sbom_path
                component_count = item.component_count

    except Exception as exc:
        await _fail_job(job_id, stage, f"SBOM 단계 예외: {exc}")
        return None

    elapsed = time.monotonic() - t0
    await _end_stage(
        job_id, stage, elapsed,
        sbom_path=str(sbom_path),
        component_count=component_count,
    )
    return sbom_path


async def _stage_scan(
    job_id: str,
    sbom_path: Path,
    storage_dir: Path,
) -> Optional[ScanResult]:
    stage = "scanning"
    t0 = time.monotonic()

    await _start_stage(job_id, stage)

    log_count = 0
    scan_result: Optional[ScanResult] = None

    try:
        async for item in scan_sbom(sbom_path, storage_dir, job_id):
            if isinstance(item, str):
                log_count += 1
                progress = min(90, log_count * 4)
                await _emit_progress(job_id, stage, progress, item)

            elif isinstance(item, ScanResult):
                if not item.success:
                    await _fail_job(job_id, stage, item.error or "CVE 스캔 실패")
                    return None
                scan_result = item

    except Exception as exc:
        await _fail_job(job_id, stage, f"스캔 단계 예외: {exc}")
        return None

    counts = scan_result.counts_by_severity if scan_result else {}
    elapsed = time.monotonic() - t0
    await _end_stage(
        job_id, stage, elapsed,
        scan_result_path=str(storage_dir / "scan.json"),
        total_cves=scan_result.total_count if scan_result else 0,
        critical_cves=counts.get("CRITICAL", 0),
        high_cves=counts.get("HIGH", 0),
        medium_cves=counts.get("MEDIUM", 0),
        low_cves=counts.get("LOW", 0),
    )
    return scan_result


async def _stage_vex(
    job_id: str,
    scan_result: ScanResult,
    rootfs_path: Path,
    product_info: dict,
    storage_dir: Path,
) -> None:
    stage = "vex_analyzing"
    t0 = time.monotonic()

    await _start_stage(job_id, stage)

    # VEX 대상 CVE 선정: Critical/High 우선, 최대 MAX_VEX_CVES 개
    cves_to_analyze = _select_cves_for_vex(scan_result.vulnerabilities)
    total = len(cves_to_analyze)

    vex_result: Optional[VexResult] = None

    try:
        async for event in analyze_cve_batch(
            cves=cves_to_analyze,
            rootfs_path=rootfs_path,
            product_info=product_info,
            output_dir=storage_dir,
        ):
            event_type = event.get("type", "")

            # ── 상세 서버 로그 ────────────────────────────────────────────
            if event_type == "cve_start":
                logger.info("[VEX] (%d/%d) %s 분석 시작",
                            event.get("index", 0), event.get("total", 0), event.get("cve_id", ""))
            elif event_type == "gemini_response":
                logger.info("[VEX] Turn %d 응답 수신 (%d chars)",
                            event.get("turn", 0), len(event.get("content", "")))
            elif event_type == "executing_command":
                # 주석(#)과 빈 줄 제거 후 실제 명령어 줄만 로깅
                raw_cmd = event.get("command", "")
                cmd_lines = [
                    l.strip() for l in raw_cmd.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]
                if len(cmd_lines) == 1:
                    logger.info("[VEX] 명령 실행: %s", cmd_lines[0])
                else:
                    logger.info("[VEX] 명령 실행 (%d줄 스크립트):", len(cmd_lines))
                    for cl in cmd_lines:
                        logger.info("[VEX]   %s", cl)
            elif event_type == "command_result":
                # 상세 로깅은 vex.py에서 원본 stdout 기준으로 처리
                pass
            elif event_type == "vex_complete":
                stmt = event.get("statement")
                status = stmt.status if stmt else event.get("status", "?")
                logger.info("[VEX] %s → %s", event.get("cve_id", ""), status)
            elif event_type == "max_turns_reached":
                logger.warning("[VEX] %s 최대 턴 도달 → under_investigation", event.get("cve_id", ""))
            elif event_type == "cve_done":
                logger.info("[VEX] %s 완료: %s", event.get("cve_id", ""), event.get("status", ""))
            elif event_type == "error":
                logger.error("[VEX] 오류: %s", event.get("message", ""))

            # ── emit (직렬화 불가 객체 제거) ─────────────────────────────
            if event_type == "batch_complete":
                vex_result = event.get("vex_result")
                emit_event = {k: v for k, v in event.items() if k != "vex_result"}
                await _emit_event(job_id, emit_event)
            elif event_type in ("vex_complete",):
                emit_event = {k: v for k, v in event.items() if k != "statement"}
                await _emit_event(job_id, emit_event)
            else:
                await _emit_event(job_id, event)

            if event_type == "cve_start":
                idx = event.get("index", 0)
                progress = int((idx - 1) / max(total, 1) * 90)
                async with get_db() as db:
                    await db_update_job(db, job_id, stage_progress=progress)

    except Exception as exc:
        await _fail_job(job_id, stage, f"VEX 분석 단계 예외: {exc}")
        return

    combined_vex_path = storage_dir / "combined_vex.json"
    elapsed = time.monotonic() - t0

    not_affected = vex_result.not_affected_count if vex_result else 0
    affected = vex_result.affected_count if vex_result else 0
    under_inv = vex_result.under_investigation_count if vex_result else 0

    await _end_stage(
        job_id, stage, elapsed,
        combined_vex_path=str(combined_vex_path) if combined_vex_path.exists() else None,
        not_affected_count=not_affected,
        affected_count=affected,
        under_investigation_count=under_inv,
    )

    # ── 완료 ────────────────────────────────────────────────────────────
    async with get_db() as db:
        await db_update_job(
            db, job_id,
            status="completed",
            current_stage=None,
            stage_progress=100,
            completed_at=now_iso(),
        )
    complete_event = {"type": "job_complete", "status": "completed", "job_id": job_id}
    async with get_db() as db:
        await db_add_event(db, job_id, complete_event)
    broadcast(job_id, complete_event)
    logger.info("[Runner] 파이프라인 완료: job=%s", job_id)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _select_cves_for_vex(vulns: list[Vulnerability]) -> list[str]:
    """
    VEX 분석 대상 CVE를 severity 우선순위 기준으로 선정합니다.
    중복 CVE ID 제거, 최대 MAX_VEX_CVES 개 반환.
    """
    seen: set[str] = set()
    unique: list[Vulnerability] = []
    for v in sorted(vulns, key=lambda v: _SEV_PRIORITY.get(v.severity.upper(), 99)):
        if v.cve_id not in seen:
            seen.add(v.cve_id)
            unique.append(v)

    return [v.cve_id for v in unique[:MAX_VEX_CVES]]


async def _emit_event(job_id: str, event: dict) -> None:
    """이벤트를 DB에 저장하고 SSE 구독자에게 브로드캐스트합니다."""
    async with get_db() as db:
        await db_add_event(db, job_id, {**event, "job_id": job_id})
    broadcast(job_id, {**event, "job_id": job_id})


async def _emit_progress(
    job_id: str,
    stage: str,
    progress: int,
    log: str,
) -> None:
    event = {
        "type": "stage_progress",
        "stage": stage,
        "progress": progress,
        "log": log,
        "job_id": job_id,
    }
    async with get_db() as db:
        await db_update_job(db, job_id, stage_progress=progress)
        await db_add_event(db, job_id, event)
    broadcast(job_id, event)


async def _start_stage(job_id: str, stage: str) -> None:
    event = {"type": "stage_start", "stage": stage, "job_id": job_id}
    async with get_db() as db:
        await db_update_job(db, job_id, status=stage, current_stage=stage, stage_progress=0)
        await db_start_stage(db, job_id, stage)
        await db_add_event(db, job_id, event)
    broadcast(job_id, event)
    logger.info("[Runner] 단계 시작: job=%s stage=%s", job_id, stage)


async def _end_stage(job_id: str, stage: str, elapsed: float, **extra_job_cols) -> None:
    event = {
        "type": "stage_complete",
        "stage": stage,
        "elapsed": round(elapsed, 2),
        "job_id": job_id,
    }
    async with get_db() as db:
        await db_update_job(db, job_id, stage_progress=100, **extra_job_cols)
        await db_end_stage(db, job_id, stage, elapsed)
        await db_add_event(db, job_id, event)
    broadcast(job_id, event)
    logger.info("[Runner] 단계 완료: job=%s stage=%s (%.1fs)", job_id, stage, elapsed)


async def _fail_job(job_id: str, stage: str, error: str) -> None:
    logger.error("[Runner] 단계 실패: job=%s stage=%s → %s", job_id, stage, error)
    error_event = {
        "type": "error",
        "stage": stage,
        "message": error,
        "job_id": job_id,
    }
    complete_event = {
        "type": "job_complete",
        "status": "failed",
        "job_id": job_id,
    }
    async with get_db() as db:
        await db_update_job(
            db, job_id,
            status="failed",
            current_stage=stage,
            error_message=error,
            completed_at=now_iso(),
        )
        await db_add_event(db, job_id, error_event)
        await db_add_event(db, job_id, complete_event)
    broadcast(job_id, error_event)
    broadcast(job_id, complete_event)
