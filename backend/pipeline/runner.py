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
from pipeline.emba import run_emba_extract_sbom, run_sbom_post_processing
from pipeline.scanner import ScanResult, Vulnerability, scan_sbom
from pipeline.vex import VexResult, VexStatement, analyze_cve_batch
# Legacy — binwalk + syft 경로.  EMBA 로 교체됐지만 MOCK 모드와 향후 fallback
# 여지를 위해 import 만 보존.  실제 호출처는 모두 _stage_emba_pipeline 으로
# 이동했다.
from pipeline.extractor import ExtractResult, extract_firmware  # noqa: F401
from pipeline.sbom import SbomResult, generate_sbom_multi  # noqa: F401

logger = logging.getLogger(__name__)

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


async def run_vex_resume(job_id: str) -> None:
    """
    중단된 VEX 분석을 이어서 실행합니다.
    이미 완료된 CVE (vex/{cve_id}_vex.json 존재)는 건너뜁니다.
    """
    logger.info("[Runner] VEX 이어서 분석 시작: job=%s", job_id)

    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            logger.error("[Runner] Job 없음: %s", job_id)
            return

    storage_dir = Path(job["storage_dir"])
    rootfs_path_str = job.get("rootfs_path")
    if not rootfs_path_str:
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

    scan_json = storage_dir / "scan.json"
    if not scan_json.exists():
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
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message=f"scan.json 파싱 실패: {exc}",
                                completed_at=now_iso())
        return

    # 이미 완료된 CVE 파악 (vex/{cve_id}_vex.json 존재 여부)
    vex_dir = storage_dir / "vex"
    all_cves = _select_cves_for_vex(vulnerabilities)
    remaining = [c for c in all_cves if not (vex_dir / f"{c}_vex.json").exists()]

    logger.info("[Runner] VEX 이어서: 전체 %d개 중 %d개 미완료", len(all_cves), len(remaining))

    if not remaining:
        logger.info("[Runner] 모든 CVE가 이미 완료됨 — combined_vex.json만 재빌드")
        from pipeline.vex import rebuild_combined_vex_from_dir
        rebuild_combined_vex_from_dir(product_info, vex_dir, storage_dir)
        async with get_db() as db:
            await db_update_job(db, job_id, status="completed",
                                error_message=None, completed_at=now_iso())
        return

    async with get_db() as db:
        await db_update_job(db, job_id, status="vex_analyzing",
                            error_message=None, completed_at=None)

    from pipeline.scanner import ScanResult
    # 미완료 CVE만 포함한 가상 ScanResult (진행률 계산용)
    filtered_vulns = [v for v in vulnerabilities if v.cve_id in remaining]
    scan_result = ScanResult(
        vulnerabilities=filtered_vulns,
        counts_by_severity={},
        total_count=len(filtered_vulns),
        log=[],
        success=True,
    )

    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir,
                     cve_override=remaining)


async def run_vex_resume_from(job_id: str, start_cve_id: str) -> None:
    """
    지정된 CVE 부터 이어서 VEX 분석을 실행합니다.

    스캔 정렬 기준(severity 우선순위 + CVE ID) 으로 ``start_cve_id`` 의
    인덱스를 찾고, 그 인덱스 이상의 모든 CVE 에 대한 기존 산출물
    (``vex/{CVE-ID}_*``) 을 삭제한 뒤 분석을 재개합니다.
    이전(상위) CVE 의 결과는 그대로 보존되며, ``run_vex_resume`` 와 동일하게
    이미 결과가 있는 CVE 는 자동으로 skip 됩니다 — 단, 이번 호출에서
    삭제했기 때문에 ``start_cve_id`` 이후는 모두 새로 분석됩니다.
    """
    logger.info("[Runner] VEX 지정 CVE부터 이어서 분석: job=%s start=%s",
                job_id, start_cve_id)

    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            logger.error("[Runner] Job 없음: %s", job_id)
            return

    storage_dir = Path(job["storage_dir"])
    rootfs_path_str = job.get("rootfs_path")
    if not rootfs_path_str:
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

    scan_json = storage_dir / "scan.json"
    if not scan_json.exists():
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message="scan.json이 없어 VEX 재분석 불가",
                                completed_at=now_iso())
        return

    try:
        data = json.loads(scan_json.read_text(encoding="utf-8"))
        vulnerabilities = _parse_scan_vulns(data)
    except Exception as exc:
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message=f"scan.json 파싱 실패: {exc}",
                                completed_at=now_iso())
        return

    all_cves = _select_cves_for_vex(vulnerabilities)
    try:
        start_idx = all_cves.index(start_cve_id)
    except ValueError:
        async with get_db() as db:
            await db_update_job(
                db, job_id, status="failed",
                error_message=f"{start_cve_id} 가 스캔 결과에 없습니다.",
                completed_at=now_iso(),
            )
        return

    targets = all_cves[start_idx:]

    # 지정된 CVE 부터의 기존 산출물 삭제 — 그래야 _stage_vex 의
    # cve_override 가 모두 새로 분석됩니다.
    vex_dir = storage_dir / "vex"
    if vex_dir.exists():
        for cve in targets:
            for suffix in ("_vex.json", "_report.md", "_gemini_yolo.md", "_pty_raw.log"):
                p = vex_dir / f"{cve}{suffix}"
                if p.exists():
                    p.unlink(missing_ok=True)
        logger.info("[Runner] %s 이후 %d개 CVE 산출물 삭제",
                    start_cve_id, len(targets))

    # combined_vex.json 도 부분 재시도이므로 무효화 — 배치 종료 시 재빌드됨.
    combined = storage_dir / "combined_vex.json"
    if combined.exists():
        combined.unlink(missing_ok=True)

    async with get_db() as db:
        await db_update_job(db, job_id, status="vex_analyzing",
                            current_stage="vex_analyzing",
                            stage_progress=0,
                            error_message=None, completed_at=None)

    from pipeline.scanner import ScanResult
    filtered_vulns = [v for v in vulnerabilities if v.cve_id in targets]
    scan_result = ScanResult(
        vulnerabilities=filtered_vulns,
        counts_by_severity={},
        total_count=len(filtered_vulns),
        log=[],
        success=True,
    )

    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir,
                     cve_override=targets)


async def run_vex_single(
    job_id: str, cve_id: str, model: Optional[str] = None,
) -> None:
    """
    단일 CVE에 대해서만 VEX 분석을 실행합니다.
    완료 후 combined_vex.json을 전체 재빌드합니다.

    ``model`` 이 지정되면 해당 모델로 **고정** 분석 (폴백 없음).  사용자가
    UI 에서 "Re-analyze (Pro)" / "Re-analyze (Flash)" 처럼 명시 선택할 때
    사용.
    """
    logger.info("[Runner] 단일 CVE VEX 분석: job=%s cve=%s", job_id, cve_id)

    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            logger.error("[Runner] Job 없음: %s", job_id)
            return

    storage_dir = Path(job["storage_dir"])
    rootfs_path_str = job.get("rootfs_path")
    if not rootfs_path_str:
        async with get_db() as db:
            await db_update_job(db, job_id, status="failed",
                                error_message="rootfs_path가 저장되지 않아 VEX 분석 불가",
                                completed_at=now_iso())
        return

    rootfs_path = Path(rootfs_path_str)
    product_info = {
        "name": job["product_name"] or "firmware",
        "version": job["product_version"] or "unknown",
    }

    async with get_db() as db:
        await db_update_job(db, job_id, status="vex_analyzing",
                            error_message=None, completed_at=None)

    from pipeline.scanner import ScanResult, Vulnerability
    # scan.json 에서 해당 CVE 의 실제 메타데이터(description, package,
    # severity 등) 를 읽어 Vulnerability 객체를 복원한다.  이전에는
    # 빈 값 가상 Vulnerability 로 채워서 Gemini 프롬프트에 CVE 맥락이
    # 전혀 실리지 않아 "취약 컴포넌트 정보 누락" 이라며 분석이 실패
    # 했다.  scan.json 이 없거나 해당 CVE 가 없을 때만 가상 객체로
    # 폴백.
    real_vuln: Optional[Vulnerability] = None
    scan_json = storage_dir / "scan.json"
    if scan_json.exists():
        try:
            _data = json.loads(scan_json.read_text(encoding="utf-8"))
            for v in _parse_scan_vulns(_data):
                if v.cve_id == cve_id:
                    real_vuln = v
                    break
        except Exception as exc:
            logger.warning(
                "[Runner] %s scan.json 에서 %s 메타데이터 조회 실패: %s",
                job_id, cve_id, exc,
            )
    if real_vuln is None:
        logger.warning(
            "[Runner] %s scan.json 에 %s 메타데이터 없음 → 빈 맥락으로 분석",
            job_id, cve_id,
        )
        real_vuln = Vulnerability(
            cve_id=cve_id, package_name="", package_version="",
            severity="UNKNOWN", description="", fix_version=None, urls=[],
        )

    scan_result = ScanResult(
        vulnerabilities=[real_vuln],
        counts_by_severity={},
        total_count=1,
        log=[],
        success=True,
    )

    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir,
                     cve_override=[cve_id], model_override=model)

    # 완료 후 combined_vex.json 전체 재빌드 (기존 완료 CVE 포함)
    vex_dir = storage_dir / "vex"
    if vex_dir.exists():
        from pipeline.vex import rebuild_combined_vex_from_dir
        rebuild_combined_vex_from_dir(product_info, vex_dir, storage_dir)
        logger.info("[Runner] combined_vex.json 재빌드 완료 (단일 CVE 후)")


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

    # ── Stage 1 + 2: EMBA 추출 + SBOM + CPE 후처리 (통합) ───────────────
    # EMBA 가 펌웨어를 직접 추출하고 SBOM 까지 만든 뒤, fix_cpe.py + enrich_sbom.py
    # 가 CPE 를 보정하여 storage/<job>/sbom.cdx.json 을 생성한다.  EMBA 의 P##
    # 모듈은 extracting stage, S## 모듈 + 후처리는 sbom_generating stage 로 표시.
    emba_result = await _stage_emba_pipeline(
        job_id, firmware_path, storage_dir, product_info=product_info,
    )
    if emba_result is None:
        return  # _fail_job already called
    sbom_path, rootfs_path = emba_result

    # ── Stage 3: CVE 스캔 (grype, 변경 없음) ─────────────────────────────
    scan_result = await _stage_scan(job_id, sbom_path, storage_dir)
    if scan_result is None:
        return

    # ── Stage 4: VEX 분석 (Gemini/Codex, 변경 없음) ──────────────────────
    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir)


# ---------------------------------------------------------------------------
# Resume-from-SBOM — EMBA 가 만든 sbom.raw.json 이 이미 있을 때 후속 단계만
# 재실행한다.  EMBA(추출 + SBOM 생성) 가 가장 무거운 단계(수십분~1시간) 인데
# 여기서 실패하지 않았고 fix_cpe / enrich / grype / VEX 단계에서 깨진 경우,
# 처음부터 다시 돌리는 비용을 회피한다.
# ---------------------------------------------------------------------------


async def run_from_existing_sbom(job_id: str) -> None:
    """``storage/<job>/sbom.raw.json`` 에서 시작해 fix_cpe → enrich → grype →
    VEX 까지 진행한다.

    extracting 단계는 EMBA 결과 디렉토리에서 rootfs_path 만 복구.  EMBA 자체는
    재실행하지 않는다 (사용 의도: SBOM 만들기 단계는 끝났는데 후처리에서 막혔거나
    사용자가 후속 단계만 다시 돌리고 싶을 때).
    """
    logger.info("[Runner] Resume-from-SBOM 시작: job=%s", job_id)

    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            logger.error("[Runner] Job 없음: %s", job_id)
            return

    storage_dir = Path(job["storage_dir"])
    sbom_raw = storage_dir / "sbom.raw.json"
    if not sbom_raw.exists():
        await _fail_job(
            job_id, "sbom_generating",
            f"resume 불가: sbom.raw.json 없음 ({sbom_raw}). EMBA 단계가 끝나지 않았던 잡입니다."
        )
        return

    product_info = {
        "name": job["product_name"] or "firmware",
        "version": job["product_version"] or "unknown",
    }
    # rootfs_path 복원 우선순위:
    #   1) DB 의 rootfs_path (잡이 sbom_generating 단계까지 끝나 _end_stage 가
    #      실행됐을 때만 채워짐 — fix_cpe 실패 잡은 보통 비어있음)
    #   2) storage/<job>/emba_logs/ 에서 _find_emba_rootfs (squashfs-root /
    #      ubi_extracted/.../rootfs / Linux 시그니처 디렉토리 자동 탐색)
    rootfs_path: Optional[Path] = None
    if job.get("rootfs_path"):
        cand = Path(job["rootfs_path"])
        if cand.exists():
            rootfs_path = cand
    if rootfs_path is None:
        emba_log_dir = storage_dir / "emba_logs"
        if emba_log_dir.exists():
            from pipeline.emba import _find_emba_rootfs
            try:
                rootfs_path = _find_emba_rootfs(emba_log_dir)
            except Exception as exc:
                logger.warning("[Runner] _find_emba_rootfs 예외: %s", exc)
            if rootfs_path is None:
                # 마지막 fallback — emba_logs/firmware 그대로
                firmware_dir = emba_log_dir / "firmware"
                if firmware_dir.exists():
                    rootfs_path = firmware_dir
            if rootfs_path is not None:
                logger.info("[Runner] rootfs 복원: %s", rootfs_path)

    sbom_stage = "sbom_generating"
    t0 = time.monotonic()
    await _start_stage(job_id, sbom_stage)

    sbom_path: Optional[Path] = None
    component_count = 0
    log_count = 0
    try:
        async for event in run_sbom_post_processing(
            sbom_raw, storage_dir,
            rootfs_path=rootfs_path,
            emba_log_dir=storage_dir / "emba_logs",
        ):
            etype = event.get("type")
            if etype == "stage_progress":
                log_count += 1
                progress = min(90, log_count * 5)
                await _emit_progress(job_id, sbom_stage, progress, event.get("log", ""))
            elif etype == "stage_percent":
                # enrich_sbom tqdm — progress bar 만 갱신, log 미발사
                pct = int(event.get("progress") or 0)
                await _emit_progress(job_id, sbom_stage, pct, "")
            elif etype == "error":
                msg = event.get("message") or "SBOM 후처리 실패"
                await _fail_job(job_id, sbom_stage, msg)
                return
            elif etype == "emba_pipeline_complete":
                sbom_path = Path(event["sbom_path"])
                component_count = int(event.get("component_count") or 0)
                break
    except Exception as exc:
        logger.exception("[Runner] Resume-from-SBOM 예외")
        await _fail_job(job_id, sbom_stage, f"Resume-from-SBOM 예외: {exc}")
        return

    if sbom_path is None or not sbom_path.exists():
        await _fail_job(job_id, sbom_stage, "후처리가 sbom.cdx.json 을 생성하지 못함")
        return

    elapsed_sbom = time.monotonic() - t0
    await _end_stage(
        job_id, sbom_stage, elapsed_sbom,
        sbom_path=str(sbom_path),
        component_count=component_count,
        rootfs_path=str(rootfs_path) if rootfs_path else None,
    )

    # 이어서 scanning + vex_analyzing
    scan_result = await _stage_scan(job_id, sbom_path, storage_dir)
    if scan_result is None:
        return
    if rootfs_path is None:
        await _fail_job(
            job_id, "vex_analyzing",
            "rootfs_path 복원 실패 — VEX 분석 불가. 잡을 처음부터 다시 돌려야 합니다."
        )
        return
    await _stage_vex(job_id, scan_result, rootfs_path, product_info, storage_dir)


# ---------------------------------------------------------------------------
# Stage runners
# ---------------------------------------------------------------------------


async def _stage_emba_pipeline(
    job_id: str,
    firmware_path: Path,
    storage_dir: Path,
    product_info: Optional[dict] = None,
) -> Optional[tuple[Path, Path]]:
    """EMBA 추출 + SBOM 생성 + CPE 후처리를 단일 함수로 통합.

    EMBA 한 번의 호출이 펌웨어 추출과 SBOM 생성을 모두 수행하므로 기존의
    ``_stage_extract`` + ``_stage_sbom`` 두 단계를 함수 하나로 합쳤다.  UI/DB
    측 단계 표시는 그대로 ``extracting`` → ``sbom_generating`` 두 단계로
    유지하기 위해 EMBA stdout 의 P##/S## 모듈 마커를 보고 stage 전환 이벤트를
    적절한 시점에 발사한다.

    반환: (sbom_path, rootfs_path) — 둘 다 절대경로.
    """
    extract_stage = "extracting"
    sbom_stage = "sbom_generating"
    t0 = time.monotonic()
    extract_started_ts = t0
    sbom_started_ts: Optional[float] = None

    await _start_stage(job_id, extract_stage)
    current_stage = extract_stage

    sbom_path: Optional[Path] = None
    rootfs_path: Optional[Path] = None
    emba_log_dir: Optional[Path] = None
    component_count = 0
    log_count = 0

    try:
        async for event in run_emba_extract_sbom(
            firmware_path, storage_dir, job_id, product_info=product_info,
        ):
            etype = event.get("type")

            if etype == "stage_transition":
                # EMBA 가 P 모듈 → S 모듈 로 전환 = extracting 완료 + sbom_generating 시작
                if event.get("from") == "extracting" and current_stage == extract_stage:
                    elapsed = time.monotonic() - extract_started_ts
                    await _end_stage(job_id, extract_stage, elapsed)
                    await _start_stage(job_id, sbom_stage)
                    current_stage = sbom_stage
                    sbom_started_ts = time.monotonic()
                continue

            if etype == "stage_progress":
                log_count += 1
                progress = min(90, log_count * 2)
                # event 안의 stage 가 아닌 실제 current_stage 로 emit
                # (run_emba 가 보낸 stage 와 일치하지만 안전 가드)
                await _emit_progress(job_id, current_stage, progress, event.get("log", ""))
                continue

            if etype == "stage_percent":
                # enrich_sbom 의 tqdm progress — PipelineStepper 의 progress bar
                # 만 갱신하고 log 는 미발사 (사용자 화면에 update 마다 한 줄씩
                # 누적되는 노이즈 차단).
                pct = int(event.get("progress") or 0)
                await _emit_progress(job_id, current_stage, pct, "")
                continue

            if etype == "error":
                msg = event.get("message") or "EMBA 파이프라인 실패"
                await _fail_job(job_id, current_stage, msg)
                return None

            if etype == "emba_pipeline_complete":
                sbom_path = Path(event["sbom_path"])
                rootfs_str = event.get("rootfs_path")
                rootfs_path = Path(rootfs_str) if rootfs_str else None
                emba_log_dir_str = event.get("emba_log_dir")
                emba_log_dir = Path(emba_log_dir_str) if emba_log_dir_str else None
                component_count = int(event.get("component_count") or 0)
                break

    except Exception as exc:
        logger.exception("[Runner] EMBA 파이프라인 예외")
        await _fail_job(job_id, current_stage, f"EMBA 파이프라인 예외: {exc}")
        return None

    if sbom_path is None or not sbom_path.exists():
        await _fail_job(job_id, current_stage, "EMBA 파이프라인이 sbom.cdx.json 을 생성하지 못함")
        return None

    if rootfs_path is None:
        # EMBA 가 SBOM 은 만들었으나 squashfs-root 후보를 못 찾은 케이스.
        # 추출 결과 디렉토리(emba_log_dir/firmware) 자체를 rootfs 로 fallback —
        # VEX 분석 시 정확도가 떨어지지만 SBOM/CVE 스캔까지는 진행 가능.
        # emba_log_dir 은 product 기반 leaf 이름이라 emba.py 에서 받아온 값을 사용.
        fallback_root = (emba_log_dir / "firmware") if emba_log_dir else None
        if fallback_root and fallback_root.exists():
            rootfs_path = fallback_root
            logger.warning("[Runner] rootfs 미식별 — fallback to %s", fallback_root)
        else:
            await _fail_job(job_id, sbom_stage, "EMBA 추출 결과에서 rootfs 후보를 찾지 못함")
            return None

    # sbom_generating 단계 종료 (DB column 업데이트)
    elapsed_sbom = time.monotonic() - (sbom_started_ts or extract_started_ts)
    await _end_stage(
        job_id, sbom_stage, elapsed_sbom,
        sbom_path=str(sbom_path),
        component_count=component_count,
        rootfs_path=str(rootfs_path),
    )

    return sbom_path, rootfs_path


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
    cve_override: Optional[list[str]] = None,
    model_override: Optional[str] = None,
) -> None:
    stage = "vex_analyzing"
    t0 = time.monotonic()

    await _start_stage(job_id, stage)
    cancel_marker = storage_dir / ".cancel_vex"
    cancel_marker.unlink(missing_ok=True)

    # CVE 목록: 외부에서 명시적으로 전달된 경우 우선 사용 (resume/single 모드)
    cves_to_analyze = cve_override if cve_override is not None else _select_cves_for_vex(scan_result.vulnerabilities)
    total = len(cves_to_analyze)

    # Build a quick lookup for raw vuln data so we can attach a full
    # CveResult payload to each cve_done event. This lets the frontend
    # merge one CVE at a time without re-fetching /result.
    vuln_map: dict[str, Vulnerability] = {
        v.cve_id: v for v in scan_result.vulnerabilities
    }
    pending_stmt: dict[str, VexStatement] = {}

    vex_result: Optional[VexResult] = None
    vex_cancelled = False
    vex_rate_limited: Optional[dict] = None
    # Incremental VEX status counts.  Updated per cve_done so the dashboard
    # (5-second polling on /api/jobs) and the detail page (refresh while
    # analysis is in progress) reflect partial progress instead of staying
    # at 0/0/0 until the batch finishes.
    inc_not_affected = 0
    inc_affected = 0
    inc_under_inv = 0

    # grype 가 이미 수집한 CVE 메타데이터를 Gemini 에 그대로 넘겨 중복
    # 검색(GoogleSearch 등)으로 인한 쿼터 낭비를 줄인다.
    vuln_info_map: dict[str, dict] = {
        cve_id: {
            "package_name": v.package_name,
            "package_version": v.package_version,
            "severity": v.severity,
            "description": v.description,
            "fix_version": v.fix_version,
            "urls": list(v.urls),
        }
        for cve_id, v in vuln_map.items()
    }

    try:
        async for event in analyze_cve_batch(
            cves=cves_to_analyze,
            rootfs_path=rootfs_path,
            product_info=product_info,
            output_dir=storage_dir,
            vuln_map=vuln_info_map,
            model_override=model_override,
        ):
            event_type = event.get("type", "")

            # ── 상세 서버 로그 ────────────────────────────────────────────
            if event_type == "cve_start":
                logger.info("[VEX] (%d/%d) %s 분석 시작",
                            event.get("index", 0), event.get("total", 0), event.get("cve_id", ""))
            elif event_type == "gemini_response":
                logger.info("[VEX] Turn %d 응답 수신 (%d chars)",
                            event.get("turn", 0), len(event.get("content", "")))
            elif event_type == "vex_complete":
                stmt = event.get("statement")
                status = stmt.status if stmt else event.get("status", "?")
                logger.info("[VEX] %s → %s", event.get("cve_id", ""), status)
            elif event_type == "vex_json_not_found":
                logger.warning(
                    "[VEX] %s OpenVEX JSON 추출 실패 → under_investigation (fallback)",
                    event.get("cve_id", ""),
                )
            elif event_type == "cve_done":
                logger.info("[VEX] %s 완료: %s", event.get("cve_id", ""), event.get("status", ""))
            elif event_type == "error":
                logger.error("[VEX] 오류: %s", event.get("message", ""))
            elif event_type == "batch_cancelled":
                logger.warning("[VEX] 분석 취소: %s", event.get("message", ""))
                vex_cancelled = True
            elif event_type == "batch_rate_limited":
                logger.warning(
                    "[VEX] Gemini rate-limit — %s (%d/%d) retry_after=%s",
                    event.get("cve_id", ""), event.get("index", 0),
                    event.get("total", 0), event.get("retry_after"),
                )
                vex_rate_limited = event

            # ── emit (직렬화 불가 객체 제거) ─────────────────────────────
            if event_type == "batch_complete":
                vex_result = event.get("vex_result")
                emit_event = {k: v for k, v in event.items() if k != "vex_result"}
                await _emit_event(job_id, emit_event)
            elif event_type == "vex_complete":
                stmt_obj = event.get("statement")
                if isinstance(stmt_obj, VexStatement):
                    pending_stmt[stmt_obj.cve_id] = stmt_obj
                emit_event = {k: v for k, v in event.items() if k != "statement"}
                await _emit_event(job_id, emit_event)
            elif event_type == "cve_done":
                cve_id = event.get("cve_id", "")
                emit_event = dict(event)
                vuln = vuln_map.get(cve_id)
                stmt = pending_stmt.pop(cve_id, None)
                if vuln is not None:
                    emit_event["cve_result"] = {
                        "cve_id": vuln.cve_id,
                        "package_name": vuln.package_name,
                        "package_version": vuln.package_version,
                        "severity": vuln.severity,
                        "description": vuln.description,
                        "fix_version": vuln.fix_version,
                        "urls": list(vuln.urls),
                        "vex_status": stmt.status if stmt else event.get("status"),
                        "vex_justification": stmt.justification if stmt else None,
                        "vex_detail": (
                            (stmt.report_text or stmt.impact_statement)
                            if stmt else None
                        ),
                        "analysis_grade": (
                            stmt.analysis_grade if stmt else None
                        ),
                        "analysis_evidence": (
                            stmt.analysis_evidence if stmt else None
                        ),
                        "analysis_model": (
                            stmt.analysis_model if stmt else None
                        ),
                    }
                await _emit_event(job_id, emit_event)
            else:
                await _emit_event(job_id, event)

            if event_type == "cve_start":
                idx = event.get("index", 0)
                progress = int((idx - 1) / max(total, 1) * 90)
                async with get_db() as db:
                    await db_update_job(db, job_id, stage_progress=progress)

            if event_type == "cve_done":
                status = event.get("status") or ""
                if status == "not_affected":
                    inc_not_affected += 1
                elif status == "affected":
                    inc_affected += 1
                elif status == "under_investigation":
                    inc_under_inv += 1
                idx = event.get("index", 0)
                # Push stage_progress + per-status counts to DB so the
                # dashboard polling sees partial progress without waiting
                # for batch_complete.
                progress = int(idx / max(total, 1) * 90)
                async with get_db() as db:
                    await db_update_job(
                        db, job_id,
                        stage_progress=progress,
                        not_affected_count=inc_not_affected,
                        affected_count=inc_affected,
                        under_investigation_count=inc_under_inv,
                    )

            if vex_cancelled:
                break

    except Exception as exc:
        await _fail_job(job_id, stage, f"VEX 분석 단계 예외: {exc}")
        return

    if vex_cancelled:
        await _fail_job(job_id, stage, "VEX 분석이 사용자 요청으로 취소되었습니다.")
        return

    if vex_rate_limited is not None:
        retry_after = vex_rate_limited.get("retry_after")
        hint = f" (재시도까지 약 {retry_after}s)" if retry_after else ""
        # The affected model name is extracted from the Gemini banner
        # when available (analyze_cve_batch attaches it); fall back to
        # a generic label otherwise.  Previously this was hard-coded to
        # "Gemini 2.5 Pro" which was wrong once auto-mode started
        # picking gemini-3-* models.
        model_label = vex_rate_limited.get("model") or "Gemini"
        msg = (
            f"[RATE_LIMIT] {model_label} 쿼터에 도달해 분석을 중단했습니다"
            f"{hint}. 쿼터 회복 후 'Resume VEX' 로 이어서 분석하세요."
        )
        await _fail_job(job_id, stage, msg)
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
    VEX 분석 대상 CVE를 severity 우선순위 기준으로 반환합니다.
    중복 CVE ID 제거, Critical/High/Medium/Low 순 정렬.

    같은 severity 내에서는 **scan.json 원래 순서를 유지**한다 (Python
    ``sorted`` 는 stable).  프론트엔드 VulnerabilitiesTab /
    VexAnalysisTab 도 ``Array.prototype.sort`` 는 stable 이고 severity
    만으로 정렬하므로 같은 순서가 보장된다 → Resume from here 인덱스도
    정확히 맞는다.
    """
    seen: set[str] = set()
    unique: list[Vulnerability] = []
    for v in sorted(vulns, key=lambda v: _SEV_PRIORITY.get(v.severity.upper(), 99)):
        if v.cve_id not in seen:
            seen.add(v.cve_id)
            unique.append(v)

    return [v.cve_id for v in unique]


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
