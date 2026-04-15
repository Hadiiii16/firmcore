"""
sbom.py — sbom_claude_scripts 래퍼 (CycloneDX SBOM 생성)

firmcore/ 루트에 위치한 커스텀 SBOM 생성기를 사용합니다.
명령: ./sbom_claude_scripts dir:{rootfs_path} -o cyclonedx-json={output_path}

환경변수 SBOM_BIN 으로 바이너리 경로를 재정의할 수 있습니다.

Usage:
    result = None
    async for item in generate_sbom(rootfs_path, output_dir, job_id):
        if isinstance(item, str):
            await send_log(item)
        elif isinstance(item, SbomResult):
            result = item
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncGenerator, Optional, Union

logger = logging.getLogger(__name__)

SBOM_TIMEOUT = 120  # seconds

# SBOM_BIN: 환경 변수로 재정의 가능, 기본값은 프로젝트 루트의 sbom_claude_scripts
_PROJECT_ROOT = Path(__file__).parent.parent.parent
SYFT_BIN = Path(os.environ.get("SBOM_BIN", _PROJECT_ROOT / "sbom_claude_scripts"))


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class SbomResult:
    """syft SBOM 생성 최종 결과."""

    sbom_path: Path
    """생성된 CycloneDX JSON 파일 경로."""

    component_count: int
    """SBOM에 포함된 컴포넌트(패키지) 수."""

    log: list[str]
    """누적 로그 라인 목록."""

    success: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def generate_sbom_multi(
    rootfs_candidates: list[Path],
    output_dir: Path,
    job_id: str,
) -> AsyncGenerator[Union[str, SbomResult], None]:
    """
    여러 rootfs 후보를 각각 스캔한 뒤 컴포넌트를 (name+version 기준) 중복 제거해 합산.
    단일 후보인 경우 generate_sbom과 동일하게 동작.
    """
    logs: list[str] = []

    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    if not rootfs_candidates:
        yield SbomResult(sbom_path=output_dir / "sbom.cdx.json",
                         component_count=0, log=logs, success=False,
                         error="rootfs 후보가 없습니다.")
        return

    if len(rootfs_candidates) == 1:
        async for item in generate_sbom(rootfs_candidates[0], output_dir, job_id):
            yield item
        return

    yield _log(f"[{job_id}] 다중 rootfs SBOM 통합 스캔: {len(rootfs_candidates)}개 후보")

    all_components: dict[str, dict] = {}  # key: "name@version"
    base_sbom: dict = {}

    for idx, rootfs in enumerate(rootfs_candidates, 1):
        tmp_dir = output_dir / f"_sbom_tmp_{idx}"
        tmp_dir.mkdir(exist_ok=True)
        yield _log(f"[{job_id}] [{idx}/{len(rootfs_candidates)}] 스캔: {rootfs.name}")

        result: Optional[SbomResult] = None
        async for item in generate_sbom(rootfs, tmp_dir, job_id):
            if isinstance(item, str):
                yield item
            elif isinstance(item, SbomResult):
                result = item

        if result and result.success and result.sbom_path.exists():
            try:
                sbom_data = json.loads(result.sbom_path.read_text(encoding="utf-8"))
                if not base_sbom:
                    base_sbom = sbom_data
                for comp in sbom_data.get("components", []):
                    key = f"{comp.get('name','')}@{comp.get('version','')}"
                    if key not in all_components:
                        all_components[key] = comp
                yield _log(f"[{job_id}]   → {len(sbom_data.get('components', []))}개 컴포넌트")
            except Exception as exc:
                yield _log(f"[{job_id}]   ⚠ SBOM 병합 실패: {exc}")

    # 통합 SBOM 저장
    final_sbom_path = output_dir / "sbom.cdx.json"
    if base_sbom and all_components:
        base_sbom["components"] = list(all_components.values())
        final_sbom_path.write_text(
            json.dumps(base_sbom, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        count = len(all_components)
        yield _log(f"[{job_id}] 통합 SBOM 완료: {count:,}개 컴포넌트 (중복 제거 후)")
        yield SbomResult(sbom_path=final_sbom_path, component_count=count, log=logs, success=True)
    else:
        yield SbomResult(sbom_path=final_sbom_path, component_count=0, log=logs,
                         success=False, error="모든 rootfs 후보에서 SBOM 생성 실패")


async def generate_sbom(
    rootfs_path: Path,
    output_dir: Path,
    job_id: str,
) -> AsyncGenerator[Union[str, SbomResult], None]:
    """
    rootfs 디렉토리에서 CycloneDX JSON SBOM을 생성하는 비동기 제너레이터.

    Parameters
    ----------
    rootfs_path:
        extractor.py 가 탐지한 rootfs 디렉토리 경로.
    output_dir:
        sbom.cdx.json 을 저장할 디렉토리 (잡 별 격리 경로).
    job_id:
        로깅 및 추적용 잡 ID.

    Yields
    ------
    str
        syft 출력 로그 라인 (실시간).
    SbomResult
        마지막 아이템: 최종 결과.
    """
    logs: list[str] = []

    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    sbom_path = output_dir / "sbom.cdx.json"
    yield _log(f"[{job_id}] SBOM 생성 시작: {rootfs_path}")

    # ── 사전 검사 ────────────────────────────────────────────────────────────
    if not SYFT_BIN.exists():
        yield SbomResult(
            sbom_path=sbom_path,
            component_count=0,
            log=logs,
            success=False,
            error=(
                f"SBOM 바이너리를 찾을 수 없습니다: {SYFT_BIN}\n"
                f"  → firmcore/ 루트에 sbom_claude_scripts 파일이 있는지 확인하세요.\n"
                f"  → 환경변수 SBOM_BIN 으로 경로를 재정의할 수 있습니다."
            ),
        )
        return

    if not rootfs_path.exists():
        yield SbomResult(
            sbom_path=sbom_path,
            component_count=0,
            log=logs,
            success=False,
            error=f"rootfs 경로를 찾을 수 없습니다: {rootfs_path}",
        )
        return

    # 실행 권한 보장
    _ensure_executable(SYFT_BIN)
    yield _log(f"[{job_id}] SBOM 바이너리: {SYFT_BIN}")

    output_dir.mkdir(parents=True, exist_ok=True)
    yield _log(
        f"[{job_id}] 실행: {SYFT_BIN.name} dir:{rootfs_path} "
        f"-o cyclonedx-json={sbom_path}"
    )

    # ── 서브프로세스 실행 ────────────────────────────────────────────────────
    try:
        proc = await asyncio.create_subprocess_exec(
            str(SYFT_BIN),
            f"dir:{rootfs_path}",
            "-o", f"cyclonedx-json={sbom_path}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        yield SbomResult(
            sbom_path=sbom_path,
            component_count=0,
            log=logs,
            success=False,
            error=f"syft 프로세스 시작 실패: {exc}",
        )
        return

    # ── 실시간 출력 스트리밍 ─────────────────────────────────────────────────
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SBOM_TIMEOUT

    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            proc.kill()
            await proc.wait()
            yield SbomResult(
                sbom_path=sbom_path,
                component_count=0,
                log=logs,
                success=False,
                error=f"syft 타임아웃 ({SBOM_TIMEOUT}초 초과)",
            )
            return

        try:
            raw = await asyncio.wait_for(
                proc.stdout.readline(),
                timeout=min(remaining, 5.0),
            )
        except asyncio.TimeoutError:
            continue

        if not raw:
            break

        line = raw.decode(errors="replace").rstrip()
        if line:
            yield _log(line)

    try:
        await asyncio.wait_for(proc.wait(), timeout=15)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()

    if proc.returncode not in (0, None):
        yield SbomResult(
            sbom_path=sbom_path,
            component_count=0,
            log=logs,
            success=False,
            error=f"syft 비정상 종료 (exit code: {proc.returncode})",
        )
        return

    # ── 출력 파일 검증 및 컴포넌트 수 파싱 ───────────────────────────────────
    if not sbom_path.exists():
        yield SbomResult(
            sbom_path=sbom_path,
            component_count=0,
            log=logs,
            success=False,
            error=(
                "syft 실행은 완료됐지만 SBOM 파일이 생성되지 않았습니다. "
                f"예상 경로: {sbom_path}"
            ),
        )
        return

    component_count = _count_components(sbom_path)
    yield _log(
        f"[{job_id}] SBOM 생성 완료: {sbom_path.name} "
        f"({component_count:,}개 컴포넌트, {sbom_path.stat().st_size:,} bytes)"
    )

    yield SbomResult(
        sbom_path=sbom_path,
        component_count=component_count,
        log=logs,
        success=True,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_executable(path: Path) -> None:
    """파일에 실행 권한이 없으면 추가합니다."""
    current = path.stat().st_mode
    if not (current & stat_module.S_IXUSR):
        path.chmod(current | stat_module.S_IXUSR | stat_module.S_IXGRP)
        logger.debug("실행 권한 추가: %s", path)


def _count_components(sbom_path: Path) -> int:
    """CycloneDX JSON 파일에서 components 배열 길이를 반환합니다."""
    try:
        data = json.loads(sbom_path.read_text(encoding="utf-8"))
        return len(data.get("components", []))
    except Exception as exc:
        logger.warning("SBOM 파싱 실패 (컴포넌트 수 집계 불가): %s", exc)
        return 0
