"""
extractor.py — 멀티포맷 펌웨어 추출기

추출 전략 (순서대로 시도):
  1. binwalk -e -M  (기본 재귀 추출)
  2. rootfs 탐지 실패 시 → 추가 추출 시도:
     - UBI/UBIFS : ubireader_extract_files  →  ubireader_extract_images  →  ubidump
     - SquashFS   : unsquashfs
     - JFFS2      : jefferson
     - cramfs     : mount (loop, 실패시 skip)
  3. 각 단계 결과에서 다시 rootfs 탐지
  4. 모두 실패 시 추출 트리 자체를 rootfs로 사용 (부분 분석)

rootfs 판별: {etc, bin, usr} 중 2개 이상 포함한 가장 얕은 디렉토리.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncGenerator, Optional, Union

logger = logging.getLogger(__name__)

EXTRACT_TIMEOUT = 300   # binwalk 전체 타임아웃 (초)
EXTRA_TIMEOUT   = 120   # 2차 추출 툴 타임아웃 (초)

# rootfs 판별 마커 (2개 이상 있으면 후보)
_ROOTFS_MARKERS = {"etc", "bin", "usr", "lib", "sbin"}
_ROOTFS_MIN_MATCH = 2

# 2차 추출이 필요한 파일 확장자 → 처리 함수 이름
_EXTRA_HANDLERS: dict[str, str] = {
    ".ubi":     "_extract_ubi",
    ".ubifs":   "_extract_ubi",
    ".img":     "_extract_ubi_or_squashfs",
    ".squash":  "_extract_squashfs",
    ".sqsh":    "_extract_squashfs",
    ".sfs":     "_extract_squashfs",
    ".jffs2":   "_extract_jffs2",
    ".cramfs":  "_extract_cramfs",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractResult:
    rootfs_path: Optional[Path]
    """대표 rootfs 경로 (파일이 가장 많은 후보)."""

    rootfs_candidates: list[Path] = field(default_factory=list)
    """탐지된 모든 rootfs 후보 경로 목록 (SBOM 통합 스캔용)."""

    file_count: int = 0
    log: list[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def extract_firmware(
    firmware_path: Path,
    output_dir: Path,
    job_id: str,
) -> AsyncGenerator[Union[str, ExtractResult], None]:
    logs: list[str] = []

    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    file_size = firmware_path.stat().st_size if firmware_path.exists() else 0
    yield _log(f"[{job_id}] 추출 시작: {firmware_path.name} ({file_size:,} bytes)")

    if not shutil.which("binwalk"):
        yield ExtractResult(rootfs_path=None, file_count=0, log=logs, success=False,
                            error="binwalk을 찾을 수 없습니다.")
        return

    if not firmware_path.exists():
        yield ExtractResult(rootfs_path=None, file_count=0, log=logs, success=False,
                            error=f"펌웨어 파일을 찾을 수 없습니다: {firmware_path}")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    yield _log(f"[{job_id}] 출력 디렉토리: {output_dir}")

    # ── Step 1: binwalk -e -M ────────────────────────────────────────────────
    yield _log(f"[{job_id}] [1/3] binwalk -e -M 실행 중...")
    ok, err = await _run_binwalk(firmware_path, output_dir, logs, job_id)
    if not ok:
        yield ExtractResult(rootfs_path=None, file_count=0, log=logs, success=False, error=err)
        return

    # ── Step 2: rootfs 탐지 ──────────────────────────────────────────────────
    yield _log(f"[{job_id}] [2/3] rootfs 탐지 중...")
    rootfs = _find_rootfs(output_dir)

    if rootfs:
        yield _log(f"[{job_id}] ✓ rootfs 발견 (binwalk): {rootfs.relative_to(output_dir)}")
    else:
        # ── Step 3: 2차 추출 시도 ────────────────────────────────────────────
        yield _log(f"[{job_id}] [3/3] rootfs 미탐지 → 2차 추출 시도 중...")
        candidates = _find_extra_targets(output_dir, firmware_path)

        for target, handler_name in candidates:
            handler = globals().get(handler_name)
            if not handler:
                continue
            yield _log(f"[{job_id}]   → {handler_name.replace('_extract_', '')} 시도: {target.name}")
            extra_dir = output_dir / f"_extra_{target.stem}"
            extra_dir.mkdir(exist_ok=True)
            try:
                async for msg in handler(target, extra_dir, logs, job_id):
                    yield msg
            except Exception as exc:
                yield _log(f"[{job_id}]   ✗ 실패: {exc}")
                continue

            rootfs = _find_rootfs(extra_dir) or _find_rootfs(output_dir)
            if rootfs:
                yield _log(f"[{job_id}] ✓ rootfs 발견 ({handler_name}): {rootfs}")
                break

    # ── 최종 결과 ────────────────────────────────────────────────────────────
    all_candidates = _find_all_rootfs(output_dir)

    if not all_candidates:
        rootfs = _best_effort_rootfs(output_dir)
        if rootfs:
            yield _log(f"[{job_id}] ⚠ rootfs 구조 미탐지 → 최대 파일 디렉토리 사용: {rootfs.name}")
            all_candidates = [rootfs]
        else:
            yield _log(f"[{job_id}] ✗ 유효한 파일 시스템 추출 실패")
            yield ExtractResult(rootfs_path=None, rootfs_candidates=[], log=logs, success=False,
                                error="rootfs를 탐지하지 못했습니다. 펌웨어 구조를 확인하세요.")
            return

    # 파일 수 기준으로 정렬, 대표 rootfs = 가장 큰 것
    all_candidates.sort(key=lambda p: -sum(1 for _ in p.rglob("*") if _.is_file()))
    best_rootfs = all_candidates[0]
    file_count = sum(1 for _ in best_rootfs.rglob("*") if _.is_file())

    yield _log(f"[{job_id}] rootfs 후보 {len(all_candidates)}개 탐지:")
    for c in all_candidates:
        fc = sum(1 for _ in c.rglob("*") if _.is_file())
        yield _log(f"[{job_id}]   {'★' if c == best_rootfs else '·'} {c.name} ({fc:,}개 파일)")

    yield _log(f"[{job_id}] 완료: 대표 rootfs {file_count:,}개 파일, 전체 후보 {len(all_candidates)}개")
    yield ExtractResult(
        rootfs_path=best_rootfs,
        rootfs_candidates=all_candidates,
        file_count=file_count,
        log=logs,
        success=True,
    )


# ---------------------------------------------------------------------------
# binwalk runner
# ---------------------------------------------------------------------------


async def _run_binwalk(
    firmware_path: Path,
    output_dir: Path,
    logs: list[str],
    job_id: str,
) -> tuple[bool, Optional[str]]:
    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    try:
        proc = await asyncio.create_subprocess_exec(
            "binwalk", "-e", "-M",
            "--directory", str(output_dir),
            str(firmware_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        return False, f"binwalk 시작 실패: {exc}"

    loop = asyncio.get_running_loop()
    deadline = loop.time() + EXTRACT_TIMEOUT

    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            proc.kill()
            await proc.wait()
            return False, f"binwalk 타임아웃 ({EXTRACT_TIMEOUT}초)"

        try:
            raw = await asyncio.wait_for(proc.stdout.readline(), timeout=min(remaining, 5.0))
        except asyncio.TimeoutError:
            continue

        if not raw:
            break
        line = raw.decode(errors="replace").rstrip()
        if line:
            _log(line)

    try:
        await asyncio.wait_for(proc.wait(), timeout=15)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()

    if proc.returncode not in (0, None):
        return False, f"binwalk 비정상 종료 (exit={proc.returncode})"
    return True, None


# ---------------------------------------------------------------------------
# 2차 추출 핸들러
# ---------------------------------------------------------------------------


async def _extract_ubi(
    target: Path,
    out_dir: Path,
    logs: list[str],
    job_id: str,
) -> AsyncGenerator[str, None]:
    """ubireader_extract_files → ubireader_extract_images → ubidump 순으로 시도."""
    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    tools = [
        (["ubireader_extract_files", "-o", str(out_dir), str(target)], "ubireader_extract_files"),
        (["ubireader_extract_images", "-o", str(out_dir), str(target)], "ubireader_extract_images"),
        (["ubidump.py", "-o", str(out_dir), str(target)], "ubidump"),
    ]

    for cmd, tool_name in tools:
        if not shutil.which(cmd[0]):
            yield _log(f"[{job_id}]   {tool_name} 없음 (스킵)")
            continue
        yield _log(f"[{job_id}]   {tool_name} 실행 중...")
        rc = await _run_cmd(cmd, EXTRA_TIMEOUT)
        if rc == 0:
            yield _log(f"[{job_id}]   ✓ {tool_name} 성공")
            # 추출된 .ubifs 파일이 있으면 재귀 처리
            for ubifs in out_dir.rglob("*.ubifs"):
                sub = out_dir / f"_ubifs_{ubifs.stem}"
                sub.mkdir(exist_ok=True)
                async for msg in _extract_ubi(ubifs, sub, logs, job_id):
                    yield msg
            return
        yield _log(f"[{job_id}]   ✗ {tool_name} 실패 (rc={rc})")

    # 마지막 수단: binwalk로 UBI 파일 자체 재추출
    yield _log(f"[{job_id}]   binwalk로 UBI 재추출 시도...")
    await _run_cmd(
        ["binwalk", "-e", "--directory", str(out_dir), str(target)],
        EXTRA_TIMEOUT,
    )


async def _extract_ubi_or_squashfs(
    target: Path,
    out_dir: Path,
    logs: list[str],
    job_id: str,
) -> AsyncGenerator[str, None]:
    """바이너리 매직 바이트로 포맷 판별 후 UBI 또는 SquashFS 추출."""
    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    try:
        with open(target, "rb") as f:
            magic = f.read(8)
    except OSError:
        magic = b""

    # UBI magic: 0x55 0x42 0x49 0x23  ("UBI#")
    if magic[:4] == b"UBI#":
        yield _log(f"[{job_id}]   UBI 매직 감지 → UBI 추출")
        async for msg in _extract_ubi(target, out_dir, logs, job_id):
            yield msg
    # SquashFS magic: 0x73717368 (sqsh) or 0x68737173 (hsqs, little-endian)
    elif magic[:4] in (b"sqsh", b"hsqs", b"shsq", b"qshs"):
        yield _log(f"[{job_id}]   SquashFS 매직 감지 → unsquashfs")
        async for msg in _extract_squashfs(target, out_dir, logs, job_id):
            yield msg
    else:
        # 매직 불명: binwalk로 재시도
        yield _log(f"[{job_id}]   포맷 불명 (magic={magic[:4].hex()}) → binwalk 재추출")
        await _run_cmd(
            ["binwalk", "-e", "--directory", str(out_dir), str(target)],
            EXTRA_TIMEOUT,
        )


async def _extract_squashfs(
    target: Path,
    out_dir: Path,
    logs: list[str],
    job_id: str,
) -> AsyncGenerator[str, None]:
    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    sq_out = out_dir / "squashfs-root"
    if not shutil.which("unsquashfs"):
        yield _log(f"[{job_id}]   unsquashfs 없음 (apt install squashfs-tools)")
        return
    yield _log(f"[{job_id}]   unsquashfs -f -d {sq_out} {target.name}")
    rc = await _run_cmd(["unsquashfs", "-f", "-d", str(sq_out), str(target)], EXTRA_TIMEOUT)
    if rc == 0:
        yield _log(f"[{job_id}]   ✓ unsquashfs 성공")
    else:
        yield _log(f"[{job_id}]   ✗ unsquashfs 실패 (rc={rc})")


async def _extract_jffs2(
    target: Path,
    out_dir: Path,
    logs: list[str],
    job_id: str,
) -> AsyncGenerator[str, None]:
    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    if shutil.which("jefferson"):
        yield _log(f"[{job_id}]   jefferson 실행 중...")
        rc = await _run_cmd(["jefferson", "-d", str(out_dir), str(target)], EXTRA_TIMEOUT)
        if rc == 0:
            yield _log(f"[{job_id}]   ✓ jefferson 성공")
            return
        yield _log(f"[{job_id}]   ✗ jefferson 실패 (rc={rc})")
    else:
        yield _log(f"[{job_id}]   jefferson 없음 (pip install jefferson)")

    # 대안: binwalk로 재추출
    await _run_cmd(["binwalk", "-e", "--directory", str(out_dir), str(target)], EXTRA_TIMEOUT)


async def _extract_cramfs(
    target: Path,
    out_dir: Path,
    logs: list[str],
    job_id: str,
) -> AsyncGenerator[str, None]:
    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    # cramfsck -x로 추출 시도
    if shutil.which("cramfsck"):
        yield _log(f"[{job_id}]   cramfsck 실행 중...")
        rc = await _run_cmd(["cramfsck", "-x", str(out_dir), str(target)], EXTRA_TIMEOUT)
        if rc == 0:
            yield _log(f"[{job_id}]   ✓ cramfsck 성공")
            return
    yield _log(f"[{job_id}]   cramfs: binwalk 재추출 시도")
    await _run_cmd(["binwalk", "-e", "--directory", str(out_dir), str(target)], EXTRA_TIMEOUT)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_extra_targets(output_dir: Path, firmware_path: Path) -> list[tuple[Path, str]]:
    """
    2차 추출이 필요한 파일 목록을 반환.
    binwalk가 추출한 파일 + 원본 펌웨어 자체를 검사.
    UBI 헤더("UBI#")를 바이너리로 스캔해서 확장자 무관하게 탐지.
    """
    results: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    def _add(p: Path, handler: str) -> None:
        if p not in seen and p.exists() and p.stat().st_size > 1024:
            seen.add(p)
            results.append((p, handler))

    # 확장자 기반
    for f in sorted(output_dir.rglob("*")):
        if not f.is_file():
            continue
        handler = _EXTRA_HANDLERS.get(f.suffix.lower())
        if handler:
            _add(f, handler)

    # 매직 바이트 기반 스캔 (확장자 무관)
    scan_targets = list(output_dir.rglob("*"))
    scan_targets.append(firmware_path)
    for f in scan_targets:
        if not f.is_file() or f in seen:
            continue
        try:
            with open(f, "rb") as fh:
                magic = fh.read(8)
            if magic[:4] == b"UBI#":
                _add(f, "_extract_ubi")
            elif magic[:4] in (b"sqsh", b"hsqs", b"shsq", b"qshs"):
                _add(f, "_extract_squashfs")
            elif magic[:2] == b"\x85\x19":  # cramfs little-endian
                _add(f, "_extract_cramfs")
            elif magic[:4] == b"\x19\x85\x20\x03":  # jffs2
                _add(f, "_extract_jffs2")
        except OSError:
            continue

    return results


def _find_all_rootfs(extraction_root: Path) -> list[Path]:
    """
    추출 트리에서 rootfs 후보를 모두 찾아 반환.

    판별: {etc, bin, usr, lib, sbin} 중 2개 이상 포함.
    부모-자식 관계인 경우 부모만 포함 (중복 제거).
    """
    raw: list[Path] = []

    for dirpath in sorted(extraction_root.rglob("*")):
        if not dirpath.is_dir():
            continue
        try:
            subdirs = {d.name.lower() for d in dirpath.iterdir() if d.is_dir()}
        except PermissionError:
            continue

        if len(_ROOTFS_MARKERS & subdirs) >= _ROOTFS_MIN_MATCH:
            raw.append(dirpath)

    # 부모가 이미 포함된 경우 자식 제거 (ancestor dedup)
    result: list[Path] = []
    for p in sorted(raw, key=lambda x: len(x.parts)):
        if not any(p != r and (p == r or str(p).startswith(str(r) + "/")) for r in result):
            result.append(p)

    return result


def _find_rootfs(extraction_root: Path) -> Optional[Path]:
    """단일 rootfs 반환 (레거시 호환용)."""
    candidates = _find_all_rootfs(extraction_root)
    if not candidates:
        return None
    candidates.sort(key=lambda p: -sum(1 for _ in p.rglob("*") if _.is_file()))
    return candidates[0]


def _best_effort_rootfs(extraction_root: Path) -> Optional[Path]:
    """rootfs를 찾지 못한 경우, 가장 많은 파일을 보유한 하위 디렉토리 반환."""
    best: Optional[tuple[int, Path]] = None
    for d in extraction_root.rglob("*"):
        if not d.is_dir():
            continue
        try:
            count = sum(1 for _ in d.rglob("*") if _.is_file())
        except PermissionError:
            continue
        if best is None or count > best[0]:
            best = (count, d)

    if best and best[0] > 10:  # 최소 10개 파일
        return best[1]
    return None


async def _run_cmd(cmd: list[str], timeout: int) -> int:
    """커맨드 실행 후 returncode 반환. 타임아웃 시 -1."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout)
        return proc.returncode or 0
    except (asyncio.TimeoutError, OSError):
        try:
            proc.kill()
        except Exception:
            pass
        return -1
