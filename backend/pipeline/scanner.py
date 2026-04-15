"""
scanner.py — grype 래퍼 (CVE 스캔)

grype sbom:{sbom_path} -o json 으로 SBOM을 스캔하고,
CVE 목록 및 severity 별 카운트를 반환합니다.

stdout(JSON 결과)은 파일로 직접 리다이렉트하고,
stderr(진행 상황)는 실시간으로 yield합니다.

Usage:
    result = None
    async for item in scan_sbom(sbom_path, output_dir, job_id):
        if isinstance(item, str):
            await send_log(item)
        elif isinstance(item, ScanResult):
            result = item
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncGenerator, Optional, Union

logger = logging.getLogger(__name__)

SCAN_TIMEOUT = 60  # seconds

# severity 정렬 순서 (심각도 높은 순)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


@dataclass
class Vulnerability:
    """grype 가 탐지한 개별 취약점."""

    cve_id: str
    """CVE ID (예: CVE-2021-44228)."""

    package_name: str
    package_version: str

    severity: str
    """CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE | UNKNOWN"""

    description: str

    fix_version: Optional[str]
    """패치 버전. 아직 패치 없으면 None."""

    urls: list[str]
    """참고 URL 목록."""


@dataclass
class ScanResult:
    """grype 스캔 최종 결과."""

    vulnerabilities: list[Vulnerability]
    """탐지된 취약점 전체 목록."""

    counts_by_severity: dict[str, int]
    """severity 별 카운트 (예: {"CRITICAL": 3, "HIGH": 12})."""

    total_count: int
    """탐지된 취약점 총 수."""

    log: list[str]
    """누적 로그 라인 목록."""

    success: bool
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def scan_sbom(
    sbom_path: Path,
    output_dir: Path,
    job_id: str,
) -> AsyncGenerator[Union[str, ScanResult], None]:
    """
    CycloneDX SBOM 파일을 grype 로 스캔하는 비동기 제너레이터.

    Parameters
    ----------
    sbom_path:
        sbom.py 가 생성한 CycloneDX JSON 파일 경로.
    output_dir:
        scan.json 결과를 저장할 디렉토리 (잡 별 격리 경로).
    job_id:
        로깅 및 추적용 잡 ID.

    Yields
    ------
    str
        grype stderr 진행 로그 라인 (실시간).
    ScanResult
        마지막 아이템: 최종 결과.

    Notes
    -----
    stdout(JSON)은 scan.json 파일로 직접 기록되므로 메모리를 최소화합니다.
    stderr는 실시간 yield되어 프론트엔드 진행 표시에 활용됩니다.
    """
    logs: list[str] = []

    def _log(msg: str) -> str:
        logger.info(msg)
        logs.append(msg)
        return msg

    scan_output_path = output_dir / "scan.json"
    yield _log(f"[{job_id}] CVE 스캔 시작: {sbom_path.name}")

    # ── 사전 검사 ────────────────────────────────────────────────────────────
    if not shutil.which("grype"):
        yield ScanResult(
            vulnerabilities=[],
            counts_by_severity={},
            total_count=0,
            log=logs,
            success=False,
            error=(
                "grype를 찾을 수 없습니다. PATH에 grype가 설치되어 있는지 확인하세요.\n"
                "  설치: https://github.com/anchore/grype/releases"
            ),
        )
        return

    if not sbom_path.exists():
        yield ScanResult(
            vulnerabilities=[],
            counts_by_severity={},
            total_count=0,
            log=logs,
            success=False,
            error=f"SBOM 파일을 찾을 수 없습니다: {sbom_path}",
        )
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    yield _log(f"[{job_id}] 실행: grype sbom:{sbom_path.name} --add-cpes-if-none -o json → {scan_output_path.name}")

    # ── 서브프로세스 실행 ────────────────────────────────────────────────────
    # stdout → 파일 직접 기록 (JSON이므로 버퍼 없이 파일로)
    # stderr → PIPE 로 받아 실시간 yield
    # --add-cpes-if-none : CPE 없는 패키지도 NVD 매칭 시도 → 탐지율 향상
    scan_file = None
    try:
        scan_file = open(scan_output_path, "wb")
        proc = await asyncio.create_subprocess_exec(
            "grype",
            f"sbom:{sbom_path}",
            "--add-cpes-if-none",
            "-o", "json",
            stdout=scan_file,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        if scan_file:
            scan_file.close()
        yield ScanResult(
            vulnerabilities=[],
            counts_by_severity={},
            total_count=0,
            log=logs,
            success=False,
            error=f"grype 프로세스 시작 실패: {exc}",
        )
        return

    # ── stderr 실시간 스트리밍 (deadline 방식 타임아웃) ───────────────────────
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SCAN_TIMEOUT

    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            proc.kill()
            await proc.wait()
            scan_file.close()
            yield ScanResult(
                vulnerabilities=[],
                counts_by_severity={},
                total_count=0,
                log=logs,
                success=False,
                error=f"grype 타임아웃 ({SCAN_TIMEOUT}초 초과)",
            )
            return

        try:
            raw = await asyncio.wait_for(
                proc.stderr.readline(),
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
    finally:
        scan_file.close()

    if proc.returncode not in (0, None):
        yield ScanResult(
            vulnerabilities=[],
            counts_by_severity={},
            total_count=0,
            log=logs,
            success=False,
            error=f"grype 비정상 종료 (exit code: {proc.returncode})",
        )
        return

    # ── JSON 결과 파싱 ────────────────────────────────────────────────────────
    if not scan_output_path.exists() or scan_output_path.stat().st_size == 0:
        yield ScanResult(
            vulnerabilities=[],
            counts_by_severity={},
            total_count=0,
            log=logs,
            success=False,
            error="grype 결과 파일이 비어 있거나 생성되지 않았습니다.",
        )
        return

    try:
        data = json.loads(scan_output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        yield ScanResult(
            vulnerabilities=[],
            counts_by_severity={},
            total_count=0,
            log=logs,
            success=False,
            error=f"grype JSON 결과 파싱 실패: {exc}",
        )
        return

    vulnerabilities = _parse_vulnerabilities(data)
    counts = _count_by_severity(vulnerabilities)

    yield _log(f"[{job_id}] 스캔 완료: 총 {len(vulnerabilities):,}개 취약점 탐지")
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) > 0:
            yield _log(f"[{job_id}]   {sev}: {counts[sev]}")

    yield ScanResult(
        vulnerabilities=vulnerabilities,
        counts_by_severity=counts,
        total_count=len(vulnerabilities),
        log=logs,
        success=True,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_vulnerabilities(data: dict) -> list[Vulnerability]:
    """
    grype JSON 출력의 matches 배열을 Vulnerability 목록으로 변환합니다.

    grype JSON 스키마 (핵심 필드):
    {
      "matches": [
        {
          "vulnerability": {
            "id": "CVE-XXXX-XXXXX",
            "severity": "High",
            "description": "...",
            "fix": { "versions": ["1.2.3"], "state": "fixed" },
            "urls": ["https://..."]
          },
          "artifact": {
            "name": "package",
            "version": "1.0.0"
          }
        }
      ]
    }
    """
    results: list[Vulnerability] = []

    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        fix_info = vuln.get("fix", {})
        fix_versions = fix_info.get("versions", [])
        fix_version: Optional[str] = fix_versions[0] if fix_versions else None

        results.append(
            Vulnerability(
                cve_id=vuln.get("id", "UNKNOWN"),
                package_name=artifact.get("name", ""),
                package_version=artifact.get("version", ""),
                severity=vuln.get("severity", "UNKNOWN").upper(),
                description=vuln.get("description", ""),
                fix_version=fix_version,
                urls=vuln.get("urls", []),
            )
        )

    # severity 심각도 순 정렬
    severity_index = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    results.sort(key=lambda v: severity_index.get(v.severity, len(SEVERITY_ORDER)))

    return results


def _count_by_severity(vulns: list[Vulnerability]) -> dict[str, int]:
    """severity 별 취약점 수를 집계합니다. 0인 항목은 제외."""
    counts: dict[str, int] = {}
    for v in vulns:
        sev = v.severity.upper()
        counts[sev] = counts.get(sev, 0) + 1
    # SEVERITY_ORDER 순서로 정렬된 딕셔너리 반환
    return {
        sev: counts[sev]
        for sev in SEVERITY_ORDER
        if counts.get(sev, 0) > 0
    }
