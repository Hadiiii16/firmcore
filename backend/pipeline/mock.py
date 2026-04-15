"""
mock.py — MOCK_PIPELINE=true 시 사용하는 더미 파이프라인

실제 외부 도구(binwalk, syft, grype, Gemini) 없이도
전체 UI/API 플로우를 개발/테스트할 수 있도록 합니다.
실제 파일을 생성하므로 result 엔드포인트도 정상 동작합니다.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from db import db_add_event, db_end_stage, db_start_stage, db_update_job, get_db, now_iso
from event_bus import broadcast

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mock 데이터
# ---------------------------------------------------------------------------

_MOCK_CVES = [
    {
        "id": "CVE-2021-44228",
        "severity": "CRITICAL",
        "package": "log4j",
        "version": "2.14.0",
        "description": "Apache Log4j2 JNDI features allow remote code execution.",
        "fix_version": "2.15.0",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "vex_status": "not_affected",
        "vex_justification": "vulnerable_code_not_present",
        "vex_impact": "Log4j library not found in firmware rootfs.",
    },
    {
        "id": "CVE-2022-0778",
        "severity": "HIGH",
        "package": "openssl",
        "version": "1.1.1k",
        "description": "OpenSSL infinite loop in BN_mod_sqrt() allows DoS.",
        "fix_version": "1.1.1n",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0778"],
        "vex_status": "not_affected",
        "vex_justification": "vulnerable_code_not_present",
        "vex_impact": "BN_mod_sqrt symbol absent from libcrypto.so dynamic symbol table.",
    },
    {
        "id": "CVE-2021-3711",
        "severity": "CRITICAL",
        "package": "openssl",
        "version": "1.1.1k",
        "description": "SM2 decryption buffer overflow in OpenSSL.",
        "fix_version": "1.1.1l",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"],
        "vex_status": "not_affected",
        "vex_justification": "vulnerable_code_not_in_execute_path",
        "vex_impact": (
            "EVP_PKEY_decrypt found in libcrypto.so but no binary links "
            "the SM2 decryption path; firmware has no SM2 consumers."
        ),
    },
    {
        "id": "CVE-2023-38545",
        "severity": "CRITICAL",
        "package": "curl",
        "version": "7.88.0",
        "description": "SOCKS5 heap-based buffer overflow in curl.",
        "fix_version": "8.4.0",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38545"],
        "vex_status": "affected",
        "vex_justification": None,
        "vex_impact": (
            "curl binary present; SOCKS5 proxy feature enabled; "
            "network-accessible via web UI ubus call. Exploitation possible."
        ),
    },
    {
        "id": "CVE-2022-42889",
        "severity": "CRITICAL",
        "package": "commons-text",
        "version": "1.9",
        "description": "Apache Commons Text RCE via StringSubstitutor.",
        "fix_version": "1.10.0",
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2022-42889"],
        "vex_status": "under_investigation",
        "vex_justification": None,
        "vex_impact": "Library present; call path from web UI CGI requires manual review.",
    },
]

_MOCK_COMPONENTS = [
    {"name": "busybox", "version": "1.35.0", "type": "application", "purl": "pkg:generic/busybox@1.35.0"},
    {"name": "openssl", "version": "1.1.1k", "type": "library", "purl": "pkg:generic/openssl@1.1.1k"},
    {"name": "curl", "version": "7.88.0", "type": "library", "purl": "pkg:generic/curl@7.88.0"},
    {"name": "libc", "version": "2.31", "type": "library", "purl": "pkg:generic/glibc@2.31"},
    {"name": "uhttpd", "version": "2022-08-10", "type": "application", "purl": "pkg:generic/uhttpd@2022-08-10"},
    {"name": "opkg", "version": "2022-02-24", "type": "application", "purl": "pkg:generic/opkg@2022-02-24"},
    {"name": "dropbear", "version": "2022.83", "type": "application", "purl": "pkg:generic/dropbear@2022.83"},
    {"name": "dnsmasq", "version": "2.87", "type": "application", "purl": "pkg:generic/dnsmasq@2.87"},
    {"name": "iptables", "version": "1.8.8", "type": "application", "purl": "pkg:generic/iptables@1.8.8"},
    {"name": "kmod", "version": "30", "type": "application", "purl": "pkg:generic/kmod@30"},
]

_STAGE_LOGS: dict[str, list[str]] = {
    "extracting": [
        "binwalk -e -M --directory=/storage/extracted firmware.bin",
        "DECIMAL       HEXADECIMAL     DESCRIPTION",
        "0             0x0             TRX firmware header, little endian, image size: 8388608 bytes",
        "28            0x1C            LZMA compressed data, properties: 0x5D",
        "1441792       0x160000        Squashfs filesystem, little endian, version 4.0",
        "Extracting 0x0 at offset 0...",
        "Extracting squashfs filesystem...",
        "unsquashfs: [============================================================] 1024/1024 100%",
        "rootfs 발견: extracted/squashfs-root (1,024개 파일)",
    ],
    "sbom_generating": [
        "syft dir:extracted/squashfs-root -o cyclonedx-json=sbom.cdx.json",
        " ✔ Loaded image",
        " ✔ Parsed image",
        " ✔ Cataloged packages  [10 packages]",
        "SBOM 생성 완료: sbom.cdx.json (10개 컴포넌트)",
    ],
    "scanning": [
        "grype sbom:sbom.cdx.json -o json",
        " ✔ Vulnerability DB  [updated]",
        " ✔ Scanned for vulnerabilities  [5 vulnerability matches]",
        "스캔 완료: 총 5개 취약점 발견",
        "  CRITICAL: 3",
        "  HIGH: 1",
        "  MEDIUM: 0",
        "  LOW: 0",
    ],
}

_VEX_GEMINI_TURNS: dict[str, list[dict]] = {
    "CVE-2021-44228": [
        {
            "turn": 1,
            "content": "1단계-A: find . -name 'log4j*.jar' -o -name 'log4j-core*.jar' 2>/dev/null",
        },
        {
            "turn": 2,
            "content": "출력 없음 → log4j 라이브러리가 rootfs에 존재하지 않습니다. not_affected (vulnerable_code_not_present)로 판정합니다.",
        },
    ],
}


# ---------------------------------------------------------------------------
# Mock pipeline entry point
# ---------------------------------------------------------------------------


async def run_mock_pipeline(job_id: str) -> None:
    """
    가짜 파이프라인. 실제 도구 없이 전체 플로우를 시뮬레이션합니다.
    각 단계는 실제 소요 시간을 흉내 내기 위해 짧은 sleep을 삽입합니다.
    """
    logger.info("[Mock] 파이프라인 시작: job=%s", job_id)

    async with get_db() as db:
        job = await db.execute("SELECT storage_dir FROM jobs WHERE id = ?", (job_id,))
        row = await job.fetchone()

    if not row:
        logger.error("[Mock] Job 없음: %s", job_id)
        return

    storage_dir = Path(row[0])
    storage_dir.mkdir(parents=True, exist_ok=True)

    # Stage 1: 추출
    await _mock_stage(job_id, "extracting", _STAGE_LOGS["extracting"], duration=3.0)
    rootfs_path = storage_dir / "extracted" / "squashfs-root"
    rootfs_path.mkdir(parents=True, exist_ok=True)
    async with get_db() as db:
        await db_update_job(db, job_id, rootfs_path=str(rootfs_path))

    # Stage 2: SBOM 생성
    await _mock_stage(job_id, "sbom_generating", _STAGE_LOGS["sbom_generating"], duration=2.0)
    sbom_path = storage_dir / "sbom.cdx.json"
    _write_mock_sbom(sbom_path)
    async with get_db() as db:
        await db_update_job(db, job_id, sbom_path=str(sbom_path), component_count=len(_MOCK_COMPONENTS))

    # Stage 3: 스캔
    await _mock_stage(job_id, "scanning", _STAGE_LOGS["scanning"], duration=1.5)
    scan_path = storage_dir / "scan.json"
    _write_mock_scan(scan_path)
    async with get_db() as db:
        await db_update_job(
            db, job_id,
            scan_result_path=str(scan_path),
            total_cves=len(_MOCK_CVES),
            critical_cves=sum(1 for c in _MOCK_CVES if c["severity"] == "CRITICAL"),
            high_cves=sum(1 for c in _MOCK_CVES if c["severity"] == "HIGH"),
        )

    # Stage 4: VEX 분석
    await _mock_vex_stage(job_id, storage_dir)

    # 완료
    complete_event = {"type": "job_complete", "status": "completed", "job_id": job_id}
    async with get_db() as db:
        await db_update_job(
            db, job_id,
            status="completed",
            current_stage=None,
            stage_progress=100,
            completed_at=now_iso(),
            not_affected_count=sum(1 for c in _MOCK_CVES if c["vex_status"] == "not_affected"),
            affected_count=sum(1 for c in _MOCK_CVES if c["vex_status"] == "affected"),
            under_investigation_count=sum(1 for c in _MOCK_CVES if c["vex_status"] == "under_investigation"),
        )
        await db_add_event(db, job_id, complete_event)
    broadcast(job_id, complete_event)
    logger.info("[Mock] 파이프라인 완료: job=%s", job_id)


# ---------------------------------------------------------------------------
# Internal mock helpers
# ---------------------------------------------------------------------------


async def _mock_stage(
    job_id: str,
    stage: str,
    logs: list[str],
    duration: float,
) -> None:
    start_event = {"type": "stage_start", "stage": stage, "job_id": job_id}
    async with get_db() as db:
        await db_update_job(db, job_id, status=stage, current_stage=stage, stage_progress=0)
        await db_start_stage(db, job_id, stage)
        await db_add_event(db, job_id, start_event)
    broadcast(job_id, start_event)

    interval = duration / max(len(logs), 1)
    for i, log_line in enumerate(logs, start=1):
        await asyncio.sleep(interval)
        progress = int(i / len(logs) * 90)
        progress_event = {
            "type": "stage_progress",
            "stage": stage,
            "progress": progress,
            "log": log_line,
            "job_id": job_id,
        }
        async with get_db() as db:
            await db_update_job(db, job_id, stage_progress=progress)
            await db_add_event(db, job_id, progress_event)
        broadcast(job_id, progress_event)

    complete_event = {"type": "stage_complete", "stage": stage, "elapsed": duration, "job_id": job_id}
    async with get_db() as db:
        await db_update_job(db, job_id, stage_progress=100)
        await db_end_stage(db, job_id, stage, duration)
        await db_add_event(db, job_id, complete_event)
    broadcast(job_id, complete_event)


async def _mock_vex_stage(job_id: str, storage_dir: Path) -> None:
    stage = "vex_analyzing"
    total_cves = len(_MOCK_CVES)

    start_event = {"type": "stage_start", "stage": stage, "job_id": job_id}
    async with get_db() as db:
        await db_update_job(db, job_id, status=stage, current_stage=stage, stage_progress=0)
        await db_start_stage(db, job_id, stage)
        await db_add_event(db, job_id, start_event)
    broadcast(job_id, start_event)

    vex_dir = storage_dir / "vex"
    vex_dir.mkdir(parents=True, exist_ok=True)

    for idx, cve_data in enumerate(_MOCK_CVES, start=1):
        cve_id = cve_data["id"]
        progress = int((idx - 1) / total_cves * 90)

        cve_start = {"type": "cve_start", "cve_id": cve_id, "index": idx, "total": total_cves, "job_id": job_id}
        async with get_db() as db:
            await db_update_job(db, job_id, stage_progress=progress)
            await db_add_event(db, job_id, cve_start)
        broadcast(job_id, cve_start)

        # 가짜 Gemini 응답 시뮬레이션
        for turn in _VEX_GEMINI_TURNS.get(cve_id, [{"turn": 1, "content": f"{cve_id} 분석 완료."}]):
            await asyncio.sleep(0.5)
            gemini_ev = {
                "type": "gemini_response",
                "turn": turn["turn"],
                "cve_id": cve_id,
                "content": turn["content"],
                "job_id": job_id,
            }
            async with get_db() as db:
                await db_add_event(db, job_id, gemini_ev)
            broadcast(job_id, gemini_ev)

        # 가짜 명령어 실행
        await asyncio.sleep(0.3)
        cmd_ev = {
            "type": "executing_command",
            "command": f"find . -name '*.so*' 2>/dev/null | head -5",
            "cve_id": cve_id,
            "job_id": job_id,
        }
        async with get_db() as db:
            await db_add_event(db, job_id, cmd_ev)
        broadcast(job_id, cmd_ev)

        await asyncio.sleep(0.2)
        result_ev = {
            "type": "command_result",
            "command": cmd_ev["command"],
            "result": "./usr/lib/libcrypto.so.1.1\n./usr/lib/libssl.so.1.1",
            "returncode": 0,
            "blocked": False,
            "cve_id": cve_id,
            "job_id": job_id,
        }
        async with get_db() as db:
            await db_add_event(db, job_id, result_ev)
        broadcast(job_id, result_ev)

        # VEX 완료
        vex_doc = _build_mock_vex_doc(cve_data)
        (vex_dir / f"{cve_id}_vex.json").write_text(
            json.dumps(vex_doc, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        vex_ev = {
            "type": "vex_complete",
            "cve_id": cve_id,
            "status": cve_data["vex_status"],
            "job_id": job_id,
        }
        async with get_db() as db:
            await db_add_event(db, job_id, vex_ev)
        broadcast(job_id, vex_ev)

    # combined_vex.json 생성
    combined_vex = _build_combined_mock_vex()
    combined_path = storage_dir / "combined_vex.json"
    combined_path.write_text(json.dumps(combined_vex, ensure_ascii=False, indent=2), encoding="utf-8")

    complete_event = {"type": "stage_complete", "stage": stage, "elapsed": 5.0, "job_id": job_id}
    async with get_db() as db:
        await db_update_job(
            db, job_id,
            stage_progress=100,
            combined_vex_path=str(combined_path),
        )
        await db_end_stage(db, job_id, stage, 5.0)
        await db_add_event(db, job_id, complete_event)
    broadcast(job_id, complete_event)


# ---------------------------------------------------------------------------
# Mock file writers
# ---------------------------------------------------------------------------


def _write_mock_sbom(path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {"timestamp": now_iso()},
        "components": [
            {
                "type": c["type"],
                "name": c["name"],
                "version": c["version"],
                "purl": c["purl"],
            }
            for c in _MOCK_COMPONENTS
        ],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _write_mock_scan(path: Path) -> None:
    matches = [
        {
            "vulnerability": {
                "id": c["id"],
                "severity": c["severity"].capitalize(),
                "description": c["description"],
                "fix": {"versions": [c["fix_version"]], "state": "fixed"},
                "urls": c["urls"],
            },
            "artifact": {"name": c["package"], "version": c["version"]},
        }
        for c in _MOCK_CVES
    ]
    path.write_text(json.dumps({"matches": matches}, indent=2), encoding="utf-8")


def _build_mock_vex_doc(cve: dict) -> dict:
    stmt: dict = {
        "vulnerability": {
            "@id": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            "name": cve["id"],
            "description": cve["description"],
        },
        "products": [{"@id": "pkg:generic/firmware@unknown"}],
        "status": cve["vex_status"],
        "impact_statement": cve["vex_impact"],
    }
    if cve["vex_justification"] and cve["vex_status"] == "not_affected":
        stmt["justification"] = cve["vex_justification"]

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "FirmCore VEX Analyzer (Mock)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": [stmt],
    }


def _build_combined_mock_vex() -> dict:
    statements = []
    for cve in _MOCK_CVES:
        stmt: dict = {
            "vulnerability": {
                "@id": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                "name": cve["id"],
            },
            "products": [{"@id": "pkg:generic/firmware@unknown"}],
            "status": cve["vex_status"],
            "impact_statement": cve["vex_impact"],
        }
        if cve["vex_justification"] and cve["vex_status"] == "not_affected":
            stmt["justification"] = cve["vex_justification"]
        statements.append(stmt)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "FirmCore VEX Analyzer (Mock)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": statements,
    }
