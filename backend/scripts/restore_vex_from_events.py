"""
restore_vex_from_events.py — DB job_events 에서 VEX 산출물 복구

Resume-from-here 를 반복하다 디스크 ``{CVE}_vex.json`` / ``_report.md`` 가
삭제됐을 때, 과거 ``cve_done`` 이벤트의 ``cve_result`` payload 를 바탕으로
복원한다.

사용:
    cd backend
    python3 -m scripts.restore_vex_from_events <job_id>
        [--dry-run]          # 변경 없이 시뮬레이션만
        [--overwrite]        # 이미 있는 파일도 덮어쓰기 (기본: skip)

복구 로직:
  1. ``job_events`` 에서 해당 job 의 모든 ``cve_done`` 이벤트 조회
  2. CVE 별로 가장 **최신 (id 가 큰)** 이벤트의 ``cve_result`` payload 사용
  3. ``vex_status`` 가 있는 것만 복원 대상.  ``unknown`` 은 skip
  4. 누락된 파일만 새로 쓴다 (--overwrite 없이는 기존 파일 보존)
  5. 마지막으로 ``combined_vex.json`` 재빌드
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# backend 디렉토리를 sys.path 에 추가해 pipeline / db 모듈 import
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from db import db_get_events, db_get_job, get_db  # noqa: E402
from pipeline.vex import (  # noqa: E402
    VexStatement,
    rebuild_combined_vex_from_dir,
)


def _latest_cve_done_by_cve(events: list[dict]) -> dict[str, dict]:
    """Return mapping cve_id → latest cve_done event (highest id wins)."""
    latest: dict[str, dict] = {}
    for ev in events:
        try:
            payload = json.loads(ev["data"])
        except (json.JSONDecodeError, TypeError):
            continue
        if payload.get("type") != "cve_done":
            continue
        cve_id = payload.get("cve_id")
        if not cve_id:
            continue
        # db_get_events returns events ordered by id asc; the later entry
        # wins so simple dict overwrite works.
        latest[cve_id] = payload
    return latest


def _build_vex_json(
    product_name: str,
    product_version: str,
    cve_id: str,
    cve_result: dict,
) -> dict:
    """Reconstruct a minimal OpenVEX document for a single CVE."""
    status = cve_result.get("vex_status") or "under_investigation"
    justification = cve_result.get("vex_justification")
    grade = cve_result.get("analysis_grade")
    evidence = cve_result.get("analysis_evidence")
    detail = cve_result.get("vex_detail") or ""

    # GEMINI.md v5.0 prefix 형식: [EVIDENCE: …] [GRADE: …] (affected 일 때만)
    prefix_parts: list[str] = []
    if evidence:
        prefix_parts.append(f"[EVIDENCE: {evidence.upper()}]")
    if status == "affected" and grade:
        prefix_parts.append(f"[GRADE: {grade.upper()}]")
    impact_prefix = (" ".join(prefix_parts) + " ") if prefix_parts else ""
    # vex_detail 은 보통 보고서 전체 텍스트인데, impact_statement 는 한 줄
    # 요약이 적합.  보고서에서 첫 줄 또는 판정 단계 한 줄을 취함.
    first_meaningful = next(
        (ln.strip() for ln in detail.splitlines() if ln.strip() and not ln.startswith("=")),
        cve_id,
    )
    impact_statement = impact_prefix + first_meaningful[:300]

    stmt: dict[str, Any] = {
        "vulnerability": {
            "@id": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "name": cve_id,
        },
        "products": [
            {
                "@id": f"pkg:generic/{product_name}@{product_version}",
            },
        ],
        "status": status,
        "impact_statement": impact_statement,
    }
    if justification and status not in ("affected", "fixed", "under_investigation"):
        stmt["justification"] = justification
    if grade:
        stmt["x_firmcore_grade"] = grade.upper()
    if evidence:
        stmt["x_firmcore_evidence"] = evidence.upper()

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "FirmCore VEX Restore",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": [stmt],
    }


async def _run(job_id: str, dry_run: bool, overwrite: bool) -> int:
    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            print(f"[ERROR] job not found: {job_id}")
            return 2
        events = await db_get_events(db, job_id, after_id=0)

    storage_dir = Path(job["storage_dir"])
    vex_dir = storage_dir / "vex"
    vex_dir.mkdir(parents=True, exist_ok=True)

    product_name = job.get("product_name") or "firmware"
    product_version = job.get("product_version") or "unknown"

    latest = _latest_cve_done_by_cve(events)
    print(f"[INFO] {len(latest)} unique CVE cve_done events in DB")

    restored_vex = 0
    restored_report = 0
    skipped_existing = 0
    skipped_unknown = 0

    for cve_id, ev in sorted(latest.items()):
        cve_result = ev.get("cve_result") or {}
        vex_status = cve_result.get("vex_status")
        if not vex_status or vex_status == "unknown":
            skipped_unknown += 1
            continue

        vex_file = vex_dir / f"{cve_id}_vex.json"
        report_file = vex_dir / f"{cve_id}_report.md"
        detail = cve_result.get("vex_detail") or ""

        # VEX JSON
        if vex_file.exists() and not overwrite:
            skipped_existing += 1
        else:
            doc = _build_vex_json(product_name, product_version, cve_id, cve_result)
            if not dry_run:
                vex_file.write_text(
                    json.dumps(doc, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            restored_vex += 1

        # Report MD
        if report_file.exists() and not overwrite:
            pass
        elif detail:
            if not dry_run:
                report_file.write_text(detail, encoding="utf-8")
            restored_report += 1

    print(f"[INFO] restored _vex.json    : {restored_vex}")
    print(f"[INFO] restored _report.md   : {restored_report}")
    print(f"[INFO] skipped (exists)      : {skipped_existing}")
    print(f"[INFO] skipped (unknown)     : {skipped_unknown}")

    if dry_run:
        print("[DRY-RUN] no files written; combined_vex.json not rebuilt")
        return 0

    # Rebuild combined_vex.json from the populated directory.
    product_info = {"name": product_name, "version": product_version}
    combined = rebuild_combined_vex_from_dir(product_info, vex_dir, storage_dir)
    print(f"[INFO] combined_vex rebuilt  : {combined}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job_id", help="복구할 Job ID")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true",
                        help="기존 파일도 덮어쓰기")
    args = parser.parse_args()
    rc = asyncio.run(_run(args.job_id, args.dry_run, args.overwrite))
    sys.exit(rc)


if __name__ == "__main__":
    main()
