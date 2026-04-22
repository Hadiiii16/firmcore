"""
backfill_analysis_model.py — 기존 vex/*_vex.json 에 analysis_model 을 소급 주입.

``analysis_model`` 필드는 나중에 추가되어 그 이전에 완료된 CVE 들은
``x_firmcore_analysis_model`` 확장이 없다.  사용자가 "이 시점 이후에
분석된 것은 Pro 였다" 같은 사실을 알고 있을 때, mtime 기반으로 대상
파일을 추려 확장 필드를 삽입하고 combined_vex.json 을 재빌드한다.

사용:
    cd backend && source .venv/bin/activate
    python3 -m scripts.backfill_analysis_model \\
        <JOB_ID> <MODEL_NAME> \\
        [--since <ISO-8601>]          # 이 시각 이후 mtime 만 대상
        [--all]                        # since 무시하고 전체 대상
        [--dry-run]                    # 변경 없이 목록만 출력
        [--overwrite]                  # 기존 필드도 덮어쓰기

예시:
    # 오늘 00:00 이후 분석된 _vex.json 을 전부 Pro 로 태깅
    python3 -m scripts.backfill_analysis_model \\
        01KPSEK30BZCGJSCNJY1CGR6K7 gemini-3-pro-preview \\
        --since 2026-04-22T00:00:00
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from db import db_get_job, get_db  # noqa: E402
from pipeline.vex import rebuild_combined_vex_from_dir  # noqa: E402


async def _run(
    job_id: str,
    model: str,
    since: datetime | None,
    apply_all: bool,
    dry_run: bool,
    overwrite: bool,
) -> int:
    async with get_db() as db:
        job = await db_get_job(db, job_id)
        if not job:
            print(f"[ERROR] job not found: {job_id}")
            return 2

    storage_dir = Path(job["storage_dir"])
    vex_dir = storage_dir / "vex"
    if not vex_dir.exists():
        print(f"[ERROR] vex dir not found: {vex_dir}")
        return 2

    since_ts = since.timestamp() if since else None
    cutoff_label = (
        "all files"
        if apply_all
        else f"mtime >= {since.isoformat()}" if since
        else "mtime >= (now - 24h)"
    )
    print(f"[INFO] backfilling analysis_model={model!r} for {cutoff_label}")

    files = sorted(vex_dir.glob("*_vex.json"))
    total = 0
    updated = 0
    skipped_existing = 0
    skipped_mtime = 0

    # Default since = today 00:00 local if neither --since nor --all.
    if since_ts is None and not apply_all:
        now = datetime.now()
        since_ts = datetime(now.year, now.month, now.day).timestamp()

    for f in files:
        total += 1
        if not apply_all and f.stat().st_mtime < since_ts:
            skipped_mtime += 1
            continue
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  [WARN] parse fail: {f.name} ({exc})")
            continue

        stmts = doc.get("statements", [])
        if not stmts:
            continue
        stmt = stmts[0]

        existing = stmt.get("x_firmcore_analysis_model")
        if existing and not overwrite:
            skipped_existing += 1
            print(f"  [SKIP] {f.name} — already has {existing!r}")
            continue

        stmt["x_firmcore_analysis_model"] = model
        updated += 1
        if dry_run:
            print(f"  [DRY] {f.name} ← {model}")
        else:
            f.write_text(
                json.dumps(doc, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"  [OK ] {f.name} ← {model}")

    print()
    print(f"[INFO] scanned          : {total}")
    print(f"[INFO] updated          : {updated}")
    print(f"[INFO] skipped (has it) : {skipped_existing}")
    print(f"[INFO] skipped (mtime)  : {skipped_mtime}")

    if dry_run:
        print("[DRY-RUN] combined_vex.json not rebuilt")
        return 0
    if updated == 0:
        print("[INFO] nothing changed; combined_vex.json not touched")
        return 0

    product_info = {
        "name": job.get("product_name") or "firmware",
        "version": job.get("product_version") or "unknown",
    }
    combined = rebuild_combined_vex_from_dir(product_info, vex_dir, storage_dir)
    print(f"[INFO] combined_vex rebuilt: {combined}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("job_id")
    parser.add_argument("model", help="예: gemini-3-pro-preview / gemini-3-flash-preview")
    parser.add_argument("--since", help="ISO-8601 (예: 2026-04-22T00:00:00)")
    parser.add_argument("--all", action="store_true", dest="apply_all",
                        help="mtime 무시, 모든 _vex.json 대상")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true",
                        help="이미 analysis_model 이 있어도 덮어쓰기")
    args = parser.parse_args()

    since = None
    if args.since:
        try:
            since = datetime.fromisoformat(args.since)
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc).astimezone()
        except ValueError as exc:
            print(f"[ERROR] invalid --since: {exc}")
            sys.exit(2)

    rc = asyncio.run(_run(
        args.job_id, args.model, since,
        args.apply_all, args.dry_run, args.overwrite,
    ))
    sys.exit(rc)


if __name__ == "__main__":
    main()
