"""
db.py — aiosqlite 연결 관리 및 스키마 초기화

모든 DB 접근은 get_db() 비동기 컨텍스트 매니저를 통해 이루어집니다.
파이프라인 러너(BackgroundTask)와 API 핸들러가 독립적인 연결을 사용합니다.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

import aiosqlite

# ---------------------------------------------------------------------------
# Paths (환경변수로 재정의 가능)
# ---------------------------------------------------------------------------

DB_PATH = Path(
    os.environ.get("DB_PATH", Path(__file__).parent.parent / "data" / "firmcore.db")
)
STORAGE_DIR = Path(
    os.environ.get("STORAGE_DIR", Path(__file__).parent.parent.parent / "storage")
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS jobs (
    id                      TEXT PRIMARY KEY,
    filename                TEXT NOT NULL,
    file_size               INTEGER,
    firmware_path           TEXT,
    storage_dir             TEXT,
    status                  TEXT NOT NULL DEFAULT 'pending',
    current_stage           TEXT,
    stage_progress          INTEGER DEFAULT 0,
    error_message           TEXT,
    product_name            TEXT DEFAULT '',
    product_version         TEXT DEFAULT '',
    rootfs_path             TEXT,
    sbom_path               TEXT,
    scan_result_path        TEXT,
    combined_vex_path       TEXT,
    component_count         INTEGER DEFAULT 0,
    total_cves              INTEGER DEFAULT 0,
    critical_cves           INTEGER DEFAULT 0,
    high_cves               INTEGER DEFAULT 0,
    medium_cves             INTEGER DEFAULT 0,
    low_cves                INTEGER DEFAULT 0,
    not_affected_count      INTEGER DEFAULT 0,
    affected_count          INTEGER DEFAULT 0,
    under_investigation_count INTEGER DEFAULT 0,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    completed_at            TEXT
);

CREATE TABLE IF NOT EXISTS stage_timings (
    job_id          TEXT NOT NULL,
    stage           TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    elapsed_seconds REAL,
    PRIMARY KEY (job_id, stage),
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS job_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    event_data  TEXT    NOT NULL,   -- JSON 문자열
    created_at  TEXT    NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE INDEX IF NOT EXISTS idx_job_events_job_id ON job_events (job_id, id);
"""


# ---------------------------------------------------------------------------
# DB lifecycle
# ---------------------------------------------------------------------------


async def init_db() -> None:
    """애플리케이션 시작 시 DB 파일 및 스키마를 초기화합니다."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(DB_PATH)) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


@asynccontextmanager
async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """aiosqlite 연결 비동기 컨텍스트 매니저. Row를 dict-like으로 반환합니다."""
    async with aiosqlite.connect(str(DB_PATH)) as db:
        db.row_factory = aiosqlite.Row
        yield db


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Job CRUD
# ---------------------------------------------------------------------------


async def db_create_job(
    db: aiosqlite.Connection,
    job_id: str,
    filename: str,
    file_size: int,
    firmware_path: str,
    storage_dir: str,
    product_name: str = "",
    product_version: str = "",
) -> None:
    ts = now_iso()
    await db.execute(
        """
        INSERT INTO jobs
            (id, filename, file_size, firmware_path, storage_dir,
             status, product_name, product_version, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        """,
        (job_id, filename, file_size, firmware_path, storage_dir,
         product_name, product_version, ts, ts),
    )
    await db.commit()


async def db_get_job(
    db: aiosqlite.Connection,
    job_id: str,
) -> Optional[dict]:
    async with db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)) as cur:
        row = await cur.fetchone()
    return dict(row) if row else None


async def db_list_jobs(
    db: aiosqlite.Connection,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[dict], int]:
    async with db.execute(
        "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ) as cur:
        rows = await cur.fetchall()
    async with db.execute("SELECT COUNT(*) FROM jobs") as cur:
        total_row = await cur.fetchone()
    total = total_row[0] if total_row else 0
    return [dict(r) for r in rows], total


async def db_update_job(
    db: aiosqlite.Connection,
    job_id: str,
    **kwargs: Any,
) -> None:
    """임의 컬럼 부분 업데이트. updated_at은 자동 설정됩니다."""
    kwargs["updated_at"] = now_iso()
    cols = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [job_id]
    await db.execute(f"UPDATE jobs SET {cols} WHERE id = ?", vals)
    await db.commit()


# ---------------------------------------------------------------------------
# Event CRUD (SSE 리플레이 및 히스토리용)
# ---------------------------------------------------------------------------


async def db_add_event(
    db: aiosqlite.Connection,
    job_id: str,
    event: dict,
) -> None:
    await db.execute(
        """
        INSERT INTO job_events (job_id, event_type, event_data, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (job_id, event.get("type", "unknown"),
         json.dumps(event, ensure_ascii=False), now_iso()),
    )
    await db.commit()


async def db_get_events(
    db: aiosqlite.Connection,
    job_id: str,
    after_id: int = 0,
) -> list[dict]:
    """after_id 이후의 이벤트 목록을 반환합니다 (SSE 폴링용)."""
    async with db.execute(
        """
        SELECT id, event_data
        FROM   job_events
        WHERE  job_id = ? AND id > ?
        ORDER  BY id
        """,
        (job_id, after_id),
    ) as cur:
        rows = await cur.fetchall()
    return [{"id": r[0], "data": r[1]} for r in rows]


# ---------------------------------------------------------------------------
# Stage timing CRUD
# ---------------------------------------------------------------------------


async def db_start_stage(
    db: aiosqlite.Connection,
    job_id: str,
    stage: str,
) -> None:
    await db.execute(
        """
        INSERT OR REPLACE INTO stage_timings (job_id, stage, started_at)
        VALUES (?, ?, ?)
        """,
        (job_id, stage, now_iso()),
    )
    await db.commit()


async def db_end_stage(
    db: aiosqlite.Connection,
    job_id: str,
    stage: str,
    elapsed: float,
) -> None:
    await db.execute(
        """
        UPDATE stage_timings
        SET    completed_at = ?, elapsed_seconds = ?
        WHERE  job_id = ? AND stage = ?
        """,
        (now_iso(), round(elapsed, 3), job_id, stage),
    )
    await db.commit()


async def db_get_stage_timings(
    db: aiosqlite.Connection,
    job_id: str,
) -> list[dict]:
    async with db.execute(
        """
        SELECT stage, started_at, completed_at, elapsed_seconds
        FROM   stage_timings
        WHERE  job_id = ?
        ORDER  BY started_at
        """,
        (job_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]
