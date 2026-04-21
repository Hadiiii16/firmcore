"""
main.py — FirmCore FastAPI 애플리케이션

CORS, 라우터, lifespan(DB 초기화), 전역 예외 핸들러를 설정합니다.

실행:
    uvicorn main:app --host 0.0.0.0 --port 8080 --reload

Mock 모드:
    MOCK_PIPELINE=true uvicorn main:app --reload
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from db import init_db
from api.upload import router as upload_router
from api.jobs import router as jobs_router
from api.dashboard import router as dashboard_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

_MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


_TERMINAL_STATUSES = ("completed", "failed", "pending")


async def _recover_orphan_jobs() -> int:
    """Mark non-terminal jobs as ``failed`` on server startup.

    A server restart kills every in-memory ``BackgroundTasks`` pipeline
    immediately, but the DB still carries the last status ("extracting",
    "sbom_generating", "scanning", "vex_analyzing").  Those jobs can
    never resume — yet they block DELETE because the normal delete
    endpoint only allows terminal states.  Rewrite them once at boot so
    users can clean them up from the UI.
    """
    from db import get_db, now_iso

    async with get_db() as db:
        async with db.execute(
            "SELECT id, status FROM jobs WHERE status NOT IN (?, ?, ?)",
            _TERMINAL_STATUSES,
        ) as cur:
            rows = await cur.fetchall()
        if not rows:
            return 0
        ts = now_iso()
        for r in rows:
            await db.execute(
                "UPDATE jobs SET status = 'failed', "
                "error_message = COALESCE(error_message, ?), "
                "updated_at = ?, completed_at = COALESCE(completed_at, ?) "
                "WHERE id = ?",
                (
                    "Server restarted during analysis; job cannot resume.",
                    ts, ts, r["id"],
                ),
            )
        await db.commit()
        return len(rows)


async def _recompute_job_cve_counts() -> int:
    """완료된 Job 들의 CVE 집계 컬럼을 scan.json 기준으로 재산출.

    초기 scanner 가 grype matches 를 dedup 없이 카운트했던 구버전에서
    저장된 값은 중복이 섞여 부풀려져 있습니다.  Dashboard KPI / Job
    상세 탭은 on-the-fly dedup 을 쓰므로 Job 목록 뱃지와 숫자가 안
    맞습니다.  서버 시작 시 한 번 재집계해 전사적으로 일관된 숫자를
    보여주도록 합니다.
    """
    import json
    from pathlib import Path

    from db import get_db

    async with get_db() as db:
        async with db.execute(
            "SELECT id, storage_dir, scan_result_path, "
            "total_cves, critical_cves, high_cves, medium_cves, low_cves "
            "FROM jobs WHERE status = 'completed'",
        ) as cur:
            rows = await cur.fetchall()

        updated = 0
        for raw in rows:
            # ``sqlite3.Row`` 는 ``.get()`` 을 지원하지 않으므로 dict 로 변환.
            r = dict(raw)
            sp = r.get("scan_result_path")
            if not sp:
                sd = r.get("storage_dir")
                if sd:
                    candidate = Path(sd) / "scan.json"
                    if candidate.exists():
                        sp = str(candidate)
            if not sp or not Path(sp).exists():
                continue
            try:
                data = json.loads(Path(sp).read_text(encoding="utf-8"))
            except Exception:
                continue

            seen: set[tuple[str, str, str]] = set()
            counts: dict[str, int] = {}
            for m in data.get("matches", []):
                vuln = m.get("vulnerability", {})
                art = m.get("artifact", {})
                key = (
                    vuln.get("id", "UNKNOWN"),
                    art.get("name", ""),
                    art.get("version", ""),
                )
                if key in seen:
                    continue
                seen.add(key)
                sev = (vuln.get("severity") or "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1

            new_vals = {
                "total_cves": len(seen),
                "critical_cves": counts.get("CRITICAL", 0),
                "high_cves": counts.get("HIGH", 0),
                "medium_cves": counts.get("MEDIUM", 0),
                "low_cves": counts.get("LOW", 0),
            }
            current = {k: r.get(k) or 0 for k in new_vals}
            if new_vals == current:
                continue
            await db.execute(
                "UPDATE jobs SET total_cves = ?, critical_cves = ?, "
                "high_cves = ?, medium_cves = ?, low_cves = ? WHERE id = ?",
                (
                    new_vals["total_cves"],
                    new_vals["critical_cves"],
                    new_vals["high_cves"],
                    new_vals["medium_cves"],
                    new_vals["low_cves"],
                    r["id"],
                ),
            )
            updated += 1
        await db.commit()
        return updated


@asynccontextmanager
async def lifespan(app: FastAPI):
    """애플리케이션 시작/종료 시 처리."""
    logger.info("FirmCore 백엔드 시작 중... (MOCK=%s)", _MOCK)
    await init_db()
    logger.info("DB 초기화 완료")
    recovered = await _recover_orphan_jobs()
    if recovered:
        logger.info(
            "[Startup] 이전 세션의 진행중 Job %d개를 'failed' 로 복구", recovered,
        )
    recomputed = await _recompute_job_cve_counts()
    if recomputed:
        logger.info(
            "[Startup] Job %d개의 CVE 집계 컬럼을 dedup 기준으로 재산출", recomputed,
        )
    yield
    # 종료 시 실행 중인 모든 Gemini 서브프로세스를 정리
    from pipeline.vex import terminate_active_gemini_processes
    terminated = await terminate_active_gemini_processes("server shutdown")
    if terminated:
        logger.info("[Shutdown] Gemini 프로세스 %d개 종료 완료", terminated)
    logger.info("FirmCore 백엔드 종료")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


app = FastAPI(
    title="FirmCore API",
    description="펌웨어 취약점 분석 플랫폼 — SBOM 생성 + CVE 스캔 + VEX 자동화",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

_VITE_FALLBACK_PORTS = [5173, 5174, 5175, 5176, 5177, 5178, 5179]

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8080",   # 자기 자신 (Swagger UI)
        "http://127.0.0.1:3000",
        # Vite 는 5173 이 이미 사용 중이면 5174~5179 로 자동 폴백하므로
        # 그 범위를 전부 허용한다.
        *[f"http://localhost:{p}" for p in _VITE_FALLBACK_PORTS],
        *[f"http://127.0.0.1:{p}" for p in _VITE_FALLBACK_PORTS],
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "X-Job-Id"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(upload_router,    prefix="/api/upload",    tags=["Upload"])
app.include_router(jobs_router,      prefix="/api/jobs",      tags=["Jobs"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/health", tags=["System"])
async def health() -> dict:
    """서비스 상태 확인 엔드포인트."""
    return {
        "status": "ok",
        "mock_mode": _MOCK,
        "version": "1.0.0",
    }


# ---------------------------------------------------------------------------
# 전역 예외 핸들러
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("처리되지 않은 예외: %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content={"detail": "서버 내부 오류가 발생했습니다. 관리자에게 문의하세요."},
    )
