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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

_MOCK = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """애플리케이션 시작/종료 시 처리."""
    logger.info("FirmCore 백엔드 시작 중... (MOCK=%s)", _MOCK)
    await init_db()
    logger.info("DB 초기화 완료")
    yield
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # React (CRA / Vite preview)
        "http://localhost:5173",   # Vite 개발 서버
        "http://localhost:8080",   # 자기 자신 (Swagger UI)
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "X-Job-Id"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(upload_router, prefix="/api/upload", tags=["Upload"])
app.include_router(jobs_router,   prefix="/api/jobs",   tags=["Jobs"])

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
