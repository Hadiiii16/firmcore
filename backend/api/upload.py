"""
upload.py — POST /api/upload

펌웨어 이미지를 멀티파트 폼으로 수신하고 분석 파이프라인을 시작합니다.
- 최대 500MB 파일 허용 (1MB 청크 스트리밍 저장)
- ULID로 고유 job_id 생성
- MOCK_PIPELINE=true 시 더미 파이프라인 실행
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import aiofiles
from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile
from ulid import ULID

from db import STORAGE_DIR, db_create_job, get_db
from models.job import JobCreateResponse, JobStatus

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_UPLOAD_BYTES: int = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "500")) * 1024 * 1024
CHUNK_SIZE: int = 1024 * 1024  # 1MB
_MOCK: bool = os.environ.get("MOCK_PIPELINE", "false").lower() == "true"


@router.post("", response_model=JobCreateResponse, status_code=201)
async def upload_firmware(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="펌웨어 이미지 (.bin/.img/.trx 등)"),
    product_name: str = Form("", description="제품명 (선택)"),
    product_version: str = Form("", description="펌웨어 버전 (선택)"),
) -> JobCreateResponse:
    """
    펌웨어 이미지를 업로드하고 분석 Job을 생성합니다.

    업로드 즉시 job_id를 반환하며, 분석은 백그라운드에서 진행됩니다.
    실시간 진행 상황은 GET /api/jobs/{job_id}/stream (SSE)으로 확인하세요.
    """
    # ── Content-Length 사전 검사 (큰 파일 조기 차단) ───────────────────────
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"파일이 너무 큽니다. 최대 허용 크기: {MAX_UPLOAD_BYTES // (1024 * 1024)}MB",
        )

    if not file.filename:
        raise HTTPException(status_code=400, detail="파일 이름이 없습니다.")

    # ── Job ID 생성 ───────────────────────────────────────────────────────
    job_id = str(ULID())

    # ── 저장 디렉토리 생성 ───────────────────────────────────────────────
    job_dir = STORAGE_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    # 원본 파일명에서 확장자 추출 (보안: 디렉토리 구분자 제거)
    safe_filename = Path(file.filename).name
    suffix = Path(safe_filename).suffix or ".bin"
    firmware_path = job_dir / f"firmware{suffix}"

    # ── 파일을 청크 단위로 저장 (메모리 효율적) ─────────────────────────
    total_bytes = 0
    try:
        async with aiofiles.open(firmware_path, "wb") as out_f:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    firmware_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"파일이 너무 큽니다. 최대 허용 크기: {MAX_UPLOAD_BYTES // (1024 * 1024)}MB",
                    )
                await out_f.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        firmware_path.unlink(missing_ok=True)
        logger.exception("파일 저장 실패: job=%s", job_id)
        raise HTTPException(status_code=500, detail=f"파일 저장 중 오류: {exc}") from exc

    logger.info(
        "펌웨어 업로드 완료: job=%s filename=%s size=%dMB mock=%s",
        job_id, safe_filename, total_bytes // (1024 * 1024), _MOCK,
    )

    # ── DB에 Job 레코드 생성 ─────────────────────────────────────────────
    async with get_db() as db:
        await db_create_job(
            db=db,
            job_id=job_id,
            filename=safe_filename,
            file_size=total_bytes,
            firmware_path=str(firmware_path),
            storage_dir=str(job_dir),
            product_name=product_name.strip(),
            product_version=product_version.strip(),
        )
        job = await db.execute("SELECT created_at FROM jobs WHERE id = ?", (job_id,))
        row = await job.fetchone()
        created_at = row[0] if row else ""

    # ── 파이프라인 백그라운드 실행 ───────────────────────────────────────
    if _MOCK:
        from pipeline.mock import run_mock_pipeline
        background_tasks.add_task(run_mock_pipeline, job_id)
        logger.info("[Mock] 파이프라인 예약: job=%s", job_id)
    else:
        from pipeline.runner import run_pipeline
        background_tasks.add_task(run_pipeline, job_id)

    return JobCreateResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        filename=safe_filename,
        created_at=created_at,
    )
