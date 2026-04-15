"""
event_bus.py — 인메모리 SSE 이벤트 버스

asyncio 단일 이벤트 루프 특성을 활용하여 락 없이 구현합니다.
파이프라인 러너(BackgroundTask)가 이벤트를 broadcast하면,
SSE 엔드포인트의 대기 중인 제너레이터가 즉시 깨어납니다.

설계:
  - 이벤트 버스는 "깨우기 신호"용으로만 사용 (이벤트 본문은 DB가 소스)
  - DB 폴링 방식과 결합하여 중복 없이 실시간에 가까운 스트리밍 제공
  - 하나의 Job에 여러 SSE 클라이언트 동시 연결 지원
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)

# job_id → 구독 중인 asyncio.Queue 목록
_LISTENERS: dict[str, list[asyncio.Queue]] = {}


def subscribe(job_id: str) -> asyncio.Queue:
    """새 SSE 클라이언트를 위한 알림 큐를 등록하고 반환합니다."""
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    _LISTENERS.setdefault(job_id, []).append(q)
    logger.debug("[EventBus] 구독 등록: job=%s, 총 구독자=%d", job_id, len(_LISTENERS[job_id]))
    return q


def unsubscribe(job_id: str, q: asyncio.Queue) -> None:
    """SSE 연결 해제 시 큐를 제거합니다."""
    listeners = _LISTENERS.get(job_id, [])
    try:
        listeners.remove(q)
    except ValueError:
        pass
    if not listeners:
        _LISTENERS.pop(job_id, None)
    logger.debug("[EventBus] 구독 해제: job=%s", job_id)


def broadcast(job_id: str, event: dict) -> None:
    """
    job_id의 모든 SSE 구독자에게 알림을 전송합니다.

    Notes
    -----
    구독자가 없어도 오류가 발생하지 않습니다.
    큐가 가득 찬 경우 해당 구독자는 건너뜁니다 (이벤트 드롭 로깅).
    실제 이벤트 본문은 DB에서 읽으므로 알림만 전달하면 됩니다.
    """
    listeners = list(_LISTENERS.get(job_id, []))
    if not listeners:
        return
    for q in listeners:
        try:
            q.put_nowait(event)         # 알림 페이로드 (SSE 제너레이터가 DB를 폴링하는 신호)
        except asyncio.QueueFull:
            logger.warning("[EventBus] 큐 포화 (job=%s), 알림 드롭", job_id)


def listener_count(job_id: str) -> int:
    """현재 job_id를 구독 중인 SSE 클라이언트 수를 반환합니다."""
    return len(_LISTENERS.get(job_id, []))
