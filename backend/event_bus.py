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
    """새 SSE 클라이언트를 위한 알림 큐를 등록하고 반환합니다.

    이 큐는 이벤트 본문이 아니라 **"DB 를 다시 읽어라"는 깨우기 신호**
    만 전달한다.  SSE 제너레이터는 신호 하나를 받으면 ``notify_q.empty()``
    가 될 때까지 큐를 비우고 한 번의 DB 조회로 ``last_event_id`` 이후
    모든 신규 이벤트를 batch 로 내보낸다.  그래서 큐 깊이는 1 이면 충분
    — 2개째 신호는 "이미 깨어 있음" 이므로 조용히 drop 해도 정보 손실 없음.
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=1)
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
    job_id의 모든 SSE 구독자에게 **깨우기 신호**를 전송합니다.

    이벤트 본문은 DB 가 source of truth 이므로 여기선 "뭔가 새로 쓰였다"
    는 신호만 전달한다.  큐 깊이가 1 이라 이미 신호가 쌓여 있으면
    ``QueueFull`` 이 나는데, 이는 "구독자가 아직 이전 신호도 처리 못 한
    상태 = 깨우면 어차피 모든 누적 이벤트를 DB batch 로 읽어갈 것" 이므
    로 조용히 drop 한다 (경고 로그 없음 — 정상 동작).
    """
    listeners = list(_LISTENERS.get(job_id, []))
    if not listeners:
        return
    for q in listeners:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            # Coalesced — 추가 신호는 무의미하므로 조용히 drop.
            pass


def listener_count(job_id: str) -> int:
    """현재 job_id를 구독 중인 SSE 클라이언트 수를 반환합니다."""
    return len(_LISTENERS.get(job_id, []))
